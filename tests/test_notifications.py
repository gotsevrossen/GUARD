"""Desktop-notification polling: GET /api/notifications.

The dashboard notifies with fixed wording; these tests pin the server side of that
contract: the caller's own threshold, a bounded and validated cursor, and a
response that carries no sensor- or model-written text at all.
"""
from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

from triage.schema import AlertStatus, NormalizedAlert, Severity, Source, TriageResult
from triage.service import assess

OWNER_PASSWORD = "owner-password-1"
ANALYST_PASSWORD = "analyst-password-1"
LURE = "Call support at 555-0100 now"


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("LIGHTHOUSE_STATIC_DIR", str(tmp_path / "no-dashboard-build"))
    monkeypatch.delenv("LIGHTHOUSE_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("LIGHTHOUSE_DEV", raising=False)
    sys.modules.pop("triage.api", None)
    module = importlib.import_module("triage.api")
    try:
        yield module
    finally:
        sys.modules.pop("triage.api", None)


@pytest.fixture
def client(api):
    return TestClient(api.app)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def login(client, username: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def seed(api, severity: Severity, sensor: Severity = Severity.LOW) -> int:
    alert = NormalizedAlert(source=Source.SURICATA, title=LURE, source_ip="203.0.113.9", destination_ip="192.168.1.10",
                            device="FRONT-DESK-PC", rule_id="2001219", sensor_severity=sensor,
                            raw={"payload_printable": "RAW-MARKER " + LURE})
    triage = TriageResult(severity=severity, explanation=LURE, recommended_action=LURE, reasoning="REASONING-MARKER")
    return api.db.store(alert, assess(alert, triage))


@pytest.fixture
def users(api, client):
    api.db.create_user("alice", OWNER_PASSWORD, "owner")
    api.db.create_user("bob", ANALYST_PASSWORD, "analyst")
    return {"alice": login(client, "alice", OWNER_PASSWORD), "bob": login(client, "bob", ANALYST_PASSWORD)}


def poll(client, token: str, after: int | str | None = 0):
    params = {} if after is None else {"after": after}
    return client.get("/api/notifications", params=params, headers=auth(token))


# --- auth and roles ----------------------------------------------------------

def test_requires_a_session(client):
    assert client.get("/api/notifications").status_code in (401, 403)
    assert client.get("/api/notifications", headers=auth("not-a-real-token")).status_code == 401


def test_password_change_still_owed_is_refused(api, client):
    api.db.create_user("carol", OWNER_PASSWORD, "owner", must_change_password=True)
    token = login(client, "carol", OWNER_PASSWORD)
    assert poll(client, token).status_code == 403


@pytest.mark.parametrize("role", ["owner", "analyst", "admin"])
def test_every_role_may_poll(api, client, role):
    api.db.create_user(f"user-{role}", OWNER_PASSWORD, role)
    assert poll(client, login(client, f"user-{role}", OWNER_PASSWORD)).status_code == 200


# --- the threshold is the caller's own, from the server ----------------------

def test_threshold_comes_from_each_callers_own_settings(api, client, users):
    api.db.set_user_setting("alice", "notification_threshold", "medium")
    api.db.set_user_setting("bob", "notification_threshold", "critical")
    medium, high, critical = seed(api, Severity.MEDIUM), seed(api, Severity.HIGH), seed(api, Severity.CRITICAL)

    alice = poll(client, users["alice"]).json()
    bob = poll(client, users["bob"]).json()
    assert alice["threshold"] == "medium" and alice["count"] == 3
    assert [entry["id"] for entry in alice["alerts"]] == [critical, high, medium]
    assert bob["threshold"] == "critical" and bob["count"] == 1
    assert [entry["id"] for entry in bob["alerts"]] == [critical]


def test_browser_cannot_choose_the_threshold(api, client, users):
    api.db.set_user_setting("alice", "notification_threshold", "critical")
    seed(api, Severity.MEDIUM)
    response = client.get("/api/notifications", params={"after": 0, "threshold": "medium"}, headers=auth(users["alice"]))
    assert response.json()["count"] == 0


def test_default_and_unknown_stored_thresholds_mean_high(api, client, users):
    seed(api, Severity.MEDIUM)
    high = seed(api, Severity.HIGH)
    assert [entry["id"] for entry in poll(client, users["alice"]).json()["alerts"]] == [high]
    # A value written before validation existed (or by hand) must not widen what notifies.
    api.db.set_user_setting("alice", "notification_threshold", "low")
    body = poll(client, users["alice"]).json()
    assert body["threshold"] == "high" and [entry["id"] for entry in body["alerts"]] == [high]


def test_unsupported_threshold_is_refused_on_save(client, users):
    for value in ("low", "unknown", "HIGH", ""):
        response = client.put("/api/preferences", json={"key": "notification_threshold", "value": value},
                              headers=auth(users["alice"]))
        assert response.status_code == 422
    ok = client.put("/api/preferences", json={"key": "notification_threshold", "value": "critical"},
                    headers=auth(users["alice"]))
    assert ok.status_code == 200
    assert poll(client, users["alice"]).json()["threshold"] == "critical"


def test_severity_is_the_stored_floored_severity(api, client, users):
    # The model said low; the sensor said critical. The floor keeps it critical.
    alert_id = seed(api, Severity.LOW, sensor=Severity.CRITICAL)
    assert poll(client, users["alice"]).json()["alerts"] == [
        {"id": alert_id, "severity": "critical", "timestamp": api.db.get_alert(alert_id).timestamp.isoformat()}]


def test_closed_alerts_do_not_notify(api, client, users):
    alert_id = seed(api, Severity.CRITICAL)
    api.db.update_status(alert_id, AlertStatus.DISMISSED)
    assert poll(client, users["alice"]).json()["count"] == 0


# --- cursor validation and the cap ------------------------------------------

def test_after_filters_and_reports_latest(api, client, users):
    first, second = seed(api, Severity.HIGH), seed(api, Severity.LOW)
    third = seed(api, Severity.CRITICAL)
    body = poll(client, users["alice"], after=first).json()
    assert body["latest_id"] == third
    assert [entry["id"] for entry in body["alerts"]] == [third]
    assert poll(client, users["alice"], after=third).json() == {"threshold": "high", "count": 0, "latest_id": third, "alerts": []}
    assert second  # stored, just below the threshold


def test_first_poll_without_after_starts_from_now(api, client, users):
    seed(api, Severity.CRITICAL)
    latest = seed(api, Severity.CRITICAL)
    assert poll(client, users["alice"], after=None).json() == {"threshold": "high", "count": 0, "latest_id": latest, "alerts": []}


def test_empty_database(client, users):
    assert poll(client, users["alice"]).json() == {"threshold": "high", "count": 0, "latest_id": 0, "alerts": []}


@pytest.mark.parametrize("after", [-1, "abc", "1.5", "1e3", 2**63, "9" * 40])
def test_invalid_after_is_rejected(client, users, after):
    assert poll(client, users["alice"], after=after).status_code == 422


def test_cursor_beyond_latest_is_harmless(api, client, users):
    latest = seed(api, Severity.HIGH)
    body = poll(client, users["alice"], after=latest + 1000).json()
    assert body == {"threshold": "high", "count": 0, "latest_id": latest, "alerts": []}


def test_response_is_capped_but_count_is_complete(api, client, users):
    ids = [seed(api, Severity.HIGH) for _ in range(api.NEW_ALERTS_MAX + 5)]
    body = poll(client, users["alice"]).json()
    assert body["count"] == api.NEW_ALERTS_MAX + 5
    assert len(body["alerts"]) == api.NEW_ALERTS_MAX
    assert body["alerts"][0]["id"] == ids[-1]


# --- no attacker- or model-written text --------------------------------------

def test_response_carries_no_sensor_or_model_text(api, client, users):
    seed(api, Severity.CRITICAL)
    response = poll(client, users["bob"])
    body = response.json()
    assert set(body) == {"threshold", "count", "latest_id", "alerts"}
    assert set(body["alerts"][0]) == {"id", "severity", "timestamp"}
    for marker in (LURE, "555-0100", "203.0.113.9", "192.168.1.10", "FRONT-DESK-PC", "RAW-MARKER",
                   "REASONING-MARKER", "2001219", "title", "raw", "source_ip", "device"):
        assert marker not in response.text
