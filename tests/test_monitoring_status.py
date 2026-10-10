"""The owner-safe "Is LightHouse watching?" status (GET /api/status).

Windows services, health files and Suricata's log are all simulated, so this runs
on any OS.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

from triage import monitoring
from triage.ingest import health

SYSMON, SECURITY = "Microsoft-Windows-Sysmon/Operational", "Security"
CHANNELS = (SYSMON, SECURITY)
WATCHED = ("network", "computer", "sign_ins")


class FakeServices:
    def __init__(self, state="running", sysmon="running", start="automatic"):
        self.states = {name: state for name in monitoring.MONITORING_SERVICES}
        self.starts = {name: start for name in monitoring.MONITORING_SERVICES}
        if sysmon is not None:
            self.states["Sysmon64"] = sysmon

    def state(self, name):
        return self.states.get(name)

    def start_type(self, name):
        return self.starts.get(name)


def paused_services():
    """What pause() leaves behind: stopped and switched to manual start."""
    return FakeServices(state="stopped", start="manual")


def write_health(state_dir, channel, status, checked_at):
    directory = state_dir / "health"
    directory.mkdir(parents=True, exist_ok=True)
    health.write_json(directory / health.channel_filename(channel),
                      {"channel": channel, "status": status, "checked_at": checked_at, "pid": 987654321})


def write_eve(path, modified, text='{"event_type":"flow"}\n'):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)
    os.utime(path, (modified, modified))


@pytest.fixture
def sensors(tmp_path):
    """A healthy install as of `now`: every reader checked in a minute ago."""
    now = time.time()
    state_dir, eve = tmp_path / "state", tmp_path / "eve.json"
    for channel in CHANNELS:
        write_health(state_dir, channel, "ok", now - 60)
    write_eve(eve, now - 60)
    return {"now": now, "state_dir": state_dir, "eve": eve}


def states(result):
    return {sensor.id: sensor.state for sensor in result.sensors}


def check(sensors, services=None, *, at=None, ai_ready=True, channels=CHANNELS):
    return monitoring.watch_status(FakeServices() if services is None else services, state_dir=sensors["state_dir"],
                                   eve_path=sensors["eve"], ai_ready=ai_ready, channels=channels,
                                   now=sensors["now"] if at is None else at)


def test_everything_reporting_is_working(sensors):
    result = check(sensors)
    assert result.overall == "working"
    assert states(result) == {"network": "working", "computer": "working", "sign_ins": "working", "local_ai": "working"}
    for sensor in result.sensors:
        assert sensor.message == monitoring.MESSAGES[sensor.id][sensor.state]
        if sensor.id in WATCHED:
            assert abs(sensor.last_heard.timestamp() - (sensors["now"] - 60)) < 1


def test_readers_go_stale_before_a_quiet_network(sensors, monkeypatch):
    monkeypatch.delenv("LIGHTHOUSE_STATUS_READER_STALE_MINUTES", raising=False)
    monkeypatch.delenv("LIGHTHOUSE_STATUS_NETWORK_QUIET_MINUTES", raising=False)
    # 11 minutes on: the Event Log readers (10-minute limit) are overdue, while half an
    # hour of a quiet network is still allowed.
    result = check(sensors, at=sensors["now"] + 10 * 60)
    assert states(result) == {"network": "working", "computer": "not_reporting", "sign_ins": "not_reporting",
                              "local_ai": "working"}
    assert result.overall == "attention"
    computer = next(sensor for sensor in result.sensors if sensor.id == "computer")
    assert abs(computer.last_heard.timestamp() - (sensors["now"] - 60)) < 1, "says when it was last heard from"
    later = check(sensors, at=sensors["now"] + 30 * 60)
    assert states(later)["network"] == "not_reporting"


def test_thresholds_come_from_the_environment(sensors, monkeypatch):
    monkeypatch.setenv("LIGHTHOUSE_STATUS_READER_STALE_MINUTES", "2")
    monkeypatch.setenv("LIGHTHOUSE_STATUS_NETWORK_QUIET_MINUTES", "3")
    # Last heard from a minute before `now`.
    assert states(check(sensors, at=sensors["now"] + 30))["computer"] == "working"
    result = check(sensors, at=sensors["now"] + 90)
    assert states(result)["computer"] == "not_reporting" and states(result)["network"] == "working"
    assert states(check(sensors, at=sensors["now"] + 150))["network"] == "not_reporting"
    # A bad value falls back to the default instead of failing the page.
    monkeypatch.setenv("LIGHTHOUSE_STATUS_READER_STALE_MINUTES", "soon")
    monkeypatch.setenv("LIGHTHOUSE_STATUS_NETWORK_QUIET_MINUTES", "0")
    assert check(sensors, at=sensors["now"] + 5 * 60).overall == "working"


def test_a_growing_network_log_counts_even_if_its_time_lags(sensors):
    old = sensors["now"] - 2 * 60 * 60
    os.utime(sensors["eve"], (old, old))
    assert states(check(sensors))["network"] == "not_reporting"
    write_eve(sensors["eve"], old)  # grew, but the modification time did not move
    result = check(sensors, at=sensors["now"] + 5)
    assert states(result)["network"] == "working"
    assert abs(result.sensors[0].last_heard.timestamp() - (sensors["now"] + 5)) < 1


def test_paused_monitoring_is_paused_not_broken(sensors):
    result = check(sensors, paused_services())
    assert result.overall == "paused"
    assert states(result) == {"network": "paused", "computer": "paused", "sign_ins": "paused", "local_ai": "working"}


def test_monitoring_that_stopped_on_its_own_is_not_shown_as_paused(sensors):
    """Still set to start automatically, so no administrator paused it: a crash or
    someone stopping the services must get attention, not "Paused by an administrator"."""
    for start in ("automatic", "disabled", None):
        result = check(sensors, FakeServices(state="stopped", start=start))
        assert result.overall == "attention", start
        assert [states(result)[sensor] for sensor in WATCHED] == ["not_reporting"] * 3, start


def test_stopped_or_failing_pieces_are_not_reporting(sensors):
    services = FakeServices()
    services.states["LightHouse-Suricata"] = "stopped"
    assert states(check(sensors, services))["network"] == "not_reporting"

    services = FakeServices(sysmon="stopped")
    assert states(check(sensors, services))["computer"] == "not_reporting"

    services = FakeServices()
    services.states["LightHouse-Ingestion"] = "stopped"
    result = check(sensors, services)
    assert [states(result)[sensor] for sensor in WATCHED] == ["not_reporting"] * 3

    write_health(sensors["state_dir"], SECURITY, "error", sensors["now"] - 5)
    assert states(check(sensors))["sign_ins"] == "not_reporting"


def test_missing_and_damaged_signals_are_not_reporting(sensors):
    sensors["eve"].unlink()
    (sensors["state_dir"] / "health" / health.channel_filename(SYSMON)).write_text("{not json", encoding="utf-8")
    # A reader time from the future is a damaged file or a clock jump, not news.
    write_health(sensors["state_dir"], SECURITY, "ok", sensors["now"] + 3600)
    result = check(sensors)
    assert [states(result)[sensor] for sensor in WATCHED] == ["not_reporting"] * 3
    assert all(sensor.last_heard is None for sensor in result.sensors)


def test_not_installed(sensors):
    result = check(sensors, FakeServices(sysmon=None), ai_ready=False)
    assert states(result)["computer"] == "not_installed"
    assert states(result)["local_ai"] == "not_installed"
    # A CPU without AVX2 is a fact of the machine, not monitoring that needs a check.
    sysmon_ok = check(sensors, ai_ready=False)
    assert sysmon_ok.overall == "working"
    # A developer's copy, not the installed services: nothing is captured.
    result = monitoring.watch_status(None, state_dir=sensors["state_dir"], eve_path=sensors["eve"], ai_ready=True,
                                     channels=CHANNELS, now=sensors["now"])
    assert [states(result)[sensor] for sensor in WATCHED] == ["not_installed"] * 3
    assert result.overall == "attention"
    # An input switched off with an empty channel name is not set up.
    assert states(check(sensors, channels=(None, SECURITY)))["computer"] == "not_installed"


def test_last_report_rejects_another_channels_file(tmp_path):
    write_health(tmp_path, SECURITY, "ok", 100.0)
    assert health.last_report(tmp_path, SECURITY) == ("ok", 100.0)
    (tmp_path / "health" / health.channel_filename(SYSMON)).write_text(
        json.dumps({"channel": SECURITY, "status": "ok", "checked_at": 100.0}), encoding="utf-8")
    assert health.last_report(tmp_path, SYSMON) is None
    assert health.last_report(tmp_path / "nowhere", SYSMON) is None


# --- The route ---------------------------------------------------------------

@pytest.fixture
def api(tmp_path, monkeypatch, sensors):
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(tmp_path / "status.db"))
    monkeypatch.setenv("LIGHTHOUSE_STATIC_DIR", str(tmp_path / "no-dashboard-build"))
    monkeypatch.setenv("LIGHTHOUSE_EVENT_STATE_DIR", str(sensors["state_dir"]))
    monkeypatch.setenv("LIGHTHOUSE_SURICATA_PATH", str(sensors["eve"]))
    monkeypatch.setenv("LIGHTHOUSE_SYSMON_CHANNEL", SYSMON)
    monkeypatch.setenv("LIGHTHOUSE_SECURITY_CHANNEL", SECURITY)
    import triage.main
    monkeypatch.setattr(triage.main, "local_ai_ready", lambda: True)
    sys.modules.pop("triage.api", None)
    module = importlib.import_module("triage.api")
    monkeypatch.setattr(module, "_services", FakeServices())
    try:
        yield module
    finally:
        sys.modules.pop("triage.api", None)


def headers(api, client, username, role, must_change_password=False):
    api.db.create_user(username, f"{username}-password-1", role, must_change_password=must_change_password)
    token = client.post("/api/auth/login", json={"username": username, "password": f"{username}-password-1"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_every_role_may_read_it_and_nobody_else(api):
    client = TestClient(api.app)
    for role in ("owner", "analyst", "admin"):
        response = client.get("/api/status", headers=headers(api, client, f"user-{role}", role))
        assert response.status_code == 200, role
        assert response.json()["overall"] == "working"
    assert client.get("/api/status").status_code in (401, 403)
    assert client.get("/api/status", headers={"Authorization": "Bearer not-a-session"}).status_code == 401
    assert client.get("/api/status", headers=headers(api, client, "newbie", "owner", True)).status_code == 403


def test_owner_response_carries_nothing_from_sensors_or_the_install(api, sensors):
    # Attacker-written sensor text in the log must never come back out.
    write_eve(sensors["eve"], time.time(), '{"alert":{"signature":"<script>EVIL-SIGNATURE</script>"}}\n')
    client = TestClient(api.app)
    response = client.get("/api/status", headers=headers(api, client, "owner1", "owner"))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"overall", "sensors"}
    assert [sensor["id"] for sensor in body["sensors"]] == ["network", "computer", "sign_ins", "local_ai"]
    for sensor in body["sensors"]:
        assert set(sensor) == {"id", "state", "message", "last_heard"}
        assert sensor["message"] == monitoring.MESSAGES[sensor["id"]][sensor["state"]]
    text = response.text
    for secret in (str(sensors["eve"]), str(sensors["state_dir"]), "eve.json", "EVIL-SIGNATURE", "LightHouse-",
                   "Sysmon", SYSMON, '"Security"', "987654321", "pid"):
        assert secret.replace("\\", "\\\\") not in text and secret not in text, secret


def test_route_reports_pause(api, monkeypatch):
    monkeypatch.setattr(api, "_services", paused_services())
    client = TestClient(api.app)
    body = client.get("/api/status", headers=headers(api, client, "owner1", "owner")).json()
    assert body["overall"] == "paused"
    assert {sensor["id"]: sensor["state"] for sensor in body["sensors"]} == {
        "network": "paused", "computer": "paused", "sign_ins": "paused", "local_ai": "working"}
