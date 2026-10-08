"""Authentication, session and role-boundary tests for the FastAPI layer."""
import importlib
import json
import sys

import pytest
from fastapi.testclient import TestClient

from triage.db import Database, hash_token
from triage.schema import NormalizedAlert, Severity, Source, TriageResult
from triage.service import assess

ANALYST_PASSWORD = "analyst-password-1"
OWNER_PASSWORD = "owner-password-1"
ADMIN_PASSWORD = "admin-password-1"


@pytest.fixture
def api(tmp_path, monkeypatch):
    """Import triage.api fresh against a throwaway database."""
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(tmp_path / "api.db"))
    # Point the static mount at a directory that does not exist so the app under
    # test is only the API surface.
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


def seed_alert(api) -> int:
    alert = NormalizedAlert(
        source=Source.SURICATA, title="ET SCAN Nmap Scripting Engine User-Agent Detected",
        source_ip="192.168.1.25", destination_ip="192.168.1.1", rule_id="2001219", mitre=["T1046"],
        sensor_severity=Severity.HIGH,
        raw={"alert": {"signature": "ET SCAN"}, "payload_printable": "SENSITIVE-PAYLOAD-MARKER",
             "http": {"hostname": "internal-fileserver"}})
    triage = TriageResult(severity=Severity.HIGH, explanation="A device scanned your network.",
                          recommended_action="Check the device at 192.168.1.25.",
                          reasoning="ANALYST-ONLY-REASONING-MARKER", uncertainty="ANALYST-ONLY-UNCERTAINTY-MARKER")
    return api.db.store(alert, assess(alert, triage))


# --- FIX 3: no account-existence oracle -------------------------------------

def test_overlong_password_rejected_identically_for_real_and_fake_user(api, client):
    """A 73+ byte password used to reach bcrypt only for real accounts, where
    bcrypt >= 4.1 raised and produced a 500. Both must now fail the same way."""
    api.db.create_user("realuser", ANALYST_PASSWORD, "analyst")
    overlong = "x" * 200
    real = client.post("/api/auth/login", json={"username": "realuser", "password": overlong})
    fake = client.post("/api/auth/login", json={"username": "ghostuser", "password": overlong})
    assert real.status_code == fake.status_code
    assert real.status_code < 500 and fake.status_code < 500


def test_max_length_wrong_password_gives_identical_401(api, client):
    api.db.create_user("realuser", ANALYST_PASSWORD, "analyst")
    at_the_limit = "y" * 72
    real = client.post("/api/auth/login", json={"username": "realuser", "password": at_the_limit})
    fake = client.post("/api/auth/login", json={"username": "ghostuser", "password": at_the_limit})
    assert real.status_code == 401 and fake.status_code == 401
    assert real.json() == fake.json()


def test_authenticate_never_raises_on_overlong_password(api):
    api.db.create_user("realuser", ANALYST_PASSWORD, "analyst")
    assert api.db.authenticate("realuser", "z" * 400) is None
    assert api.db.authenticate("ghostuser", "z" * 400) is None


def test_duplicate_username_is_a_409_and_password_length_is_a_422(api, client):
    api.db.create_user("boss", ADMIN_PASSWORD, "admin")
    token = login(client, "boss", ADMIN_PASSWORD)
    first = client.post("/api/users", headers=auth(token), json={"username": "newbie", "password": "a-good-password", "role": "analyst"})
    assert first.status_code == 201
    duplicate = client.post("/api/users", headers=auth(token), json={"username": "newbie", "password": "a-good-password", "role": "analyst"})
    assert duplicate.status_code == 409
    too_long = client.post("/api/users", headers=auth(token), json={"username": "other", "password": "q" * 200, "role": "analyst"})
    assert too_long.status_code == 422
    too_short = client.post("/api/users", headers=auth(token), json={"username": "other", "password": "short", "role": "analyst"})
    assert too_short.status_code == 422


# --- FIX 2: sessions can be revoked -----------------------------------------

def test_logout_invalidates_the_token(api, client):
    api.db.create_user("analyst1", ANALYST_PASSWORD, "analyst")
    token = login(client, "analyst1", ANALYST_PASSWORD)
    assert client.get("/api/alerts", headers=auth(token)).status_code == 200
    assert client.post("/api/auth/logout", headers=auth(token)).status_code == 204
    assert client.get("/api/alerts", headers=auth(token)).status_code == 401


def test_session_tokens_are_stored_hashed(api):
    api.db.create_user("analyst1", ANALYST_PASSWORD, "analyst")
    session = api.db.authenticate("analyst1", ANALYST_PASSWORD)
    with api.db.connect() as con:
        stored = [row["token"] for row in con.execute("SELECT token FROM sessions")]
    assert session["token"] not in stored
    assert hash_token(session["token"]) in stored


def test_password_change_revokes_other_sessions_but_keeps_this_one(api, client):
    api.db.create_user("analyst1", ANALYST_PASSWORD, "analyst")
    other_token = login(client, "analyst1", ANALYST_PASSWORD)
    token = login(client, "analyst1", ANALYST_PASSWORD)
    changed = client.post("/api/auth/password", headers=auth(token),
                          json={"current_password": ANALYST_PASSWORD, "new_password": "a-brand-new-password"})
    assert changed.status_code == 200
    assert client.get("/api/alerts", headers=auth(token)).status_code == 200
    assert client.get("/api/alerts", headers=auth(other_token)).status_code == 401
    assert client.post("/api/auth/login", json={"username": "analyst1", "password": ANALYST_PASSWORD}).status_code == 401
    assert login(client, "analyst1", "a-brand-new-password")


def test_wrong_current_password_does_not_change_anything(api, client):
    api.db.create_user("analyst1", ANALYST_PASSWORD, "analyst")
    token = login(client, "analyst1", ANALYST_PASSWORD)
    response = client.post("/api/auth/password", headers=auth(token),
                           json={"current_password": "not-the-password", "new_password": "a-brand-new-password"})
    assert response.status_code == 401
    assert login(client, "analyst1", ANALYST_PASSWORD)


def test_admin_reset_revokes_sessions_and_forces_a_change(api, client):
    api.db.create_user("boss", ADMIN_PASSWORD, "admin")
    api.db.create_user("analyst1", ANALYST_PASSWORD, "analyst")
    victim_token = login(client, "analyst1", ANALYST_PASSWORD)
    admin_token = login(client, "boss", ADMIN_PASSWORD)
    target_id = next(u["id"] for u in api.db.users() if u["username"] == "analyst1")

    reset = client.patch(f"/api/users/{target_id}/password", headers=auth(admin_token),
                         json={"new_password": "issued-by-the-admin"})
    assert reset.status_code == 200
    assert client.get("/api/alerts", headers=auth(victim_token)).status_code == 401

    fresh = client.post("/api/auth/login", json={"username": "analyst1", "password": "issued-by-the-admin"})
    assert fresh.status_code == 200
    assert fresh.json()["must_change_password"] is True

    missing = client.patch("/api/users/98765/password", headers=auth(admin_token), json={"new_password": "does-not-matter-1"})
    assert missing.status_code == 404


def test_non_admin_cannot_reset_another_password(api, client):
    api.db.create_user("analyst1", ANALYST_PASSWORD, "analyst")
    api.db.create_user("owner1", OWNER_PASSWORD, "owner")
    token = login(client, "analyst1", ANALYST_PASSWORD)
    target_id = next(u["id"] for u in api.db.users() if u["username"] == "owner1")
    response = client.patch(f"/api/users/{target_id}/password", headers=auth(token), json={"new_password": "not-allowed-here"})
    assert response.status_code == 403


# --- FIX 1: the seeded credential is random and must be changed --------------

def test_seeded_admin_password_is_random_and_must_be_changed(tmp_path):
    db = Database(str(tmp_path / "seed.db"))
    password = db.initialize()
    assert password and len(password) >= 20
    assert password != "change-me-now"
    # Only the run that creates the account hands the password back.
    assert db.initialize() is None

    other = Database(str(tmp_path / "seed2.db"))
    assert other.initialize() != password

    session = db.authenticate("admin", password)
    assert session and session["must_change_password"] is True


def test_windows_first_run_password_file_lives_until_the_admin_changes_it(tmp_path, monkeypatch):
    """The Windows installer points LIGHTHOUSE_FIRST_RUN_DIR at the protected data
    directory, because the service logs holding the banner are rotated."""
    handoff = tmp_path / "data"; handoff.mkdir()
    monkeypatch.setenv("LIGHTHOUSE_FIRST_RUN_DIR", str(handoff))
    monkeypatch.delenv("LIGHTHOUSE_DESKTOP", raising=False)
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(tmp_path / "first.db"))
    monkeypatch.setenv("LIGHTHOUSE_STATIC_DIR", str(tmp_path / "no-dashboard-build"))
    sys.modules.pop("triage.api", None)
    try:
        module = importlib.import_module("triage.api")
        password_file = handoff / "first-run-password.txt"
        password = password_file.read_text(encoding="utf-8").strip()
        assert len(password) >= 20
        client = TestClient(module.app)
        token = login(client, "admin", password)
        # Signing in is not enough; it goes when the admin sets their own password.
        assert password_file.exists()
        changed = client.post("/api/auth/password", headers=auth(token),
                              json={"current_password": password, "new_password": "the-owners-own-password"})
        assert changed.status_code == 200
        assert not password_file.exists()
        # A restart does not write a new one: the account already exists.
        assert module.db.initialize() is None and not password_file.exists()
    finally:
        sys.modules.pop("triage.api", None)


def test_must_change_password_blocks_normal_routes(api, client):
    api.db.create_user("newadmin", "temporary-password", "admin", must_change_password=True)
    session = client.post("/api/auth/login", json={"username": "newadmin", "password": "temporary-password"})
    assert session.status_code == 200
    assert session.json()["must_change_password"] is True
    token = session.json()["token"]

    for method, path in (("get", "/api/alerts"), ("get", "/api/trends"), ("get", "/api/users"),
                         ("get", "/api/preferences"), ("get", "/api/advanced/health"), ("get", "/api/advanced/devices")):
        response = getattr(client, method)(path, headers=auth(token))
        assert response.status_code == 403, f"{path} should be blocked, got {response.status_code}"

    # The escape hatches stay open.
    assert client.get("/health").status_code == 200
    changed = client.post("/api/auth/password", headers=auth(token),
                          json={"current_password": "temporary-password", "new_password": "chosen-by-the-user"})
    assert changed.status_code == 200
    assert client.get("/api/alerts", headers=auth(token)).status_code == 200
    assert client.post("/api/auth/logout", headers=auth(token)).status_code == 204


# --- FIX 4: owners never receive raw evidence -------------------------------

def test_owner_alert_detail_hides_raw_rule_id_and_reasoning(api, client):
    alert_id = seed_alert(api)
    api.db.create_user("owner1", OWNER_PASSWORD, "owner")
    api.db.create_user("analyst1", ANALYST_PASSWORD, "analyst")

    owner = client.get(f"/api/alerts/{alert_id}", headers=auth(login(client, "owner1", OWNER_PASSWORD)))
    assert owner.status_code == 200
    body = owner.json()
    assert "raw" not in body
    assert "rule_id" not in body
    assert "reasoning" not in body["triage"]
    serialized = json.dumps(body)
    assert "SENSITIVE-PAYLOAD-MARKER" not in serialized
    assert "ANALYST-ONLY-REASONING-MARKER" not in serialized
    assert "internal-fileserver" not in serialized
    # Confidence internals are analyst-only too.
    for hidden in ("model_confidence", "confidence_reasons", "uncertainty"):
        assert hidden not in body["triage"]
    assert "ANALYST-ONLY-UNCERTAINTY-MARKER" not in serialized
    # Everything an owner is supposed to see survives.
    assert body["triage"]["severity"] == "high"
    assert body["triage"]["confidence"] in {"high", "medium", "low"}
    assert body["triage"]["guidance_tier"] in {"standard", "caution", "review", "get_help"}
    assert body["triage"]["explanation"]
    assert body["title"]


def test_alert_list_carries_confidence_and_tier_but_nothing_analyst_only(api, client):
    seed_alert(api)
    api.db.create_user("owner1", OWNER_PASSWORD, "owner")
    rows = client.get("/api/alerts", headers=auth(login(client, "owner1", OWNER_PASSWORD))).json()
    assert rows[0]["confidence"] and rows[0]["guidance_tier"]
    for hidden in ("model_confidence", "confidence_reasons", "uncertainty", "reasoning", "raw", "rule_id"):
        assert hidden not in rows[0]


def test_analyst_alert_detail_still_has_the_evidence(api, client):
    alert_id = seed_alert(api)
    api.db.create_user("analyst1", ANALYST_PASSWORD, "analyst")
    response = client.get(f"/api/alerts/{alert_id}", headers=auth(login(client, "analyst1", ANALYST_PASSWORD)))
    assert response.status_code == 200
    body = response.json()
    assert body["raw"]["payload_printable"] == "SENSITIVE-PAYLOAD-MARKER"
    assert body["rule_id"] == "2001219"
    assert body["triage"]["reasoning"] == "ANALYST-ONLY-REASONING-MARKER"
    assert body["triage"]["uncertainty"] == "ANALYST-ONLY-UNCERTAINTY-MARKER"
    assert body["triage"]["model_confidence"] == "low"  # TriageResult's default when the model omits it
    assert isinstance(body["triage"]["confidence_reasons"], list)


# --- FIX 6/7: deployment posture --------------------------------------------

def test_schema_and_docs_are_not_published_by_default(client):
    for path in ("/openapi.json", "/docs", "/redoc"):
        assert client.get(path).status_code == 404


def test_no_cors_headers_without_configured_origins(client):
    response = client.get("/health", headers={"Origin": "http://192.168.1.99:5173"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in {k.lower() for k in response.headers}


def test_ingestion_health_requires_analyst_and_reports_failure(api, client, tmp_path, monkeypatch):
    from triage.ingest.health import report
    # Event Log readers, and so their health, exist only on Windows.
    monkeypatch.setattr(sys, 'platform', 'win32')
    monkeypatch.setenv('LIGHTHOUSE_EVENT_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('LIGHTHOUSE_SYSMON_CHANNEL', '')
    monkeypatch.setenv('LIGHTHOUSE_SECURITY_CHANNEL', 'Security')
    assert client.get('/api/advanced/ingestion').status_code in (401, 403)
    api.db.create_user('health-owner', OWNER_PASSWORD, 'owner')
    api.db.create_user('health-analyst', ANALYST_PASSWORD, 'analyst')
    owner = login(client, 'health-owner', OWNER_PASSWORD)
    analyst = login(client, 'health-analyst', ANALYST_PASSWORD)
    assert client.get('/api/advanced/ingestion', headers=auth(owner)).status_code == 403
    report(tmp_path / 'state', 'Security', 'error')
    response = client.get('/api/advanced/ingestion', headers=auth(analyst))
    assert response.status_code == 200
    assert response.json() == {'ok': False, 'channels': {'Security': 'error'}}
