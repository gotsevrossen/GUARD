"""The Admin page's activity log and user management (roles, resets, removal)."""
import importlib
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient

from triage import monitoring, updates
from triage.audit import AuditAction
from triage.schema import NormalizedAlert, Severity, Source, TriageResult
from triage.service import assess


class FakeServices:
    """Stands in for the Windows Service Control Manager."""
    def __init__(self, fail=False):
        self.states = {name: "running" for name in monitoring.MONITORING_SERVICES}
        self.starts = {name: "automatic" for name in monitoring.MONITORING_SERVICES}
        self.fail = fail

    def state(self, name):
        return self.states.get(name)

    def start_type(self, name):
        return self.starts.get(name)

    def set_automatic(self, name, automatic):
        self.starts[name] = "automatic" if automatic else "manual"

    def stop(self, name):
        if self.fail:
            raise OSError("access denied")
        self.states[name] = "stopped"

    def start(self, name):
        self.states[name] = "running"

    def request_stop(self, name):
        pass


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("LIGHTHOUSE_STATIC_DIR", str(tmp_path / "no-dashboard-build"))
    monkeypatch.setenv("LIGHTHOUSE_GENAI_KEY_FILE", str(tmp_path / "genai-key.bin"))
    monkeypatch.delenv("LIGHTHOUSE_GENAI_MODEL", raising=False)
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


def password(name):
    return f"{name}-password-1"


def login(client, name, password_=None):
    response = client.post("/api/auth/login", json={"username": name, "password": password_ or password(name)})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def make(api, client, name, role):
    api.db.create_user(name, password(name), role)
    return login(client, name)


def user_id(api, name):
    return next(u["id"] for u in api.db.users() if u["username"] == name)


def entries(api):
    return api.db.audit_entries(200)[0]


def last(api):
    return entries(api)[0]


def seed_alert(api) -> int:
    alert = NormalizedAlert(source=Source.SURICATA, title="ATTACKER-TITLE <script>", source_ip="192.168.1.25",
                            sensor_severity=Severity.HIGH, raw={"alert": {"signature": "ET SCAN"}})
    triage = TriageResult(severity=Severity.HIGH, explanation="A device scanned your network.",
                          recommended_action="Check the device.")
    return api.db.store(alert, assess(alert, triage))


# --- what gets recorded ------------------------------------------------------

def test_sign_ins_are_recorded_without_keeping_mistyped_names(api, client):
    make(api, client, "boss", "admin")
    assert (last(api).username, last(api).action) == ("boss", AuditAction.SIGN_IN)
    client.post("/api/auth/login", json={"username": "boss", "password": "wrong-password-1"})
    assert (last(api).username, last(api).action) == ("boss", AuditAction.SIGN_IN_FAILED)
    # A password typed into the username box must not land in the log.
    client.post("/api/auth/login", json={"username": "MySecretPassw0rd!", "password": "x"})
    assert (last(api).username, last(api).action) == ("", AuditAction.SIGN_IN_FAILED)
    assert all("MySecretPassw0rd" not in str(entry.model_dump()) for entry in entries(api))


def test_alert_status_change_is_recorded_by_id_not_title(api, client):
    owner = make(api, client, "owner1", "owner")
    alert_id = seed_alert(api)
    assert client.patch(f"/api/alerts/{alert_id}/status", headers=owner, json={"status": "dismissed"}).status_code == 200
    entry = last(api)
    assert (entry.username, entry.action, entry.target, entry.detail) == \
        ("owner1", AuditAction.ALERT_STATUS, str(alert_id), "open->dismissed")
    client.patch(f"/api/alerts/{alert_id}/status", headers=owner, json={"status": "open"})
    assert last(api).detail == "dismissed->open"
    assert all("ATTACKER-TITLE" not in str(e.model_dump()) for e in entries(api))
    # A missing alert records nothing.
    before = len(entries(api))
    assert client.patch("/api/alerts/9999/status", headers=owner, json={"status": "resolved"}).status_code == 404
    assert len(entries(api)) == before


def test_admin_actions_are_recorded(api, client, tmp_path, monkeypatch):
    services = FakeServices()
    monkeypatch.setattr(api, "_services", services)
    monkeypatch.setattr(api, "_shutdown_marker", lambda: tmp_path / "shutdown.json")
    monkeypatch.setattr(api, "SHUTDOWN_STOP_DELAY_SECONDS", 0)
    admin = make(api, client, "boss", "admin")

    assert client.post("/api/monitoring", headers=admin, json={"paused": True}).status_code == 200
    assert last(api).action == AuditAction.MONITORING_PAUSED
    assert client.post("/api/monitoring", headers=admin, json={"paused": False}).status_code == 200
    assert last(api).action == AuditAction.MONITORING_RESUMED

    note = "SECRET-BUSINESS-NOTE"
    assert client.put("/api/admin/ai-instructions", headers=admin, json={"business": note, "style": ""}).status_code == 200
    assert last(api).action == AuditAction.AI_INSTRUCTIONS_CHANGED
    assert all(note not in str(e.model_dump()) for e in entries(api)), "that it changed, never the text"

    assert client.put("/api/chat/model", headers=admin, json={"model": "local"}).status_code == 200
    assert (last(api).action, last(api).target) == (AuditAction.CHAT_MODEL_CHANGED, "local")

    async def fake_start():
        return {"state": "downloading", "error": None}
    monkeypatch.setattr(updates, "start_install", fake_start)
    assert client.post("/api/updates/install", headers=admin).status_code == 202
    assert last(api).action == AuditAction.UPDATE_INSTALL_STARTED

    assert client.post("/api/users", headers=admin,
                       json={"username": "new1", "password": "new1-password-1", "role": "analyst"}).status_code == 201
    assert (last(api).action, last(api).target, last(api).detail) == (AuditAction.USER_CREATED, "new1", "analyst")

    assert client.post("/api/shutdown", headers=admin).status_code == 202
    assert last(api).action == AuditAction.SHUT_DOWN
    assert all(e.username == "boss" for e in entries(api) if e.action != AuditAction.SIGN_IN)


def test_refused_actions_are_not_recorded(api, client, monkeypatch):
    monkeypatch.setattr(api, "_services", FakeServices(fail=True))
    owner, admin = make(api, client, "owner1", "owner"), make(api, client, "boss", "admin")
    before = len(entries(api))
    assert client.post("/api/monitoring", headers=owner, json={"paused": True}).status_code == 403
    assert client.post("/api/monitoring", headers=admin, json={"paused": True}).status_code == 502
    assert len(entries(api)) == before


def test_user_management_actions_are_recorded(api, client):
    admin = make(api, client, "boss", "admin")
    make(api, client, "owner1", "owner")
    target = user_id(api, "owner1")
    client.patch(f"/api/users/{target}/role", headers=admin, json={"role": "analyst"})
    assert (last(api).action, last(api).target, last(api).detail) == (AuditAction.USER_ROLE_CHANGED, "owner1", "owner->analyst")
    client.patch(f"/api/users/{target}/password", headers=admin, json={"new_password": "temporary-pass-1"})
    assert (last(api).action, last(api).target) == (AuditAction.USER_PASSWORD_RESET, "owner1")
    client.post(f"/api/users/{target}/sign-out", headers=admin)
    assert (last(api).action, last(api).target) == (AuditAction.USER_SIGNED_OUT, "owner1")
    client.delete(f"/api/users/{target}", headers=admin)
    assert (last(api).action, last(api).target, last(api).detail) == (AuditAction.USER_REMOVED, "owner1", "analyst")


def test_an_audit_failure_never_breaks_the_action(api, client, caplog):
    owner = make(api, client, "owner1", "owner")
    alert_id = seed_alert(api)

    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("database or disk is full")
    api.db.record_audit = broken
    assert client.patch(f"/api/alerts/{alert_id}/status", headers=owner, json={"status": "resolved"}).status_code == 200
    assert api.db.get_alert(alert_id).status == "resolved"
    assert client.post("/api/auth/login", json={"username": "owner1", "password": password("owner1")}).status_code == 200
    assert client.post("/api/auth/login", json={"username": "owner1", "password": "nope"}).status_code == 401
    assert "Could not record" in caplog.text


def test_audit_text_is_single_line_and_capped(api):
    api.db.record_audit("evil\nname‮", AuditAction.USER_CREATED, "x" * 1000 + "\r\nfake entry", "a\tb")
    entry = last(api)
    assert entry.username == "evilname"
    assert "\n" not in entry.target and len(entry.target) <= 150
    assert entry.detail == "ab"
    with pytest.raises(ValueError):
        api.db.record_audit("boss", "made_up_action")


# --- reading the log -----------------------------------------------------------

def test_activity_is_admin_only(api, client):
    owner, analyst = make(api, client, "owner1", "owner"), make(api, client, "analyst1", "analyst")
    admin = make(api, client, "boss", "admin")
    assert client.get("/api/admin/activity", headers=owner).status_code == 403
    assert client.get("/api/admin/activity", headers=analyst).status_code == 403
    assert client.get("/api/admin/activity").status_code in (401, 403)
    page = client.get("/api/admin/activity", headers=admin).json()
    assert [e["username"] for e in page["entries"]] == ["boss", "analyst1", "owner1"], "newest first"
    assert page["more"] is False


def test_activity_is_paged_and_capped(api, client):
    admin = make(api, client, "boss", "admin")
    for _ in range(7):
        api.db.record_audit("boss", AuditAction.SHUT_DOWN)
    first = client.get("/api/admin/activity", headers=admin, params={"limit": 3}).json()
    assert len(first["entries"]) == 3 and first["more"] is True
    ids = [e["id"] for e in first["entries"]]
    assert ids == sorted(ids, reverse=True)
    second = client.get("/api/admin/activity", headers=admin, params={"limit": 3, "before": ids[-1]}).json()
    assert all(e["id"] < ids[-1] for e in second["entries"])
    rest = client.get("/api/admin/activity", headers=admin, params={"limit": 200, "before": second["entries"][-1]["id"]}).json()
    assert rest["more"] is False and len(first["entries"]) + len(second["entries"]) + len(rest["entries"]) == 8
    assert client.get("/api/admin/activity", headers=admin, params={"limit": 10_000}).status_code == 422
    assert client.get("/api/admin/activity", headers=admin, params={"limit": 0}).status_code == 422


def test_the_log_is_append_only(api, client):
    make(api, client, "boss", "admin")
    # No route writes to it directly: only GET is served under the activity path.
    for route in api.app.routes:
        path = getattr(route, "path", "")
        if "activity" in path or "audit" in path:
            assert getattr(route, "methods", set()) <= {"GET", "HEAD"}, path
    assert not [name for name in dir(api.db) if "audit" in name and any(word in name for word in ("delete", "update", "edit", "clear"))]
    # And the database itself refuses edits, whatever code tries.
    with sqlite3.connect(api.db.path) as con:
        with pytest.raises(sqlite3.DatabaseError):
            con.execute("UPDATE audit_log SET username='someone-else'")
        with pytest.raises(sqlite3.DatabaseError):
            con.execute("DELETE FROM audit_log")
    assert last(api).username == "boss"


# --- user management safety rules ------------------------------------------------

@pytest.mark.parametrize("path,method,body", [
    ("/role", "patch", {"role": "owner"}), ("", "delete", None), ("/sign-out", "post", None),
    ("/password", "patch", {"new_password": "temporary-pass-1"}),
])
def test_user_management_is_admin_only(api, client, path, method, body):
    owner, analyst = make(api, client, "owner1", "owner"), make(api, client, "analyst1", "analyst")
    make(api, client, "victim", "owner")
    target = user_id(api, "victim")
    for headers in (owner, analyst):
        kwargs = {"headers": headers} | ({"json": body} if body else {})
        assert getattr(client, method)(f"/api/users/{target}{path}", **kwargs).status_code == 403
    assert "victim" in [u["username"] for u in api.db.users()]
    kwargs = {"json": body} if body else {}
    assert getattr(client, method)(f"/api/users/{target}{path}", headers=make(api, client, "boss", "admin"), **kwargs).status_code == 200
    assert getattr(client, method)(f"/api/users/9999{path}", headers=login(client, "boss"), **kwargs).status_code == 404


def test_the_last_admin_cannot_be_demoted_or_removed(api, client):
    boss = make(api, client, "boss", "admin")
    # Hand the seeded admin's role away first so "boss" is the only admin.
    assert client.patch(f"/api/users/{user_id(api, 'admin')}/role", headers=boss, json={"role": "owner"}).status_code == 200
    me = user_id(api, "boss")
    refused = client.patch(f"/api/users/{me}/role", headers=boss, json={"role": "analyst"})
    assert refused.status_code == 409 and "at least one admin" in refused.json()["detail"]
    assert api.db.user(me)["role"] == "admin"
    # Directly in the database too, since that is where the check actually lives.
    assert api.db.set_role(me, "owner") is False
    assert api.db.delete_user(me) is False
    # With a second admin, demoting yourself is allowed (and signs you out).
    make(api, client, "second", "admin")
    assert client.patch(f"/api/users/{me}/role", headers=boss, json={"role": "analyst"}).status_code == 200
    assert client.get("/api/users", headers=boss).status_code == 401


def test_an_admin_cannot_remove_their_own_account_or_the_built_in_admin(api, client):
    boss = make(api, client, "boss", "admin")
    refused = client.delete(f"/api/users/{user_id(api, 'boss')}", headers=boss)
    assert refused.status_code == 409 and "your own account" in refused.json()["detail"]
    refused = client.delete(f"/api/users/{user_id(api, 'admin')}", headers=boss)
    assert refused.status_code == 409 and "built-in admin" in refused.json()["detail"]
    assert {"boss", "admin"} <= {u["username"] for u in api.db.users()}


def test_invalid_role_is_refused(api, client):
    boss = make(api, client, "boss", "admin")
    make(api, client, "owner1", "owner")
    assert client.patch(f"/api/users/{user_id(api, 'owner1')}/role", headers=boss, json={"role": "root"}).status_code == 422


def two_sessions(client, name):
    return login(client, name), login(client, name)


def test_role_change_ends_the_users_sessions(api, client):
    boss = make(api, client, "boss", "admin")
    make(api, client, "owner1", "owner")
    sessions = two_sessions(client, "owner1")
    assert client.patch(f"/api/users/{user_id(api, 'owner1')}/role", headers=boss, json={"role": "analyst"}).status_code == 200
    assert all(client.get("/api/alerts", headers=h).status_code == 401 for h in sessions)
    assert client.get("/api/alerts", headers=boss).status_code == 200, "only the target is signed out"
    assert login(client, "owner1")


def test_password_reset_ends_sessions_and_forces_a_change(api, client):
    boss = make(api, client, "boss", "admin")
    make(api, client, "owner1", "owner")
    sessions = two_sessions(client, "owner1")
    assert client.patch(f"/api/users/{user_id(api, 'owner1')}/password", headers=boss,
                        json={"new_password": "short"}).status_code == 422, "the 12-character minimum still applies"
    assert client.patch(f"/api/users/{user_id(api, 'owner1')}/password", headers=boss,
                        json={"new_password": "temporary-pass-1"}).status_code == 200
    assert all(client.get("/api/alerts", headers=h).status_code == 401 for h in sessions)
    fresh = login(client, "owner1", "temporary-pass-1")
    assert client.get("/api/alerts", headers=fresh).status_code == 403, "must choose a new password first"


def test_removal_ends_sessions_and_the_account(api, client):
    boss = make(api, client, "boss", "admin")
    owner = make(api, client, "owner1", "owner")
    target = user_id(api, "owner1")
    api.db.set_user_setting("owner1", "notification_threshold", "high")
    assert client.delete(f"/api/users/{target}", headers=boss).status_code == 200
    # The log keeps who it was.
    assert (last(api).action, last(api).target) == (AuditAction.USER_REMOVED, "owner1")
    assert client.get("/api/alerts", headers=owner).status_code == 401
    assert client.post("/api/auth/login", json={"username": "owner1", "password": password("owner1")}).status_code == 401
    assert api.db.user(target) is None
    with sqlite3.connect(api.db.path) as con:
        assert con.execute("SELECT COUNT(*) FROM user_settings WHERE user_id=?", (target,)).fetchone()[0] == 0


def test_sign_out_everywhere_ends_only_that_users_sessions(api, client):
    boss = make(api, client, "boss", "admin")
    make(api, client, "owner1", "owner")
    sessions = two_sessions(client, "owner1")
    response = client.post(f"/api/users/{user_id(api, 'owner1')}/sign-out", headers=boss)
    assert response.status_code == 200 and response.json()["ended"] == 3
    assert all(client.get("/api/alerts", headers=h).status_code == 401 for h in sessions)
    assert client.get("/api/alerts", headers=boss).status_code == 200


def test_usernames_follow_the_form_rule_on_the_server(api, client):
    """The activity log names command-line changes "(this computer)"; no dashboard
    account may look like that, or carry characters that read differently than they look."""
    admin = make(api, client, "boss", "admin")
    for name in ("(this computer)", "bad name", "-dash", "na\u202eme", "x@y"):
        response = client.post("/api/users", headers=admin, json={"username": name, "password": "long-enough-pass-1", "role": "owner"})
        assert response.status_code == 422, name
    assert client.post("/api/users", headers=admin,
                       json={"username": "front.desk_2-a", "password": "long-enough-pass-1", "role": "owner"}).status_code == 201
