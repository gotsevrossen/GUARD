"""Pausing/resuming monitoring and the GitHub update check (all simulated)."""
import asyncio
import importlib
import sys

import httpx
import pytest
from fastapi.testclient import TestClient

from triage import monitoring, updates

# The real one; an autouse fixture below pins installed_version for the other tests.
REAL_INSTALLED_VERSION = updates.installed_version


class FakeServices:
    def __init__(self, state="running", fail=False, denied=False):
        self.states = {name: state for name in monitoring.MONITORING_SERVICES}
        self.calls, self.fail, self.denied = [], fail, denied

    def state(self, name):
        return self.states.get(name)

    def set_automatic(self, name, automatic):
        if self.denied:
            raise PermissionError("not allowed to change Windows services")
        self.calls.append(("auto" if automatic else "manual", name))

    def stop(self, name):
        if self.fail:
            raise OSError("access denied")
        self.calls.append(("stop", name))
        self.states[name] = "stopped"

    def start(self, name):
        self.calls.append(("start", name))
        self.states[name] = "running"


def test_pause_stops_and_disables_then_resume_restores_in_order():
    services = FakeServices()
    assert monitoring.status(services) == {"available": True, "paused": False,
                                           "services": {name: "running" for name in monitoring.MONITORING_SERVICES}}
    monitoring.pause(services)
    assert services.calls == [("manual", "LightHouse-Ingestion"), ("stop", "LightHouse-Ingestion"),
                              ("manual", "LightHouse-Suricata"), ("stop", "LightHouse-Suricata")]
    assert monitoring.status(services)["paused"] is True
    services.calls.clear()
    monitoring.resume(services)
    # Suricata first: ingestion depends on it.
    assert services.calls == [("auto", "LightHouse-Suricata"), ("start", "LightHouse-Suricata"),
                              ("auto", "LightHouse-Ingestion"), ("start", "LightHouse-Ingestion")]
    assert monitoring.status(None) == {"available": False, "paused": False, "services": {}}


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(tmp_path / "monitor.db"))
    monkeypatch.setenv("LIGHTHOUSE_STATIC_DIR", str(tmp_path / "no-dashboard-build"))
    sys.modules.pop("triage.api", None)
    module = importlib.import_module("triage.api")
    try:
        yield module
    finally:
        sys.modules.pop("triage.api", None)


def headers(api, client, username, role):
    api.db.create_user(username, f"{username}-password-1", role)
    token = client.post("/api/auth/login", json={"username": username, "password": f"{username}-password-1"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_only_admins_pause_and_everyone_sees_the_state(api, monkeypatch):
    services = FakeServices()
    monkeypatch.setattr(api, "_services", services)
    monkeypatch.setattr(api, "_local_chat_model", object())
    client = TestClient(api.app)
    owner, admin = headers(api, client, "owner1", "owner"), headers(api, client, "boss", "admin")
    assert client.get("/api/monitoring", headers=owner).json()["paused"] is False
    assert client.post("/api/monitoring", headers=owner, json={"paused": True}).status_code == 403
    paused = client.post("/api/monitoring", headers=admin, json={"paused": True})
    assert paused.status_code == 200 and paused.json()["paused"] is True
    assert api._local_chat_model is None, "pausing frees the chat AI's memory"
    assert client.get("/api/monitoring", headers=owner).json()["paused"] is True
    assert client.post("/api/monitoring", headers=admin, json={"paused": False}).json()["paused"] is False


def test_pause_errors_are_reported_not_raised(api, monkeypatch):
    client = TestClient(api.app)
    admin = headers(api, client, "boss", "admin")
    monkeypatch.setattr(api, "_services", None)
    assert client.post("/api/monitoring", headers=admin, json={"paused": True}).status_code == 409
    monkeypatch.setattr(api, "_services", FakeServices(fail=True))
    assert client.post("/api/monitoring", headers=admin, json={"paused": True}).status_code == 502
    # A hand-started copy (not the SYSTEM service) gets told why, not "try again".
    monkeypatch.setattr(api, "_services", FakeServices(state="stopped", denied=True))
    denied = client.post("/api/monitoring", headers=admin, json={"paused": False})
    assert denied.status_code == 403 and "installed LightHouse app" in denied.json()["detail"]


@pytest.mark.parametrize("value,expected", [("v1.2.3", (1, 2, 3)), ("0.2", (0, 2, 0)), ("V2.0.0-beta", (2, 0, 0)),
                                            ("release", None), (None, None)])
def test_version_parsing(value, expected):
    assert updates.version_tuple(value) == expected


def github(status=200, tag="v9.0.0", url=f"{updates.RELEASES_PAGE}tag/v9.0.0", calls=None):
    def handle(request):
        if calls is not None:
            calls.append(request)
        assert str(request.url) == updates.LATEST_RELEASE_API
        if status != 200:
            return httpx.Response(status)
        return httpx.Response(200, json={"tag_name": tag, "html_url": url})
    return httpx.MockTransport(handle)


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.setattr(updates, "_cache", {"at": 0.0, "ttl": 0.0, "release": None})
    monkeypatch.setattr(updates, "installed_version", lambda: "0.1.0")


def test_newer_release_is_offered_and_cached():
    calls = []
    result = asyncio.run(updates.check(github(calls=calls), now=1000.0))
    assert result == {"current": "0.1.0", "latest": "v9.0.0", "available": True,
                      "url": f"{updates.RELEASES_PAGE}tag/v9.0.0", "installable": False,
                      "install": {"state": "idle", "error": None}}
    # Reloading the dashboard again soon does not ask GitHub again.
    asyncio.run(updates.check(github(calls=calls), now=1000.0 + 60))
    assert len(calls) == 1
    # Nothing about this computer is sent: a plain GET with no query or body.
    assert calls[0].method == "GET" and not calls[0].url.query and not calls[0].content


@pytest.mark.parametrize("transport", [
    github(tag="v0.1.0"),                                   # same version
    github(tag="v0.0.9"),                                   # older
    github(status=404),                                     # no releases yet
    github(url="https://evil.example/LightHouse-Setup.exe"),  # never offer a foreign link
    httpx.MockTransport(lambda request: (_ for _ in ()).throw(httpx.ConnectError("offline", request=request))),
])
def test_no_update_offered(transport):
    assert asyncio.run(updates.check(transport, now=5000.0))["available"] is False


def test_update_route_is_admin_only(api, monkeypatch):
    async def fake_check():
        return {"current": "0.1.0", "latest": "v0.2.0", "available": True, "url": f"{updates.RELEASES_PAGE}tag/v0.2.0"}
    monkeypatch.setattr(updates, "check", fake_check)
    client = TestClient(api.app)
    owner, admin = headers(api, client, "owner1", "owner"), headers(api, client, "boss", "admin")
    assert client.get("/api/updates", headers=owner).status_code == 403
    assert client.get("/api/updates", headers=admin).json()["available"] is True


INSTALLER = b"MZ pretend installer"
INSTALLER_SHA = __import__("hashlib").sha256(INSTALLER).hexdigest()
DOWNLOADS = f"{updates.DOWNLOAD_PREFIX}v9.0.0/"


def release_with_assets(checksum=f"{INSTALLER_SHA}  LightHouse-Setup.exe", installer=INSTALLER,
                        storage_host="release-assets.githubusercontent.com", calls=None):
    def handle(request):
        url = str(request.url)
        if calls is not None:
            calls.append(url)
        if url == updates.LATEST_RELEASE_API:
            return httpx.Response(200, json={
                "tag_name": "v9.0.0", "html_url": f"{updates.RELEASES_PAGE}tag/v9.0.0",
                "assets": [{"name": "LightHouse-Setup.exe", "browser_download_url": DOWNLOADS + "LightHouse-Setup.exe"},
                           {"name": "LightHouse-Setup.exe.sha256",
                            "browser_download_url": DOWNLOADS + "LightHouse-Setup.exe.sha256"}]})
        if url == DOWNLOADS + "LightHouse-Setup.exe.sha256":
            return httpx.Response(200, text=checksum)
        if url == DOWNLOADS + "LightHouse-Setup.exe":
            # GitHub sends release downloads on to its asset storage.
            return httpx.Response(302, headers={"Location": f"https://{storage_host}/asset/setup.exe"})
        if url == f"https://{storage_host}/asset/setup.exe":
            return httpx.Response(200, content=installer)
        return httpx.Response(404)
    return httpx.MockTransport(handle)


@pytest.fixture
def installed(tmp_path, monkeypatch):
    monkeypatch.setattr(updates, "install_dir", lambda: tmp_path)
    monkeypatch.setattr(updates, "_install", {"state": "idle", "error": None})
    return tmp_path


def run_install(transport):
    launched = []

    async def go():
        await updates.start_install(transport, launch=lambda installer, install: launched.append(installer))
        await updates._install_task
    asyncio.run(go())
    return launched, dict(updates._install)


def test_release_with_installer_and_checksum_is_installable():
    assert asyncio.run(updates.check(release_with_assets(), now=1.0))["installable"] is True
    # The update page alone (no checksum file) is offered as a link, not installed.
    assert asyncio.run(updates.check(github(), now=2.0e9))["installable"] is False


def test_verified_installer_is_saved_in_the_data_folder_and_launched(installed):
    launched, state = run_install(release_with_assets())
    assert state == {"state": "installing", "error": None}
    assert launched == [installed / "data" / "updates" / "LightHouse-Setup-9.0.0.exe"]
    assert launched[0].read_bytes() == INSTALLER


@pytest.mark.parametrize("transport,reason", [
    (release_with_assets(installer=b"tampered"), "did not match its checksum"),
    (release_with_assets(checksum="not a hash"), "checksum file is not valid"),
    (release_with_assets(storage_host="evil.example"), "unexpected address"),
])
def test_unverified_downloads_are_never_launched(installed, transport, reason):
    launched, state = run_install(transport)
    assert launched == [] and state["state"] == "failed" and reason in state["error"]
    assert not any((installed / "data" / "updates").glob("*.exe"))


def test_a_copy_that_is_not_the_installed_service_cannot_update(monkeypatch):
    monkeypatch.setattr(updates, "install_dir", lambda: None)
    with pytest.raises(PermissionError):
        asyncio.run(updates.start_install(release_with_assets()))


def test_install_route_is_admin_only(api, monkeypatch):
    async def fake_start():
        return {"state": "downloading", "error": None}
    monkeypatch.setattr(updates, "start_install", fake_start)
    client = TestClient(api.app)
    owner, admin = headers(api, client, "owner1", "owner"), headers(api, client, "boss", "admin")
    assert client.post("/api/updates/install", headers=owner).status_code == 403
    started = client.post("/api/updates/install", headers=admin)
    assert started.status_code == 202 and started.json()["state"] == "downloading"

    async def refused():
        raise PermissionError("not the installed LightHouse service")
    monkeypatch.setattr(updates, "start_install", refused)
    denied = client.post("/api/updates/install", headers=admin)
    assert denied.status_code == 403 and "installed LightHouse app" in denied.json()["detail"]


def test_the_highest_version_record_wins(monkeypatch):
    """Two .dist-info records (an upgrade that merged files) must not report the old one."""
    class Dist:
        def __init__(self, version):
            self.version = version
    monkeypatch.setattr(updates.metadata, "distributions",
                        lambda name: [Dist("0.1.0"), Dist("0.3.1"), Dist("not-a-version")])
    assert REAL_INSTALLED_VERSION() == "0.3.1"
    monkeypatch.setattr(updates.metadata, "distributions", lambda name: [])
    assert REAL_INSTALLED_VERSION() == "0.0.0"


def test_an_update_that_did_not_take_is_not_offered_again(installed, monkeypatch):
    run_install(release_with_assets())
    # The service restarted after setup, but the version did not change.
    monkeypatch.setattr(updates, "_install", {"state": "idle", "error": None})
    again = asyncio.run(updates.check(release_with_assets(), now=3.0e9))
    assert again["available"] is True and again["installable"] is False
    assert again["install"]["state"] == "failed" and "did not finish" in again["install"]["error"]
    # Once the version has moved on, the record is forgotten.
    monkeypatch.setattr(updates, "installed_version", lambda: "9.0.0")
    asyncio.run(updates.check(release_with_assets(), now=4.0e9))
    assert not (installed / "data" / "config" / "update-attempt.json").exists()
