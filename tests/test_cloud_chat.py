"""Opt-in chat through Purdue GenAI Studio: the network is a mock transport here."""
import asyncio
import importlib
import json
import logging
import sys

import httpx
import pytest
from fastapi.testclient import TestClient

from triage import cloud_key, cloud_model
from triage.cloud_model import GENAI_BASE_URL, PurdueChatModel
from triage.llm import CHAT_STOPPED_NOTE, TriageModel, stream_chat
from triage.schema import ChatMessage

KEY = "sk-TEST-KEY-never-printed-0123456789"


class LocalModel(TriageModel):
    def __init__(self):
        self.chats = 0
        self.triaged = []

    async def triage(self, alert):
        self.triaged.append(alert)
        return "local triage"

    async def chat(self, system, messages, *, max_tokens, temperature):
        self.chats += 1
        return "local answer"


def sse(*pieces, done=True):
    lines = [f"data: {json.dumps({'choices': [{'delta': {'content': piece}}]})}\n\n" for piece in pieces]
    return "".join(lines) + ("data: [DONE]\n\n" if done else "")


def recording(handler):
    seen = []
    def wrapped(request):
        seen.append(request)
        return handler(request)
    return httpx.MockTransport(wrapped), seen


def collect(model):
    async def run():
        return [piece async for piece in model.chat_stream("SYS", [{"role": "user", "content": "q"}],
                                                           max_tokens=300, temperature=0.3)]
    return asyncio.run(run())


def test_streamed_answer_comes_from_genai_studio():
    transport, seen = recording(lambda request: httpx.Response(200, text=sse("Hello", " there")))
    local = LocalModel()
    model = PurdueChatModel(local, KEY, "gpt-oss:120b", transport=transport)
    assert collect(model) == ["Hello", " there"] and local.chats == 0
    request = seen[0]
    assert str(request.url) == f"{GENAI_BASE_URL}/api/chat/completions"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    body = json.loads(request.content)
    assert body["model"] == "gpt-oss:120b" and body["stream"] is True and "max_tokens" not in body
    assert body["messages"][0] == {"role": "system", "content": "SYS"}


@pytest.mark.parametrize("response", [
    httpx.Response(401, json={"detail": "bad key"}),
    httpx.Response(429, json={"detail": "slow down"}),
    httpx.Response(500, text="boom"),
    httpx.Response(200, text="null"),                      # GenAI Studio's over-limit reply
    httpx.Response(302, headers={"location": "https://evil.example/steal"}),
])
def test_failures_fall_back_to_the_local_model_and_pause(response, caplog):
    transport, seen = recording(lambda request: response)
    local = LocalModel()
    model = PurdueChatModel(local, KEY, transport=transport)
    with caplog.at_level(logging.WARNING):
        assert collect(model) == ["local answer"]
    assert len(seen) == 1, "a redirect must never be followed"
    assert not model.online
    collect(model)  # paused: straight to the local model
    assert len(seen) == 1 and local.chats == 2
    assert KEY not in caplog.text and KEY not in repr(model)


def test_network_errors_fall_back_too(caplog):
    def refuse(request):
        raise httpx.ConnectError("no route to host", request=request)
    model = PurdueChatModel(LocalModel(), KEY, transport=httpx.MockTransport(refuse))
    with caplog.at_level(logging.WARNING):
        assert collect(model) == ["local answer"]
    assert KEY not in caplog.text


def test_failure_mid_answer_keeps_the_text():
    transport, _ = recording(lambda request: httpx.Response(200, text=sse("Part one.", done=False) + "data: [1]\n\n"))
    model = PurdueChatModel(LocalModel(), KEY, transport=transport)
    async def run():
        return [event async for event in stream_chat(model, [ChatMessage(role="user", content="hi")], [], False)]
    events = asyncio.run(run())
    text = "".join(event["text"] for event in events if event["type"] == "delta")
    assert text == f"Part one.\n\n{CHAT_STOPPED_NOTE}" and events[-1] == {"type": "done", "available": True}


def test_non_streaming_chat_and_triage():
    reply = {"choices": [{"message": {"role": "assistant", "content": "Sysmon activity question"}}]}
    transport, seen = recording(lambda request: httpx.Response(200, json=reply))
    local = LocalModel()
    model = PurdueChatModel(local, KEY, transport=transport)
    text = asyncio.run(model.chat("TITLE", [{"role": "user", "content": "q"}], max_tokens=16, temperature=0.2))
    assert text == "Sysmon activity question" and json.loads(seen[0].content)["stream"] is False
    # Alert triage never goes out.
    assert asyncio.run(model.triage("alert")) == "local triage" and len(seen) == 1
    assert asyncio.run(model.warm("SYS", [])) is False


def test_model_choice(tmp_path, monkeypatch):
    monkeypatch.setenv("LIGHTHOUSE_GENAI_KEY_FILE", str(tmp_path / "genai-key.bin"))
    monkeypatch.delenv("LIGHTHOUSE_GENAI_MODEL", raising=False)
    assert cloud_model.genai_model_name() == "gpt-oss:120b"
    (tmp_path / "genai.json").write_text(json.dumps({"model": "llama3.3:70b"}), encoding="utf-8")
    assert cloud_model.genai_model_name() == "llama3.3:70b"
    monkeypatch.setenv("LIGHTHOUSE_GENAI_MODEL", "other:7b")
    assert cloud_model.genai_model_name() == "other:7b"


def test_key_shape_is_checked():
    assert cloud_key.clean_key("  abc123  ") == "abc123"
    for bad in ("", "   ", "has space", "x" * 600):
        with pytest.raises(ValueError):
            cloud_key.clean_key(bad)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_key_is_stored_encrypted_and_round_trips(tmp_path):
    path = tmp_path / "genai-key.bin"
    cloud_key.save(KEY, path)
    assert KEY.encode() not in path.read_bytes()
    assert cloud_key.load(path) == KEY
    path.write_bytes(b"not dpapi")
    assert cloud_key.load(path) is None
    assert cloud_key.clear(path) is True and cloud_key.load(path) is None


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("LIGHTHOUSE_DB_PATH", str(tmp_path / "cloud.db"))
    monkeypatch.setenv("LIGHTHOUSE_STATIC_DIR", str(tmp_path / "no-dashboard-build"))
    monkeypatch.setenv("LIGHTHOUSE_GENAI_KEY_FILE", str(tmp_path / "genai-key.bin"))
    sys.modules.pop("triage.api", None)
    module = importlib.import_module("triage.api")
    try:
        yield module
    finally:
        sys.modules.pop("triage.api", None)


def test_provider_route_and_wrapping(api, tmp_path, monkeypatch):
    client = TestClient(api.app)
    api.db.create_user("owner1", "owner-password-1", "owner")
    token = client.post("/api/auth/login", json={"username": "owner1", "password": "owner-password-1"}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    monkeypatch.setattr(api, "_local_chat_model", LocalModel())
    monkeypatch.setattr(cloud_key, "load", lambda path=None: KEY if (tmp_path / "genai-key.bin").is_file() else None)
    assert client.get("/api/chat/provider").status_code in (401, 403)
    assert client.get("/api/chat/provider", headers=headers).json() == {"provider": "local"}
    (tmp_path / "genai-key.bin").write_bytes(b"encrypted")
    response = client.get("/api/chat/provider", headers=headers)
    assert response.json() == {"provider": "purdue"} and KEY not in response.text
    assert isinstance(api.chat_model(), PurdueChatModel)
    # `cloud_key clear` without a restart: questions stop going out at once, and the
    # footer says so (the cached model held the key in memory).
    (tmp_path / "genai-key.bin").unlink()
    assert client.get("/api/chat/provider", headers=headers).json() == {"provider": "local"}
    assert not isinstance(api.chat_model(), PurdueChatModel)
    # With a stored key, chat is wrapped; without one, the local model is used as is.
    local = LocalModel()
    monkeypatch.setattr(cloud_key, "load", lambda path=None: KEY)
    assert isinstance(api._with_genai_studio(local), PurdueChatModel)
    monkeypatch.setattr(cloud_key, "load", lambda path=None: None)
    assert api._with_genai_studio(local) is local


def login_as(api, client, username, role):
    api.db.create_user(username, f"{username}-password-1", role)
    token = client.post("/api/auth/login", json={"username": username, "password": f"{username}-password-1"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_only_admins_choose_the_chat_model_from_the_curated_list(api, tmp_path, monkeypatch):
    client = TestClient(api.app)
    owner, admin = login_as(api, client, "owner1", "owner"), login_as(api, client, "boss", "admin")
    assert client.get("/api/chat/models", headers=owner).status_code == 403
    assert client.put("/api/chat/model", headers=owner, json={"model": "local"}).status_code == 403
    listing = client.get("/api/chat/models", headers=admin).json()
    ids = [choice["id"] for choice in listing["choices"]]
    assert ids[0] == "gpt-oss:120b" and "local" in ids and len(ids) <= 6
    assert listing["key_configured"] is False
    # Purdue models need a key; anything off the list is refused.
    assert client.put("/api/chat/model", headers=admin, json={"model": "gemma4:26b-a4b"}).status_code == 409
    assert client.put("/api/chat/model", headers=admin, json={"model": "deepseek-r1:32b"}).status_code == 422
    (tmp_path / "genai-key.bin").write_bytes(b"encrypted")
    monkeypatch.setattr(cloud_key, "load", lambda path=None: KEY)
    monkeypatch.setattr(api, "_local_chat_model", LocalModel())
    assert client.put("/api/chat/model", headers=admin, json={"model": "gemma4:26b-a4b"}).status_code == 200
    assert json.loads((tmp_path / "genai.json").read_text(encoding="utf-8")) == {"model": "gemma4:26b-a4b"}
    assert client.get("/api/chat/provider", headers=owner).json() == {"provider": "purdue"}
    # A model pinned by the service setting cannot be "switched" here: the dashboard
    # would claim "On this computer only" while questions still went out.
    monkeypatch.setenv("LIGHTHOUSE_GENAI_MODEL", "gpt-oss:120b")
    assert client.put("/api/chat/model", headers=admin, json={"model": "local"}).status_code == 409


def test_key_cli_only_writes_into_the_installed_data_folder(tmp_path, monkeypatch):
    """Run with any other Python, `set` must not write the key somewhere other users
    could have prepared (the old ProgramData fallback)."""
    monkeypatch.delenv("LIGHTHOUSE_GENAI_KEY_FILE", raising=False)
    monkeypatch.setenv("ProgramData", str(tmp_path))
    (tmp_path / "LightHouse" / "config").mkdir(parents=True)
    assert "ProgramData" not in str(cloud_key.key_path()) and str(tmp_path) not in str(cloud_key.key_path())
    if sys.platform == "win32":
        monkeypatch.setattr(cloud_key, "installed_runtime", lambda: False)
        monkeypatch.setattr(cloud_key.getpass, "getpass", lambda prompt: pytest.fail("must not ask for the key"))
        assert cloud_key.main(["set"]) == 2
        assert not any((tmp_path / "LightHouse").rglob("*.bin"))


def test_switching_takes_effect_without_a_restart(api, tmp_path, monkeypatch):
    client = TestClient(api.app)
    admin = login_as(api, client, "boss", "admin")
    (tmp_path / "genai-key.bin").write_bytes(b"encrypted")
    monkeypatch.setattr(cloud_key, "load", lambda path=None: KEY)
    local = LocalModel()
    monkeypatch.setattr(api, "_local_chat_model", local)
    assert isinstance(api.chat_model(), PurdueChatModel)
    # "On this computer only": nothing goes out, and the loaded local model is reused.
    assert client.put("/api/chat/model", headers=admin, json={"model": "local"}).status_code == 200
    assert api.chat_model() is local
    assert client.get("/api/chat/provider", headers=admin).json() == {"provider": "local"}
    assert client.put("/api/chat/model", headers=admin, json={"model": "llama3.3:70b"}).status_code == 200
    switched = api.chat_model()
    assert isinstance(switched, PurdueChatModel) and switched.model == "llama3.3:70b" and switched.local is local
