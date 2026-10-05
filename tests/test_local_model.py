"""The llama.cpp backend, with the runtime mocked: no GGUF is loaded here.

A real-model check is at the bottom and runs only when LIGHTHOUSE_TEST_GGUF points
at a compatible file on a machine with llama-cpp-python installed.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from triage import local_model
from triage.db import Database
from triage.llm import TRIAGE_JSON_SCHEMA, FixtureTriageModel, OllamaTriageModel, model_backend, model_name
from triage.local_model import (LlamaCppSettings, LlamaCppTriageModel, ModelUnavailable, SMOKE_TEST_ALERT,
                                load_llama, parse_reply, validate_model_file)
from triage.schema import Severity
from triage.service import TriageService

VALID = {"severity": "high", "explanation": "Someone repeatedly failed to sign in as administrator.",
         "recommended_action": "Check who owns 192.0.2.10.", "reasoning": "Event 4625 from one address."}


def gguf(path: Path, version: int = 3) -> Path:
    path.write_bytes(b"GGUF" + version.to_bytes(4, "little") + b"\0" * 32)
    return path


class FakeLlama:
    """Stands in for llama_cpp.Llama.create_chat_completion."""
    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def create_chat_completion(self, **kwargs):
        self.calls.append(kwargs)
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return {"choices": [{"message": {"content": reply}}]}


def model_with(llama, tmp_path, loads=None):
    loads = [] if loads is None else loads
    def loader(settings):
        loads.append(settings)
        return llama
    return LlamaCppTriageModel(LlamaCppSettings(model_path=gguf(tmp_path / "model.gguf")), loader=loader), loads


def is_unavailable(result):
    return result.severity == Severity.UNKNOWN and "review" in result.recommended_action


# --- configuration -----------------------------------------------------------

def test_settings_from_environment(monkeypatch, tmp_path):
    for name in ("LIGHTHOUSE_MODEL_PATH", "LIGHTHOUSE_MODEL_CONTEXT_SIZE", "LIGHTHOUSE_MODEL_GPU_LAYERS"):
        monkeypatch.delenv(name, raising=False)
    assert LlamaCppSettings.from_env() == LlamaCppSettings(model_path=None, context_size=4096, gpu_layers=0)
    monkeypatch.setenv("LIGHTHOUSE_MODEL_PATH", str(tmp_path / "phi.gguf"))
    monkeypatch.setenv("LIGHTHOUSE_MODEL_CONTEXT_SIZE", "2048")
    monkeypatch.setenv("LIGHTHOUSE_MODEL_GPU_LAYERS", "-1")
    settings = LlamaCppSettings.from_env()
    assert (settings.model_path, settings.context_size, settings.gpu_layers) == (tmp_path / "phi.gguf", 2048, -1)
    for value in ("big", "128"):
        monkeypatch.setenv("LIGHTHOUSE_MODEL_CONTEXT_SIZE", value)
        with pytest.raises(ValueError, match="LIGHTHOUSE_MODEL_CONTEXT_SIZE"):
            LlamaCppSettings.from_env()


def test_backend_selection(monkeypatch, tmp_path):
    import triage.main as main
    monkeypatch.delenv("LIGHTHOUSE_MODEL_BACKEND", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LIGHTHOUSE_MODEL_PATH", str(tmp_path / "phi.gguf"))
    assert model_backend() == "llama_cpp" and model_name() == "phi.gguf"
    assert isinstance(main.build_model(mock=False), LlamaCppTriageModel)
    assert isinstance(main.build_model(mock=True), FixtureTriageModel)
    # The Linux builds install and keep using Ollama.
    monkeypatch.setattr(sys, "platform", "linux")
    assert isinstance(main.build_model(mock=False), OllamaTriageModel)
    monkeypatch.setenv("LIGHTHOUSE_MODEL_BACKEND", "LLAMA_CPP")
    assert isinstance(main.build_model(mock=False), LlamaCppTriageModel)
    monkeypatch.setenv("LIGHTHOUSE_MODEL_BACKEND", "cloud")
    with pytest.raises(ValueError, match="LIGHTHOUSE_MODEL_BACKEND"):
        main.build_model(mock=False)


def test_building_the_model_never_loads_it(monkeypatch, tmp_path):
    monkeypatch.setattr(local_model, "load_llama", lambda settings: pytest.fail("loaded at construction"))
    LlamaCppTriageModel(LlamaCppSettings(model_path=tmp_path / "absent.gguf"))


# --- model file handling -----------------------------------------------------

def test_model_file_validation(tmp_path):
    assert validate_model_file(gguf(tmp_path / "ok.gguf")) == tmp_path / "ok.gguf"
    with pytest.raises(ModelUnavailable, match="not set"):
        validate_model_file(None)
    with pytest.raises(ModelUnavailable, match="not found"):
        validate_model_file(tmp_path / "missing.gguf")
    with pytest.raises(ModelUnavailable, match="cannot read"):
        validate_model_file(tmp_path)
    (tmp_path / "html.gguf").write_text("<html>captive portal</html>")
    with pytest.raises(ModelUnavailable, match="not a GGUF"):
        validate_model_file(tmp_path / "html.gguf")
    (tmp_path / "empty.gguf").write_bytes(b"")
    with pytest.raises(ModelUnavailable, match="not a GGUF"):
        validate_model_file(tmp_path / "empty.gguf")
    with pytest.raises(ModelUnavailable, match="unsupported GGUF version 1"):
        validate_model_file(gguf(tmp_path / "old.gguf", version=1))


def test_unsupported_cpu_is_refused_before_importing_llama_cpp(monkeypatch, tmp_path):
    monkeypatch.setattr(local_model, "cpu_supported", lambda: False)
    monkeypatch.setitem(sys.modules, "llama_cpp", None)  # any import attempt would raise
    with pytest.raises(ModelUnavailable, match="AVX2"):
        load_llama(LlamaCppSettings(model_path=gguf(tmp_path / "m.gguf")))


def test_missing_native_runtime_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(local_model, "cpu_supported", lambda: True)
    monkeypatch.setitem(sys.modules, "llama_cpp", None)
    with pytest.raises(ModelUnavailable, match="runtime could not be loaded"):
        load_llama(LlamaCppSettings(model_path=gguf(tmp_path / "m.gguf")))


# --- inference ---------------------------------------------------------------

def test_valid_reply_is_validated_and_first_attempt_is_unconstrained(tmp_path):
    llama = FakeLlama(json.dumps(VALID))
    model, _ = model_with(llama, tmp_path)
    result = asyncio.run(model.triage(SMOKE_TEST_ALERT))
    assert result.severity == Severity.HIGH and result.reasoning == VALID["reasoning"]
    assert not result.retried and not result.unavailable
    call = llama.calls[0]
    assert "response_format" not in call and call["max_tokens"] == 512
    assert call["messages"][0]["role"] == "system"
    assert "<untrusted_evidence>" in call["messages"][1]["content"]


def test_fenced_reply_is_accepted():
    assert parse_reply("```json\n" + json.dumps(VALID) + "\n```").severity == Severity.HIGH
    with pytest.raises(ValueError):
        parse_reply("I think this is serious.")


def test_malformed_reply_retries_with_grammar_then_succeeds(tmp_path):
    llama = FakeLlama('{"severity": "high", "explanation": "cut off', json.dumps(VALID))
    model, _ = model_with(llama, tmp_path)
    result = asyncio.run(model.triage(SMOKE_TEST_ALERT))
    assert result.severity == Severity.HIGH
    assert result.retried, "the confidence cap needs to know a retry was needed"
    assert [("response_format" in call) for call in llama.calls] == [False, True]
    assert llama.calls[1]["response_format"] == {"type": "json_object", "schema": TRIAGE_JSON_SCHEMA}


@pytest.mark.parametrize("reply", [
    "not json at all",
    json.dumps({**VALID, "severity": "urgent"}),          # outside the enum
    json.dumps({**VALID, "explanation": ""}),              # violates min_length
    json.dumps({**VALID, "recommended_action": "x" * 601}),
    json.dumps({"severity": "low"}),                       # required fields missing
])
def test_invalid_output_never_reaches_the_result(tmp_path, reply):
    llama = FakeLlama(reply)
    model, _ = model_with(llama, tmp_path)
    result = asyncio.run(model.triage(SMOKE_TEST_ALERT))
    assert is_unavailable(result) and result.reasoning.startswith("Model validation failed")
    assert len(llama.calls) == 2


def test_inference_exception_degrades_instead_of_raising(tmp_path):
    llama = FakeLlama(RuntimeError("llama_decode returned -1"))
    model, _ = model_with(llama, tmp_path)
    result = asyncio.run(model.triage(SMOKE_TEST_ALERT))
    assert is_unavailable(result) and "llama_decode" in result.reasoning
    assert result.unavailable


def test_model_is_loaded_once_and_calls_are_serialized(tmp_path):
    active, peak = [0], [0]
    class Tracking(FakeLlama):
        def create_chat_completion(self, **kwargs):
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            try:
                return super().create_chat_completion(**kwargs)
            finally:
                active[0] -= 1
    loads = []
    model, _ = model_with(Tracking(json.dumps(VALID)), tmp_path, loads)
    async def many():
        return await asyncio.gather(*(model.triage(SMOKE_TEST_ALERT) for _ in range(6)))
    results = asyncio.run(many())
    assert len(loads) == 1 and peak[0] == 1
    assert all(result.severity == Severity.HIGH for result in results)


def test_missing_model_degrades_and_is_retried_later(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(local_model.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(local_model, "cpu_supported", lambda: True)
    loads, provisioned = [], []
    def loader(settings):
        loads.append(settings)
        # Real file validation until the model is "installed", then a fake runtime.
        return FakeLlama(json.dumps(VALID)) if provisioned else load_llama(settings)
    path = tmp_path / "model.gguf"
    model = LlamaCppTriageModel(LlamaCppSettings(model_path=path), loader=loader)
    first = asyncio.run(model.triage(SMOKE_TEST_ALERT))
    assert is_unavailable(first) and "model file not found" in first.reasoning
    asyncio.run(model.triage(SMOKE_TEST_ALERT))
    assert len(loads) == 1, "a failed load is not retried for every alert"
    # Once the model is provisioned, the next attempt after the pause succeeds.
    provisioned.append(True)
    clock[0] += LlamaCppTriageModel.RELOAD_AFTER_SECONDS
    assert asyncio.run(model.triage(SMOKE_TEST_ALERT)).severity == Severity.HIGH
    assert len(loads) == 2


def test_load_failure_such_as_low_memory_degrades(tmp_path):
    def loader(settings):
        raise ValueError("Failed to load model from file")
    model = LlamaCppTriageModel(LlamaCppSettings(model_path=gguf(tmp_path / "m.gguf")), loader=loader)
    result = asyncio.run(model.triage(SMOKE_TEST_ALERT))
    assert is_unavailable(result) and "Failed to load model" in result.reasoning


def test_degraded_triage_still_stores_alert_with_sensor_floor(tmp_path, monkeypatch):
    monkeypatch.setattr(local_model, "cpu_supported", lambda: True)
    db = Database(str(tmp_path / "degraded.db")); db.initialize()
    model = LlamaCppTriageModel(LlamaCppSettings(model_path=tmp_path / "absent.gguf"))
    alert_id, duplicate = asyncio.run(TriageService(db, model).process(SMOKE_TEST_ALERT))
    stored = db.get_alert(alert_id)
    assert not duplicate and stored.triage.severity == Severity.MEDIUM  # the sensor floor
    assert "model file not found" in stored.triage.reasoning


# --- installer CLI -----------------------------------------------------------

def test_cli_cpu_check_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr(local_model, "cpu_supported", lambda: True)
    assert local_model.main(["check-cpu"]) == 0
    monkeypatch.setattr(local_model, "cpu_supported", lambda: False)
    assert local_model.main(["check-cpu"]) == local_model.EXIT_UNSUPPORTED_CPU


def test_cli_smoke_test(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(local_model, "load_llama", lambda settings: FakeLlama("oops", json.dumps(VALID)))
    assert local_model.main(["smoke-test", "--model-path", str(tmp_path / "m.gguf")]) == 0
    assert json.loads(capsys.readouterr().out)["severity"] == "high"
    monkeypatch.setattr(local_model, "load_llama", lambda settings: FakeLlama("oops"))
    assert local_model.main(["smoke-test", "--model-path", str(tmp_path / "m.gguf")]) == 1
    assert "self-test failed" in capsys.readouterr().err


# --- optional: a real GGUF model --------------------------------------------

@pytest.mark.skipif(not os.getenv("LIGHTHOUSE_TEST_GGUF"), reason="set LIGHTHOUSE_TEST_GGUF to a GGUF model to run")
def test_real_gguf_model_produces_validated_triage():
    pytest.importorskip("llama_cpp")
    settings = LlamaCppSettings(model_path=Path(os.environ["LIGHTHOUSE_TEST_GGUF"]))
    result = local_model.smoke_test(settings)
    assert result["ok"] and result["severity"] in {"low", "medium", "high", "critical"}
