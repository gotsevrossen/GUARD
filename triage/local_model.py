"""In-process local inference through llama.cpp (llama-cpp-python) and a GGUF model.

The Windows build's default model runtime. Nothing outside this module and
build_model() knows llama.cpp exists: ingestion, the API and the database only
see the TriageModel interface.

Lifecycle: the model is loaded lazily, on the first alert, in a worker thread, and
then reused for every later alert. On Windows it lives in the ingestion service
process, so API startup never waits for it. If loading fails (missing, corrupt or
incompatible file, too little memory, unsupported CPU), alerts are still stored,
with a result asking for a human review, and loading is retried after a pause so a
repaired model is picked up without a restart.

Also a small CLI used by the Windows installer:

    python -m triage.local_model check-cpu
    python -m triage.local_model smoke-test --model-path <file.gguf>
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, replace
import json
import logging
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable

from .llm import SYSTEM_PROMPT, TRIAGE_JSON_SCHEMA, TriageModel, build_prompt, unavailable_result
from .schema import NormalizedAlert, Severity, Source, TriageResult

logger = logging.getLogger(__name__)

GGUF_MAGIC = b"GGUF"
SUPPORTED_GGUF_VERSIONS = (2, 3)
# IsProcessorFeaturePresent feature id.
PF_AVX2_INSTRUCTIONS_AVAILABLE = 40
EXIT_UNSUPPORTED_CPU = 3


class ModelUnavailable(RuntimeError):
    """The model cannot be loaded on this machine as configured."""


def _int_env(name: str, default: int, minimum: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        number = int(value)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {value!r}") from None
    if number < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {number}")
    return number


@dataclass(frozen=True)
class LlamaCppSettings:
    model_path: Path | None
    # Prompt plus the JSON reply need well under 2,000 tokens; 4096 leaves room.
    context_size: int = 4096
    # 0 = CPU only. Takes effect only with a GPU-enabled llama.cpp build.
    gpu_layers: int = 0
    # Bounds inference time per alert; a complete reply is ~200 tokens.
    max_tokens: int = 512

    @classmethod
    def from_env(cls) -> "LlamaCppSettings":
        path = os.getenv("LIGHTHOUSE_MODEL_PATH", "").strip()
        return cls(model_path=Path(path) if path else None,
                   context_size=_int_env("LIGHTHOUSE_MODEL_CONTEXT_SIZE", 4096, minimum=512),
                   gpu_layers=_int_env("LIGHTHOUSE_MODEL_GPU_LAYERS", 0, minimum=-1))


def cpu_supported() -> bool:
    """The bundled Windows wheel is compiled for AVX2/FMA/F16C. On a CPU without
    them the native library faults and kills the whole process instead of raising,
    so this is checked before llama_cpp is ever imported. Elsewhere llama.cpp is
    built from source for the local CPU."""
    if sys.platform != "win32":
        return True
    import ctypes
    return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE))


def validate_model_file(path: Path | None) -> Path:
    """Cheap checks before handing a multi-gigabyte file to llama.cpp."""
    if path is None:
        raise ModelUnavailable("LIGHTHOUSE_MODEL_PATH is not set")
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
    except FileNotFoundError:
        raise ModelUnavailable(f"model file not found: {path}") from None
    except OSError as error:
        raise ModelUnavailable(f"cannot read model file {path}: {error.strerror or error}") from None
    if len(header) < 8 or header[:4] != GGUF_MAGIC:
        raise ModelUnavailable(f"not a GGUF model file: {path}")
    version = int.from_bytes(header[4:8], "little")
    if version not in SUPPORTED_GGUF_VERSIONS:
        raise ModelUnavailable(f"unsupported GGUF version {version}: {path}")
    return path


def load_llama(settings: LlamaCppSettings):
    """Load the model once. Slow (seconds to a minute) and memory-heavy."""
    if not cpu_supported():
        raise ModelUnavailable("this CPU lacks AVX2, which the bundled llama.cpp runtime requires")
    path = validate_model_file(settings.model_path)
    try:
        from llama_cpp import Llama
    except (ImportError, OSError, RuntimeError) as error:
        # Package missing, or a native DLL or the VC++ runtime it needs is absent.
        raise ModelUnavailable(f"llama.cpp runtime could not be loaded: {error}") from error
    return Llama(model_path=str(path), n_ctx=settings.context_size,
                 n_gpu_layers=settings.gpu_layers, verbose=False)


def parse_reply(content: str) -> TriageResult:
    """The first JSON object in the reply, which models often wrap in a Markdown
    code fence. Validation, not this extraction, is the trust boundary."""
    start = content.find("{")
    if start < 0:
        raise ValueError("model reply contains no JSON object")
    value, _ = json.JSONDecoder().raw_decode(content, start)
    return TriageResult.model_validate(value)


def run_triage(llama: Any, alert: NormalizedAlert, settings: LlamaCppSettings,
               constrained: bool) -> TriageResult:
    """One generation, validated. Raises on any failure.

    constrained=True forces schema-shaped JSON with a grammar. It is exact but, in
    llama-cpp-python, applied to the whole vocabulary before top-k: about three
    times slower per alert with Phi-4-mini's 200k-token vocabulary. So it is the
    retry path, not the first attempt.
    """
    options: dict[str, Any] = {}
    if constrained:
        options["response_format"] = {"type": "json_object", "schema": TRIAGE_JSON_SCHEMA}
    response = llama.create_chat_completion(
        messages=[{"role": "system", "content": SYSTEM_PROMPT},
                  {"role": "user", "content": build_prompt(alert)}],
        temperature=0.1,
        max_tokens=settings.max_tokens,
        **options,
    )
    return parse_reply(response["choices"][0]["message"]["content"])


class LlamaCppTriageModel(TriageModel):
    # Fast unconstrained attempt, then an exact grammar-constrained retry.
    ATTEMPTS = (False, True)
    RELOAD_AFTER_SECONDS = 300.0

    def __init__(self, settings: LlamaCppSettings,
                 loader: Callable[[LlamaCppSettings], Any] = load_llama):
        self.settings = settings
        self._loader = loader
        self._llama: Any = None
        self._load_error: str | None = None
        self._load_failed_at = 0.0
        # One llama.cpp context serves every sensor and is not safe for concurrent
        # use. The asyncio lock queues alerts without tying up executor threads;
        # the thread lock still holds if a waiting task is cancelled mid-inference.
        self._lock = asyncio.Lock()
        self._thread_lock = threading.Lock()

    async def triage(self, alert: NormalizedAlert) -> TriageResult:
        async with self._lock:
            if not await self._ensure_loaded():
                return unavailable_result(f"Local AI model unavailable: {self._load_error}")
            last_error: Exception | None = None
            for attempt, constrained in enumerate(self.ATTEMPTS):
                try:
                    result = await asyncio.to_thread(self._infer_blocking, alert, constrained)
                    # A reply that only validated under the grammar is a weaker
                    # signal; the confidence cap reads this flag.
                    return result.with_runtime_flags(retried=attempt > 0)
                except Exception as error:
                    # Malformed or truncated JSON, schema violations and runtime
                    # errors alike: never raised, or one alert could stall a sensor.
                    last_error = error
                    logger.warning("Local AI triage attempt failed: %s", error)
            return unavailable_result(f"Model validation failed: {last_error}")

    async def _ensure_loaded(self) -> bool:
        if self._llama is not None:
            return True
        if self._load_error is not None and time.monotonic() - self._load_failed_at < self.RELOAD_AFTER_SECONDS:
            return False
        try:
            await asyncio.to_thread(self._load_blocking)
        except Exception as error:
            self._load_error = str(error) or type(error).__name__
            self._load_failed_at = time.monotonic()
            logger.error("Local AI model unavailable; alerts are kept for human review: %s", self._load_error)
            return False
        self._load_error = None
        logger.info("Local AI model loaded: %s", self.settings.model_path)
        return True

    def _load_blocking(self) -> None:
        with self._thread_lock:
            # Assigned here, not by the awaiting task, so a load that finishes
            # after its task was cancelled is kept rather than loaded twice.
            if self._llama is None:
                self._llama = self._loader(self.settings)

    def _infer_blocking(self, alert: NormalizedAlert, constrained: bool) -> TriageResult:
        with self._thread_lock:
            return run_triage(self._llama, alert, self.settings, constrained)


# A representative alert for the installer's end-to-end check.
SMOKE_TEST_ALERT = NormalizedAlert(
    source=Source.WAZUH, title="Microsoft-Windows-Security-Auditing: Failed logon",
    source_ip="192.0.2.10", device="workstation", rule_id="Microsoft-Windows-Security-Auditing:4625",
    sensor_severity=Severity.MEDIUM,
    raw={"data": {"win": {"event_id": 4625, "eventdata": {"TargetUserName": "administrator", "LogonType": "3"}}}})


def smoke_test(settings: LlamaCppSettings) -> dict[str, Any]:
    """Load the model and validate one triage, as the service would. Raises."""
    started = time.perf_counter()
    llama = load_llama(settings)
    loaded = time.perf_counter()
    last_error: Exception | None = None
    for attempt, constrained in enumerate(LlamaCppTriageModel.ATTEMPTS, start=1):
        try:
            result = run_triage(llama, SMOKE_TEST_ALERT, settings, constrained)
            break
        except Exception as error:
            last_error = error
    else:
        raise ModelUnavailable(f"model output failed validation: {last_error}")
    return {"ok": True, "model": str(settings.model_path), "severity": str(result.severity), "attempt": attempt,
            "load_seconds": round(loaded - started, 1),
            "inference_seconds": round(time.perf_counter() - loaded, 1)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.local_model")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-cpu", help=f"exit 0 if this CPU can run the bundled runtime, {EXIT_UNSUPPORTED_CPU} if not")
    smoke = sub.add_parser("smoke-test", help="load the GGUF model and validate one triage")
    smoke.add_argument("--model-path", type=Path, help="defaults to LIGHTHOUSE_MODEL_PATH")
    args = parser.parse_args(argv)
    if args.command == "check-cpu":
        if cpu_supported():
            print("CPU supports the bundled llama.cpp runtime (AVX2).")
            return 0
        print("This CPU lacks AVX2; local AI triage is unavailable on this machine.")
        return EXIT_UNSUPPORTED_CPU
    settings = LlamaCppSettings.from_env()
    if args.model_path:
        settings = replace(settings, model_path=args.model_path)
    try:
        print(json.dumps(smoke_test(settings)))
    except Exception as error:
        print(f"Local AI self-test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
