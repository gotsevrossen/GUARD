"""In-process local inference through llama.cpp (llama-cpp-python) and a GGUF model.

The Windows build's default model runtime. Nothing outside this module and
build_model() knows llama.cpp exists: ingestion, the API and the database only
see the TriageModel interface.

Lifecycle: the model is loaded lazily, on the first alert, in a worker thread, and
then reused for every later alert. On Windows it lives in the ingestion service
process, so API startup never waits for it. The API process loads its own copy
only on the first "Ask LightHouse" chat request (see triage.api); llama.cpp
memory-maps the GGUF, so both processes share the weights in the OS page cache.
If loading fails (missing, corrupt or
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
from typing import Any, AsyncIterator, Callable

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


class _StreamFailed:
    """Carries a worker-thread exception across to the streaming coroutine."""
    def __init__(self, error: Exception):
        self.error = error


# Sentinel the worker sends when generation has ended, normally or not.
_STREAM_END = object()

# A saved chat state is roughly 130 KB per token with Phi-4-mini; 512 MB keeps the
# last couple of conversations without crowding an 8 GB machine.
CHAT_PROMPT_CACHE_BYTES = 512 * 1024 * 1024


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
    # CPU threads for llama.cpp; None picks them from the processor (plan_threads).
    threads: int | None = None

    @classmethod
    def from_env(cls) -> "LlamaCppSettings":
        path = os.getenv("LIGHTHOUSE_MODEL_PATH", "").strip()
        threads = _int_env("LIGHTHOUSE_MODEL_THREADS", 0, minimum=0)
        return cls(model_path=Path(path) if path else None,
                   context_size=_int_env("LIGHTHOUSE_MODEL_CONTEXT_SIZE", 4096, minimum=512),
                   gpu_layers=_int_env("LIGHTHOUSE_MODEL_GPU_LAYERS", 0, minimum=-1),
                   threads=threads or None)


def choose_inference_cores(cpus: list[tuple[int, int, int, int]]) -> tuple[list[int], int]:
    """Which logical processors llama.cpp should run on, and how many threads.

    `cpus` is (cpu set id, physical core, last-level cache, efficiency class) per
    logical processor. llama.cpp splits each step evenly across its threads and
    waits for the slowest, so a thread on a very slow core holds back all the
    others. Hybrid laptop chips (Intel Core Ultra) add a tiny island of low-power
    cores on their own cache; those are left out. Everything else is used, one
    thread per physical core (hyperthread siblings add little to this workload).
    """
    if not cpus:
        return [], 0
    classes = {efficiency for *_, efficiency in cpus}
    skip: set[int] = set()
    if len(classes) > 1:
        lowest = min(classes)
        islands: dict[int, tuple[set[int], set[int]]] = {}
        for _, core, cache, efficiency in cpus:
            effs, cores = islands.setdefault(cache, (set(), set()))
            effs.add(efficiency)
            cores.add(core)
        if len(islands) > 1:
            skip = {cache for cache, (effs, cores) in islands.items() if effs == {lowest} and len(cores) <= 2}
    kept = [cpu for cpu in cpus if cpu[2] not in skip] or cpus
    return [cpu[0] for cpu in kept], len({cpu[1] for cpu in kept})


def _windows_cpu_sets() -> list[tuple[int, int, int, int]] | None:
    """(id, core, cache, efficiency class) per logical processor, or None."""
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        length = wintypes.ULONG(0)
        kernel32.GetSystemCpuSetInformation(None, 0, ctypes.byref(length), None, 0)
        buffer = ctypes.create_string_buffer(length.value)
        if not kernel32.GetSystemCpuSetInformation(buffer, length, ctypes.byref(length), None, 0):
            return None
        raw, offset, cpus = buffer.raw, 0, []
        while offset < length.value:
            size = int.from_bytes(raw[offset:offset + 4], "little")
            # SYSTEM_CPU_SET_INFORMATION: Id @8, CoreIndex @15,
            # LastLevelCacheIndex @16, EfficiencyClass @18.
            cpus.append((int.from_bytes(raw[offset + 8:offset + 12], "little"),
                         raw[offset + 15], raw[offset + 16], raw[offset + 18]))
            offset += size or len(raw)
        return cpus
    except (OSError, AttributeError, ValueError):
        return None


def plan_threads(settings: LlamaCppSettings) -> int | None:
    """Thread count for llama.cpp; on Windows also steers this process off the
    slowest cores. None leaves llama.cpp's own default. Never raises."""
    if settings.threads:
        return settings.threads
    if sys.platform != "win32":
        return None
    cpus = _windows_cpu_sets()
    if not cpus:
        return None
    ids, physical = choose_inference_cores(cpus)
    if 0 < len(ids) < len(cpus):
        try:
            import ctypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            array = (ctypes.c_ulong * len(ids))(*ids)
            kernel32.SetProcessDefaultCpuSets(kernel32.GetCurrentProcess(), array, len(ids))
        except (OSError, AttributeError):
            pass  # a preference only; the thread count still applies
    logger.info("Local AI uses %d threads on %d of %d logical processors", physical, len(ids), len(cpus))
    return physical or None


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
    # use_mmap is llama.cpp's default, spelled out because the design relies on it:
    # the ingestion and API services each load the model, and a memory-mapped file
    # is shared through the OS page cache instead of held twice.
    options: dict[str, Any] = {"n_ctx": settings.context_size, "n_gpu_layers": settings.gpu_layers,
                               "use_mmap": True, "verbose": False}
    threads = plan_threads(settings)
    if threads:
        # Prompt reading (batch) gets the same cores as writing: on a hybrid laptop
        # llama.cpp's default of every logical processor includes the slowest ones.
        options.update(n_threads=threads, n_threads_batch=threads)
    try:
        # Flash attention computes the same attention with less memory traffic, so
        # answers are unchanged and long prompts are read faster.
        return Llama(model_path=str(path), flash_attn=True, **options)
    except (ValueError, RuntimeError, TypeError) as error:
        logger.warning("Flash attention unavailable in this llama.cpp build (%s); loading without it", error)
        return Llama(model_path=str(path), **options)


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
        self._prompt_cache_ready = False

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

    async def chat(self, system: str, messages: list[dict[str, str]], *,
                   max_tokens: int, temperature: float) -> str | None:
        """One free-text generation for "Ask LightHouse". Shares the lazy load, the
        reload pause and both locks with triage: it is the same llama.cpp context.
        No retry: there is no schema to fail, and a second attempt would double an
        already slow answer."""
        async with self._lock:
            if not await self._ensure_loaded():
                return None
            try:
                return await asyncio.to_thread(self._chat_blocking, system, messages, max_tokens, temperature)
            except Exception as error:
                # Includes a prompt too long for the context window; the caller
                # shows its fixed "unavailable" reply instead of an error.
                logger.warning("Local AI chat failed: %s", error)
                return None

    async def chat_stream(self, system: str, messages: list[dict[str, str]], *,
                          max_tokens: int, temperature: float) -> AsyncIterator[str]:
        """chat(), streamed: llama.cpp generates in a worker thread and hands each
        piece to the event loop as it is produced.

        Closing this generator (the browser went away, or the caller hit its length
        cap) sets a stop flag the worker checks between pieces, so an abandoned
        question does not keep the one model context busy for hundreds of tokens.
        The asyncio lock is held until the worker has let go of the context.
        """
        async with self._lock:
            if not await self._ensure_loaded():
                return
            loop = asyncio.get_running_loop()
            queue: asyncio.Queue[object] = asyncio.Queue()
            stop = threading.Event()

            def hand_over(item: object) -> None:
                try:
                    loop.call_soon_threadsafe(queue.put_nowait, item)
                except RuntimeError:
                    pass  # the loop is shutting down; nobody is waiting

            def produce() -> None:
                try:
                    with self._thread_lock:
                        self._enable_prompt_cache()
                        stream = self._llama.create_chat_completion(
                            messages=[{"role": "system", "content": system}, *messages],
                            temperature=temperature,
                            max_tokens=min(max_tokens, self.settings.max_tokens),
                            stream=True,
                        )
                        for chunk in stream:
                            if stop.is_set():
                                break
                            piece = chunk["choices"][0].get("delta", {}).get("content")
                            if isinstance(piece, str) and piece:
                                hand_over(piece)
                except Exception as error:
                    hand_over(_StreamFailed(error))
                finally:
                    hand_over(_STREAM_END)

            worker = asyncio.ensure_future(asyncio.to_thread(produce))
            try:
                while True:
                    item = await queue.get()
                    if item is _STREAM_END:
                        break
                    if isinstance(item, _StreamFailed):
                        # Includes a prompt too long for the context window.
                        logger.warning("Local AI chat failed: %s", item.error)
                        raise item.error
                    yield item  # type: ignore[misc]
            finally:
                stop.set()
                # Shielded: if this task is being cancelled, the worker still runs
                # to its next stop check, and the thread lock keeps the context safe.
                await asyncio.shield(worker)

    async def preload(self) -> bool:
        """Load the model now rather than on the first alert or question. Waits its
        turn like any other use of the model. Never raises."""
        async with self._lock:
            return await self._ensure_loaded()

    async def warm(self, system: str, messages: list[dict[str, str]]) -> bool:
        """Load the model if needed and read the prompt into the context, keeping its
        state (prefix reuse plus the RAM cache), so the question that follows reads
        only itself. Skipped, not queued, while the model is busy: a warm-up must
        never delay a real answer."""
        if self._lock.locked():
            return False
        async with self._lock:
            if not await self._ensure_loaded():
                return False
            try:
                await asyncio.to_thread(self._warm_blocking, system, messages)
                return True
            except Exception as error:
                logger.warning("Local AI warm-up failed: %s", error)
                return False

    def _warm_blocking(self, system: str, messages: list[dict[str, str]]) -> None:
        with self._thread_lock:
            self._enable_prompt_cache()
            # One token is the least llama.cpp generates; the point is the reading.
            self._llama.create_chat_completion(messages=[{"role": "system", "content": system}, *messages],
                                               temperature=0.0, max_tokens=1)

    def _enable_prompt_cache(self) -> None:
        """Keep recent prompt states so a chat need not re-read what it already read.

        llama.cpp reuses its context for a prompt that starts like the previous one,
        so a follow-up question costs only its new words. But the chat title asked
        in between replaces that context; the RAM cache keeps the chat's state and
        restores it. Called with the thread lock held; chat only (the API process).
        """
        if self._prompt_cache_ready:
            return
        self._prompt_cache_ready = True
        try:
            from llama_cpp import LlamaRAMCache
            self._llama.set_cache(LlamaRAMCache(capacity_bytes=CHAT_PROMPT_CACHE_BYTES))
        except Exception as error:
            # Slower, not broken: every question is read in full instead.
            logger.warning("Local AI prompt cache unavailable: %s", error)

    def _chat_blocking(self, system: str, messages: list[dict[str, str]], max_tokens: int,
                       temperature: float) -> str | None:
        with self._thread_lock:
            self._enable_prompt_cache()
            response = self._llama.create_chat_completion(
                messages=[{"role": "system", "content": system}, *messages],
                temperature=temperature,
                max_tokens=min(max_tokens, self.settings.max_tokens),
            )
        content = response["choices"][0]["message"]["content"]
        return content if isinstance(content, str) else None


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
            "threads": plan_threads(settings) or "llama.cpp default",
            "load_seconds": round(loaded - started, 1),
            "inference_seconds": round(time.perf_counter() - loaded, 1)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.local_model")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-cpu", help=f"exit 0 if this CPU can run the bundled runtime, {EXIT_UNSUPPORTED_CPU} if not")
    smoke = sub.add_parser("smoke-test", help="load the GGUF model and validate one triage")
    smoke.add_argument("--model-path", type=Path, help="defaults to LIGHTHOUSE_MODEL_PATH")
    smoke.add_argument("--threads", type=int, help="CPU threads to try (default: chosen from this processor)")
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
    if args.threads:
        settings = replace(settings, threads=max(1, args.threads))
    try:
        print(json.dumps(smoke_test(settings)))
    except Exception as error:
        print(f"Local AI self-test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
