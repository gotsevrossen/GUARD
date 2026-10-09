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

Speed, never at the cost of the answer: prompt-lookup speculative decoding (every
drafted token is checked against the model's own choice), chat taking priority
over background triage across the two processes (a triage that gives way is
re-run in full), and the chat instructions' context state saved to disk so the
first question after a restart does not re-read them.

Also a small CLI used by the Windows installer, plus a benchmark the owner runs:

    python -m triage.local_model check-cpu
    python -m triage.local_model smoke-test --model-path <file.gguf>
    python -m triage.local_model bench --model-path <file.gguf> [--runs N] [--out DIR]
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager, nullcontext
import ctypes
from dataclasses import dataclass, replace
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any, AsyncIterator, Callable, ContextManager, Iterator, Sequence

from .llm import (SYSTEM_PROMPT, TITLE_SYSTEM_PROMPT, TRIAGE_JSON_SCHEMA, TriageModel, build_prompt,
                  unavailable_result)
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

# Triage sampling temperature in normal operation. The benchmark alone passes 0.
TRIAGE_TEMPERATURE = 0.1

# Prompt-lookup drafting. Up to this many tokens are proposed from text already in
# the prompt (IP addresses, process names, JSON keys the reply repeats) and checked
# by the model in one batch. Bounded because on a CPU a batch is not free: weights
# are read once per batch, but the arithmetic grows with every drafted token, so a
# rejected draft costs more the longer it is, while 10 tokens already cover an
# address, a path or a key and its value. A 2-token match (the library default)
# picks where to copy from. `bench` measures the net effect on the owner's CPU.
SPECULATIVE_DRAFT_TOKENS = 10
SPECULATIVE_NGRAM_SIZE = 2


class GenerationInterrupted(Exception):
    """Background triage gave way to a chat; the alert is re-run from the start."""


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


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name, "").strip().lower()
    if not value:
        return default
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be 1 or 0, got {value!r}")


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
    # Prompt-lookup speculative decoding (LIGHTHOUSE_MODEL_SPECULATIVE=0 turns it off).
    speculative: bool = True
    # Where chat's system-prompt state is kept across restarts; None = not kept.
    state_dir: Path | None = None

    @classmethod
    def from_env(cls) -> "LlamaCppSettings":
        path = os.getenv("LIGHTHOUSE_MODEL_PATH", "").strip()
        threads = _int_env("LIGHTHOUSE_MODEL_THREADS", 0, minimum=0)
        state_dir = os.getenv("LIGHTHOUSE_MODEL_STATE_DIR", "").strip()
        return cls(model_path=Path(path) if path else None,
                   context_size=_int_env("LIGHTHOUSE_MODEL_CONTEXT_SIZE", 4096, minimum=512),
                   gpu_layers=_int_env("LIGHTHOUSE_MODEL_GPU_LAYERS", 0, minimum=-1),
                   threads=threads or None,
                   speculative=_bool_env("LIGHTHOUSE_MODEL_SPECULATIVE", True),
                   state_dir=Path(state_dir) if state_dir else None)


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


_LLAMA_CLASSES: dict[type, type] = {}


def lighthouse_llama_class(base: type) -> type:
    """llama_cpp.Llama plus the few hooks LightHouse needs. Built on first load,
    because llama_cpp itself is imported only then (see cpu_supported).

    Written against llama-cpp-python 0.3.35, which is pinned exactly; eval below is
    that version's Llama.eval with two changes, both of which leave every computed
    value as it was.
    """
    cached = _LLAMA_CLASSES.get(base)
    if cached is not None:
        return cached

    class LighthouseLlama(base):  # type: ignore[misc, valid-type]
        # Set by the triage worker for one generation; None means never interrupt.
        lighthouse_interrupt: Callable[[], bool] | None = None

        def eval(self, tokens: Sequence[int]) -> None:
            """Llama.eval, changed in two ways:

            1. A triage generation can be interrupted between batches (one per
               generated token, or per 512 prompt tokens), so a chat the owner is
               waiting on gets the CPU back. Nothing is half-written: the context
               holds exactly the batches that finished, as after any other stop.
            2. With a draft model, llama-cpp-python 0.3.35 asks llama.cpp for logits
               at every position of every batch and copies them into a buffer that
               only holds 512 rows, which fails on a prompt longer than that, and
               would otherwise cost a vocabulary-sized output row (200k entries)
               per prompt token. Only a verification batch (the last token plus
               its draft) needs every position, so only it asks for them; a prompt
               needs only its last position, as without a draft. The copy fed
               logprobs alone, which LightHouse never requests; sampling reads the
               logits inside llama.cpp.
            """
            interrupt = self.lighthouse_interrupt
            every_position = (getattr(self, "draft_model", None) is not None
                              and len(tokens) <= SPECULATIVE_DRAFT_TOKENS + 1)
            self._ctx.kv_cache_seq_rm(-1, self.n_tokens, -1)
            for start in range(0, len(tokens), self.n_batch):
                if interrupt is not None and interrupt():
                    raise GenerationInterrupted()
                batch = tokens[start:min(len(tokens), start + self.n_batch)]
                n_past = self.n_tokens
                self._batch.set_batch(batch=batch, n_past=n_past, logits_all=every_position)
                self._ctx.decode(self._batch)
                self.input_ids[n_past:n_past + len(batch)] = batch
                self.n_tokens += len(batch)
                self._requires_eval = False

        # --- saved system-prompt state (SystemPromptState) -----------------------

        def lighthouse_tokens(self) -> Any:
            """The token ids whose state the context holds."""
            return self.input_ids[:self.n_tokens].copy()

        def lighthouse_truncate(self, n_tokens: int) -> None:
            """Keep only the first n_tokens of the context, as llama-cpp-python does
            itself when a new prompt shares only part of the previous one."""
            if not 0 < n_tokens <= self.n_tokens:
                raise ValueError(f"cannot keep {n_tokens} of {self.n_tokens} tokens")
            if not self._ctx.kv_cache_seq_rm(-1, n_tokens, -1):
                raise RuntimeError("llama.cpp cannot shorten this model's context")
            self.n_tokens = n_tokens
            self._requires_eval = True

        def lighthouse_capture(self) -> tuple[Any, bytes]:
            """(token ids, llama.cpp state bytes) for the context as it is now.

            Not Llama.save_state: that also copies a logits buffer of up to 410 MB
            that nothing here needs."""
            from llama_cpp import llama_cpp as native
            size = int(native.llama_state_get_size(self.ctx))
            buffer = (ctypes.c_uint8 * size)()
            written = int(native.llama_state_get_data(self.ctx, buffer, size))
            if not 0 < written <= size:
                raise RuntimeError("llama.cpp could not save its state")
            return self.lighthouse_tokens(), ctypes.string_at(buffer, written)

        def lighthouse_restore(self, ids: Any, state: bytes | bytearray) -> None:
            """Put back a captured state. On any failure the context is left empty,
            exactly as after loading, and the next prompt is read in full."""
            from llama_cpp import llama_cpp as native
            count = len(ids)
            if not 0 < count <= self.n_ctx():
                raise ValueError(f"saved state has {count} tokens")
            buffer = (ctypes.c_uint8 * len(state)).from_buffer_copy(state)
            self.reset()
            self._ctx.kv_cache_clear()
            try:
                if int(native.llama_state_set_data(self.ctx, buffer, len(state))) != len(state):
                    raise RuntimeError("llama.cpp rejected the saved state")
                # The token list must describe exactly the cells restored: if they
                # disagreed, later prompts would trust attention that is not there.
                last = int(native.llama_memory_seq_pos_max(self._ctx.memory, 0))
                if last != count - 1:
                    raise RuntimeError(f"saved state covers {last + 1} positions, not {count}")
            except Exception:
                self._ctx.kv_cache_clear()
                self.reset()
                raise
            self.input_ids[:count] = ids
            self.n_tokens = count
            # Its logits are not those of the last token, so llama-cpp-python
            # re-reads at least one token before sampling, as after load_state.
            self._requires_eval = True

        def lighthouse_signature(self) -> dict[str, Any]:
            """Everything about this runtime that a saved state depends on."""
            import llama_cpp
            params = self.context_params
            return {"llama_cpp": getattr(llama_cpp, "__version__", "unknown"), "n_ctx": self.n_ctx(),
                    "n_batch": self.n_batch, "n_threads": self.n_threads,
                    "n_threads_batch": self.n_threads_batch, "flash_attn": int(params.flash_attn_type),
                    "type_k": int(params.type_k), "type_v": int(params.type_v)}

    LighthouseLlama.__name__ = LighthouseLlama.__qualname__ = "LighthouseLlama"
    _LLAMA_CLASSES[base] = LighthouseLlama
    return LighthouseLlama


def build_draft_model() -> Any | None:
    """llama-cpp-python's prompt-lookup drafter, or None (with a warning) if it
    cannot be built: drafting only ever saves time, so its absence must never stop
    the model from loading.

    Lossless: in Llama.generate (0.3.35) every token is still sampled from the main
    model's own logits at its position, with the request's sampler; a draft only
    lets several positions be computed in one batch. A drafted token is kept only
    when it equals that sample; at the first one that differs, the sample is used
    and the context is cut back to it. The draft never touches the sampler, so the
    grammar, repeat penalty and random state advance once per emitted token, as
    without it.
    """
    try:
        from llama_cpp.llama_speculative import LlamaPromptLookupDecoding
        return LlamaPromptLookupDecoding(max_ngram_size=SPECULATIVE_NGRAM_SIZE,
                                         num_pred_tokens=SPECULATIVE_DRAFT_TOKENS)
    except Exception as error:
        logger.warning("Speculative decoding unavailable (%s); the local AI runs without it", error)
        return None


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
    draft = build_draft_model() if settings.speculative else None
    if draft is not None:
        options["draft_model"] = draft
    runtime = lighthouse_llama_class(Llama)
    try:
        # Flash attention computes the same attention with less memory traffic, so
        # answers are unchanged and long prompts are read faster.
        return runtime(model_path=str(path), flash_attn=True, **options)
    except (ValueError, RuntimeError, TypeError) as error:
        logger.warning("Flash attention unavailable in this llama.cpp build (%s); loading without it", error)
        return runtime(model_path=str(path), **options)


def parse_reply(content: str) -> TriageResult:
    """The first JSON object in the reply, which models often wrap in a Markdown
    code fence. Validation, not this extraction, is the trust boundary."""
    start = content.find("{")
    if start < 0:
        raise ValueError("model reply contains no JSON object")
    value, _ = json.JSONDecoder().raw_decode(content, start)
    return TriageResult.model_validate(value)


# --- chat before triage, across the two service processes ----------------------

# Held by the API service while chat generates or warms; the ingestion service's
# triage waits for it and gives way to it. A named mutex, not an event: Windows
# releases a mutex whose owner died (WAIT_ABANDONED), so a crashed chat can never
# leave triage waiting for a signal nobody will clear.
#
# Global\ so both services (session 0) see one object. SeCreateGlobalPrivilege,
# which standard users lack, only guards Global\ file mappings: any user can
# create a Global\ mutex, so an ordinary user could create this one before the
# services start and hold it to stall triage. Hence (1) it is created with a DACL
# for SYSTEM and Administrators only, so once it exists no one else can open it,
# and (2) a mutex owned by anyone but SYSTEM or Administrators is ignored, and
# triage then simply never waits (the behaviour before this signal existed). Every
# wait is bounded as well: an administrator, or a bug, must still never stop
# alerts from being triaged.
CHAT_BUSY_MUTEX = "Global\\LightHouse-LocalAI-Chat"
# LocalSystem (both services) and the Administrators group (an elevated process).
TRUSTED_SIGNAL_OWNERS = frozenset({"S-1-5-18", "S-1-5-32-544"})
_MUTEX_ALL_ACCESS = 0x001F0001
# How long chat waits to take the mutex. Triage only holds it for microseconds to
# test it, so a longer wait means something else is holding it; chat then answers
# anyway.
CHAT_ACQUIRE_SECONDS = 2.0
_WAIT_OBJECT_0, _WAIT_ABANDONED = 0x00, 0x80


class ChatBusySignal:
    """The no-op signal: off Windows, without pywin32, or when the mutex cannot be
    created. Triage then never waits, which is the behaviour before this signal."""

    def hold(self) -> ContextManager[None]:
        """Chat side: mark chat busy for the duration of a with block."""
        return nullcontext()

    def is_busy(self) -> bool:
        """Triage side: whether a chat is generating right now. Never blocks."""
        return False


class WindowsChatBusySignal(ChatBusySignal):
    """CHAT_BUSY_MUTEX through pywin32. A mutex belongs to the thread that took it,
    so each acquire is released in the same call (is_busy) or the same with block
    (hold), on the thread that runs llama.cpp."""

    def __init__(self, name: str = CHAT_BUSY_MUTEX, win32event: Any = None,
                 owner_of: Callable[[Any], str] | None = None, security: Any = None):
        if win32event is None:
            import win32event
            security, owner_of = _admin_only_security(), _kernel_object_owner
        self._win32event = win32event
        self._handle = win32event.CreateMutex(security, False, name)
        owner = owner_of(self._handle) if owner_of is not None else "unknown"
        if owner not in TRUSTED_SIGNAL_OWNERS:
            close = getattr(self._handle, "Close", None)
            if callable(close):
                close()
            raise PermissionError(f"{name} belongs to {owner}, not to SYSTEM or Administrators")

    def _acquire(self, milliseconds: int) -> bool:
        # WAIT_ABANDONED: the previous owner exited without releasing. Ownership
        # passes to this thread, and the mutex guards no data, so it counts as free.
        return self._win32event.WaitForSingleObject(self._handle, milliseconds) in (_WAIT_OBJECT_0, _WAIT_ABANDONED)

    def _release(self) -> None:
        try:
            self._win32event.ReleaseMutex(self._handle)
        except Exception as error:
            logger.warning("Could not release the chat signal: %s", error)

    @contextmanager
    def hold(self) -> Iterator[None]:
        try:
            owned = self._acquire(int(CHAT_ACQUIRE_SECONDS * 1000))
        except Exception as error:
            logger.warning("Chat signal unavailable: %s", error)
            owned = False
        try:
            yield
        finally:
            if owned:
                self._release()

    def is_busy(self) -> bool:
        try:
            if self._acquire(0):
                self._release()
                return False
            return True
        except Exception:
            return False  # a broken signal must never hold triage back


def _admin_only_security() -> Any:
    """SECURITY_ATTRIBUTES granting the mutex to SYSTEM and Administrators only."""
    import win32security
    dacl = win32security.ACL()
    for sid in sorted(TRUSTED_SIGNAL_OWNERS):
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, _MUTEX_ALL_ACCESS,
                                 win32security.ConvertStringSidToSid(sid))
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
    attributes = win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def _kernel_object_owner(handle: Any) -> str:
    """The owner SID of a kernel object, as a string such as S-1-5-18."""
    import win32security
    info = win32security.GetSecurityInfo(handle, win32security.SE_KERNEL_OBJECT,
                                         win32security.OWNER_SECURITY_INFORMATION)
    return win32security.ConvertSidToStringSid(info.GetSecurityDescriptorOwner())


_chat_busy_signal: ChatBusySignal | None = None
_chat_busy_lock = threading.Lock()


def chat_busy_signal() -> ChatBusySignal:
    """This process's signal, created on first use. Never raises."""
    global _chat_busy_signal
    with _chat_busy_lock:
        if _chat_busy_signal is None:
            signal: ChatBusySignal = ChatBusySignal()
            if sys.platform == "win32":
                try:
                    signal = WindowsChatBusySignal()
                except Exception as error:
                    # Outside the services (a developer's shell), or a mutex some
                    # other account created first.
                    logger.warning("Chat/triage priority signal unavailable (%s); triage will not wait for chat",
                                   error)
            _chat_busy_signal = signal
        return _chat_busy_signal


@contextmanager
def interruptible(llama: Any, check: Callable[[], bool] | None) -> Iterator[None]:
    """Let `check` interrupt this generation (see LighthouseLlama.eval)."""
    llama.lighthouse_interrupt = check
    try:
        yield
    finally:
        llama.lighthouse_interrupt = None


# --- chat instructions' state, kept across restarts ------------------------------

STATE_FILE_MAGIC = b"LHSTATE\x01"
STATE_FORMAT_VERSION = 1
STATE_HEADER_MAX_BYTES = 4096
# Phi-4-mini needs ~130 KB per token, so a full 4096-token context is ~540 MB.
STATE_FILE_MAX_BYTES = 2 << 30
# The current instructions and the previous ones (an admin trying a note out).
STATE_FILES_KEPT = 2
STATE_FILE_SUFFIX = ".lhstate"


class StateFileRejected(ValueError):
    """A saved state file that is not exactly what this runtime would have saved."""


def state_key(model_path: Path, signature: dict[str, Any], system: str) -> str:
    """Names a saved state. Any change to the model file, the runtime or the exact
    system prompt (an admin editing the AI instructions) gives a new key."""
    stat = model_path.stat()
    material = {"format": STATE_FORMAT_VERSION, "model": str(model_path.resolve()), "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns, "runtime": signature, "system": system}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()


def write_state_file(path: Path, key: str, ids: Any, state: bytes) -> None:
    """MAGIC, header length (uint32 LE), JSON header, token ids (int32 LE), state.

    Deliberately not pickle: a tampered file must never be able to run code. The
    folder is Administrators/SYSTEM-only, as the rest of the data folder."""
    import numpy as np
    ids_bytes = np.asarray(ids, dtype="<i4").tobytes()
    digest = hashlib.sha256(ids_bytes)
    digest.update(state)
    header = json.dumps({"format": STATE_FORMAT_VERSION, "key": key, "n_tokens": len(ids_bytes) // 4,
                         "state_bytes": len(state), "sha256": digest.hexdigest()}).encode("utf-8")
    temporary = path.with_name(f"{path.stem}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as handle:
            for part in (STATE_FILE_MAGIC, len(header).to_bytes(4, "little"), header, ids_bytes, state):
                handle.write(part)
            handle.flush()
            os.fsync(handle.fileno())
        # Atomic: a reader sees the old file, the new one or none, never half of one.
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def read_state_file(path: Path, key: str, n_ctx: int, n_vocab: int) -> tuple[Any, bytearray]:
    """(token ids, state bytes) from a file written by write_state_file, or
    StateFileRejected. Every size is checked before anything is read into memory."""
    import numpy as np

    def reject(reason: str) -> StateFileRejected:
        return StateFileRejected(f"{path.name}: {reason}")

    size = path.stat().st_size
    if size > STATE_FILE_MAX_BYTES:
        raise reject("too large")
    with path.open("rb") as handle:
        if handle.read(len(STATE_FILE_MAGIC)) != STATE_FILE_MAGIC:
            raise reject("not a LightHouse state file")
        header_size = int.from_bytes(handle.read(4), "little")
        if not 0 < header_size <= STATE_HEADER_MAX_BYTES:
            raise reject("bad header size")
        try:
            header = json.loads(handle.read(header_size).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise reject("unreadable header") from None
        if not isinstance(header, dict) or header.get("format") != STATE_FORMAT_VERSION:
            raise reject("unknown format")
        if header.get("key") != key:
            raise reject("saved for another model, runtime or prompt")
        count, state_size, expected = header.get("n_tokens"), header.get("state_bytes"), header.get("sha256")
        if (type(count) is not int or type(state_size) is not int or not isinstance(expected, str)
                or not 0 < count <= n_ctx or not 0 < state_size <= STATE_FILE_MAX_BYTES):
            raise reject("bad sizes")
        if size != len(STATE_FILE_MAGIC) + 4 + header_size + 4 * count + state_size:
            raise reject("truncated or padded")
        ids_bytes = handle.read(4 * count)
        state = bytearray(state_size)
        if len(ids_bytes) != 4 * count or handle.readinto(state) != state_size:
            raise reject("truncated")
    digest = hashlib.sha256(ids_bytes)
    digest.update(state)
    if digest.hexdigest() != expected:
        raise reject("checksum mismatch")
    ids = np.frombuffer(ids_bytes, dtype="<i4")
    if int(ids.min()) < 0 or int(ids.max()) >= n_vocab:
        raise reject("token id out of range")
    return ids, state


def _shared_prefix(first: Any, second: Any) -> int:
    count = 0
    for a, b in zip(first, second):
        if int(a) != int(b):
            break
        count += 1
    return count


class SystemPromptState:
    """Saves the context state of the chat system prompt, and nothing after it (no
    alert, no question, no history), and puts it back after a restart.

    llama-cpp-python reuses the part of the context that matches the start of a new
    prompt, compared token by token, so with the instructions already in place the
    first question reads only the alert context and itself. The saved tokens are
    found by reading the instructions with two fixed probe questions and keeping
    what both share: the system turn as the model's own chat template renders it.
    A restored file is checked the same way: the probe must reproduce its tokens
    exactly, or the file is discarded and rebuilt.
    """

    # Fixed text, never user data. They differ from the first character, so the
    # tokens they share are the instructions and the chat template's markup.
    PROBES = ("Hello.", "Thanks!")

    def __init__(self, directory: Path, model_path: Path, role: str = "chat"):
        self.directory, self.model_path, self.role = directory, model_path, role
        self._done: str | None = None
        self._writer: threading.Thread | None = None

    def ensure(self, llama: Any, system: str) -> str:
        """Called with the model's thread lock held, before a chat generation.
        "restored", "saved", "ready" (already done for this prompt) or "failed".
        Never raises: without the file, chat just reads its instructions."""
        if system == self._done:
            return "ready"
        # Once per prompt per process, success or not: never retried per question.
        self._done = system
        try:
            return self._ensure(llama, system)
        except Exception as error:
            logger.warning("Saved chat instructions unavailable; questions read them in full: %s", error)
            return "failed"

    def flush(self, timeout: float | None = None) -> None:
        """Wait for a file being written in the background."""
        if self._writer is not None:
            self._writer.join(timeout)

    def _path(self, key: str) -> Path:
        return self.directory / f"{self.role}-{key}{STATE_FILE_SUFFIX}"

    def _ensure(self, llama: Any, system: str) -> str:
        key = state_key(self.model_path, llama.lighthouse_signature(), system)
        path = self._path(key)
        # The probes must not land in the chat RAM cache or move the sampler's seed
        # sequence: everything after this behaves as if they had not happened.
        cache, seed = getattr(llama, "cache", None), getattr(llama, "_seed", None)
        if cache is not None:
            llama.set_cache(None)
        try:
            if path.is_file():
                if self._restore(llama, path, key, system):
                    return "restored"
                path.unlink(missing_ok=True)
            first = self._probe(llama, system, self.PROBES[0])
            second = self._probe(llama, system, self.PROBES[1])
            shared = _shared_prefix(first, second)
            if shared < 1:
                return "failed"
            llama.lighthouse_truncate(shared)
            ids, state = llama.lighthouse_capture()
            # Written off the model thread: a ~100 MB write must not delay the answer.
            self._writer = threading.Thread(target=self._write, args=(path, key, ids, state),
                                            name="lighthouse-state-writer", daemon=True)
            self._writer.start()
            return "saved"
        finally:
            if cache is not None:
                llama.set_cache(cache)
            if seed is not None:
                llama.set_seed(seed)

    def _restore(self, llama: Any, path: Path, key: str, system: str) -> bool:
        try:
            ids, state = read_state_file(path, key, llama.n_ctx(), llama.n_vocab())
            llama.lighthouse_restore(ids, state)
            seen = self._probe(llama, system, self.PROBES[0])
        except Exception as error:
            logger.warning("Ignoring saved chat state %s: %s", path.name, error)
            return False
        if _shared_prefix(ids, seen) != len(ids):
            logger.warning("Saved chat state %s does not match this prompt's tokens; rebuilding it", path.name)
            return False
        try:
            os.utime(path)  # recently used, so pruning keeps it
        except OSError:
            pass
        logger.info("Chat instructions restored from %s (%d tokens)", path.name, len(ids))
        return True

    @staticmethod
    def _probe(llama: Any, system: str, text: str) -> Any:
        llama.create_chat_completion(messages=[{"role": "system", "content": system},
                                               {"role": "user", "content": text}],
                                     temperature=0.0, max_tokens=1)
        return llama.lighthouse_tokens()

    def _write(self, path: Path, key: str, ids: Any, state: bytes) -> None:
        try:
            # Only the last level: the folder belongs in the protected data folder.
            self.directory.mkdir(exist_ok=True)
            write_state_file(path, key, ids, state)
            self._prune(keep=path)
            logger.info("Chat instructions saved to %s (%d tokens)", path.name, len(ids))
        except Exception as error:
            logger.warning("Could not save the chat instructions' state: %s", error)

    def _prune(self, keep: Path) -> None:
        for leftover in self.directory.glob(f"{self.role}-*.tmp"):
            leftover.unlink(missing_ok=True)  # an interrupted write
        saved = [file for file in self.directory.glob(f"{self.role}-*{STATE_FILE_SUFFIX}") if file != keep]
        saved.sort(key=lambda file: file.stat().st_mtime, reverse=True)
        for stale in saved[STATE_FILES_KEPT - 1:]:
            stale.unlink(missing_ok=True)


# --- inference -------------------------------------------------------------------

def triage_request(alert: NormalizedAlert, settings: LlamaCppSettings, constrained: bool,
                   system: str = SYSTEM_PROMPT, temperature: float = TRIAGE_TEMPERATURE) -> dict[str, Any]:
    """create_chat_completion arguments for one triage attempt. Shared with the
    benchmark, so it measures exactly the request the service makes."""
    request: dict[str, Any] = {
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": build_prompt(alert)}],
        "temperature": temperature,
        "max_tokens": settings.max_tokens,
    }
    if constrained:
        request["response_format"] = {"type": "json_object", "schema": TRIAGE_JSON_SCHEMA}
    return request


def run_triage(llama: Any, alert: NormalizedAlert, settings: LlamaCppSettings,
               constrained: bool, system: str = SYSTEM_PROMPT) -> TriageResult:
    """One generation, validated. Raises on any failure.

    constrained=True forces schema-shaped JSON with a grammar. It is exact but, in
    llama-cpp-python, applied to the whole vocabulary before top-k: about three
    times slower per alert with Phi-4-mini's 200k-token vocabulary. So it is the
    retry path, not the first attempt.

    `system` is TriageModel.triage_system_prompt(): SYSTEM_PROMPT, plus the admin's
    business note when there is one. The alert itself stays in the user turn,
    fenced by build_prompt.
    """
    response = llama.create_chat_completion(**triage_request(alert, settings, constrained, system))
    return parse_reply(response["choices"][0]["message"]["content"])


class LlamaCppTriageModel(TriageModel):
    # Fast unconstrained attempt, then an exact grammar-constrained retry.
    ATTEMPTS = (False, True)
    RELOAD_AFTER_SECONDS = 300.0
    # Giving way to chat is bounded per alert, so monitoring can never stall: at
    # most this long waiting for chat to finish, and after this many interrupted
    # runs the alert is triaged to the end even while chat runs.
    CHAT_WAIT_SECONDS = 120.0
    MAX_PREEMPTIONS = 3
    CHAT_POLL_SECONDS = 0.25

    def __init__(self, settings: LlamaCppSettings,
                 loader: Callable[[LlamaCppSettings], Any] = load_llama,
                 chat_busy: ChatBusySignal | None = None,
                 state: SystemPromptState | None = None):
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
        # Created on first use (chat_busy_signal), not at construction.
        self._chat_busy = chat_busy
        self._chat_busy_since: float | None = None
        if state is None and settings.state_dir is not None and settings.model_path is not None:
            state = SystemPromptState(settings.state_dir, settings.model_path)
        self._state = state

    @property
    def chat_busy(self) -> ChatBusySignal:
        if self._chat_busy is None:
            self._chat_busy = chat_busy_signal()
        return self._chat_busy

    async def triage(self, alert: NormalizedAlert) -> TriageResult:
        async with self._lock:
            if not await self._ensure_loaded():
                return unavailable_result(f"Local AI model unavailable: {self._load_error}")
            # Read once per alert, so both attempts see the same instructions.
            system = self.triage_system_prompt()
            last_error: Exception | None = None
            deadline = time.monotonic() + self.CHAT_WAIT_SECONDS
            preemptions = 0
            for attempt, constrained in enumerate(self.ATTEMPTS):
                while True:
                    give_way = preemptions < self.MAX_PREEMPTIONS and await self._wait_for_chat(deadline)
                    try:
                        result = await asyncio.to_thread(self._infer_blocking, alert, constrained, system, give_way)
                    except GenerationInterrupted:
                        # Not a failed attempt: the same attempt runs again from the
                        # start once chat is done, so the result (and its retried
                        # flag) is what an uninterrupted run would have given.
                        preemptions += 1
                        logger.info("Triage paused for a chat question; it restarts when the answer is done")
                        continue
                    except Exception as error:
                        # Malformed or truncated JSON, schema violations and runtime
                        # errors alike: never raised, or one alert could stall a sensor.
                        last_error = error
                        logger.warning("Local AI triage attempt failed: %s", error)
                        break
                    # A reply that only validated under the grammar is a weaker
                    # signal; the confidence cap reads this flag.
                    return result.with_runtime_flags(retried=attempt > 0)
            return unavailable_result(f"Model validation failed: {last_error}")

    async def _wait_for_chat(self, deadline: float) -> bool:
        """Wait while a chat holds the model's CPU time, until `deadline`. True when
        chat is idle (triage should still give way if one starts), False when the
        wait ran out (triage runs to the end regardless). Polled on the event loop:
        cancelling the task stops it at once, and no thread sits in a long wait."""
        while self.chat_busy.is_busy():
            now = time.monotonic()
            if self._chat_busy_since is None:
                self._chat_busy_since = now
            # Also across alerts: a signal seen busy without a break for the whole
            # bound (a stuck chat, or a held mutex) costs that wait once, not once
            # per alert.
            if now >= deadline or now - self._chat_busy_since >= self.CHAT_WAIT_SECONDS:
                logger.info("Chat has kept the local AI busy for %.0f s; triaging alongside it",
                            now - self._chat_busy_since)
                return False
            await asyncio.sleep(self.CHAT_POLL_SECONDS)
        self._chat_busy_since = None
        return True

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

    def _infer_blocking(self, alert: NormalizedAlert, constrained: bool, system: str = SYSTEM_PROMPT,
                        give_way: bool = False) -> TriageResult:
        """One attempt. With give_way, a chat starting in the other service stops
        it at the next token (GenerationInterrupted), and the random state is put
        back as it was, so the re-run samples exactly as this run would have."""
        with self._thread_lock:
            llama = self._llama
            seed = getattr(llama, "_seed", None)
            try:
                with interruptible(llama, self.chat_busy.is_busy if give_way else None):
                    return run_triage(llama, alert, self.settings, constrained, system)
            except GenerationInterrupted:
                if seed is not None:
                    llama.set_seed(seed)
                raise

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
                    with self._thread_lock, self.chat_busy.hold():
                        self._prepare_chat(system)
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
        with self._thread_lock, self.chat_busy.hold():
            self._prepare_chat(system)
            # One token is the least llama.cpp generates; the point is the reading.
            self._llama.create_chat_completion(messages=[{"role": "system", "content": system}, *messages],
                                               temperature=0.0, max_tokens=1)

    def _prepare_chat(self, system: str) -> None:
        """Before any chat generation, with the thread lock and the chat signal
        held: the RAM prompt cache, and the saved system-prompt state. Titles have
        their own short prompt, not worth a file."""
        self._enable_prompt_cache()
        if self._state is not None and system != TITLE_SYSTEM_PROMPT:
            self._state.ensure(self._llama, system)

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
        with self._thread_lock, self.chat_busy.hold():
            self._prepare_chat(system)
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


# --- benchmark: speed with and without each change, and proof answers are equal ----

# Fixed questions, asked with no alerts open, so every run sees the same prompt.
BENCH_QUESTIONS = ("What should I check first today?",
                   "Is anything on my network unusual right now?",
                   "How do I make my office Wi-Fi safer?")
EXIT_OUTPUTS_DIFFER = 2


def bench_alerts(samples: Path | None) -> tuple[list[tuple[str, NormalizedAlert]], str]:
    """Every record in <samples>/*.jsonl, parsed as ingestion parses it. Without a
    samples folder (an installed copy has none) the smoke-test alert stands in."""
    from .ingest import parse_record
    if samples is None:
        candidates = (Path(__file__).resolve().parent.parent / "samples", Path.cwd() / "samples")
        samples = next((folder for folder in candidates if folder.is_dir()), None)
        if samples is None:
            return [("smoke-test alert", SMOKE_TEST_ALERT)], "built-in smoke-test alert (no samples folder found)"
    alerts: list[tuple[str, NormalizedAlert]] = []
    for path in sorted(samples.glob("*.jsonl")):
        try:
            source = Source(path.stem)
        except ValueError:
            continue  # not named after a sensor
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.strip():
                alerts.append((f"{path.name}:{number}", parse_record(source, json.loads(line))))
    if not alerts:
        raise ModelUnavailable(f"no sensor records in {samples}\\*.jsonl")
    return alerts, str(samples)


def _bench_triage(llama: Any, alert: NormalizedAlert, settings: LlamaCppSettings) -> dict[str, Any]:
    """The service's attempts (unconstrained, then the grammar retry) at temperature 0."""
    outputs: list[str] = []
    tokens, valid = 0, False
    started = time.perf_counter()
    for constrained in LlamaCppTriageModel.ATTEMPTS:
        response = llama.create_chat_completion(**triage_request(alert, settings, constrained, temperature=0.0))
        content = response["choices"][0]["message"]["content"]
        outputs.append(content if isinstance(content, str) else "")
        tokens += int((response.get("usage") or {}).get("completion_tokens") or 0)
        try:
            parse_reply(outputs[-1])
            valid = True
            break
        except Exception:
            continue
    return {"seconds": time.perf_counter() - started, "tokens": tokens, "retries": len(outputs) - 1,
            "valid": valid, "output": "\n--- grammar retry ---\n".join(outputs)}


def _bench_chat(llama: Any, settings: LlamaCppSettings, system: str, question: str) -> dict[str, Any]:
    """One question exactly as chat_stream asks it, at temperature 0."""
    from .llm import CHAT_REPLY_MAX_TOKENS, build_chat_context, build_chat_messages, history_budget
    from .schema import ChatMessage
    messages = build_chat_messages([ChatMessage(role="user", content=question)], build_chat_context([], False),
                                   history_budget(system))
    pieces: list[str] = []
    started = time.perf_counter()
    first: float | None = None
    for chunk in llama.create_chat_completion(messages=[{"role": "system", "content": system}, *messages],
                                              temperature=0.0, max_tokens=min(CHAT_REPLY_MAX_TOKENS,
                                                                              settings.max_tokens),
                                              stream=True):
        piece = chunk["choices"][0].get("delta", {}).get("content")
        if isinstance(piece, str) and piece:
            first = first if first is not None else time.perf_counter()
            pieces.append(piece)
    ended = time.perf_counter()
    first = first if first is not None else ended
    # Streamed pieces are tokens, except that a character split across tokens
    # arrives as one piece.
    rate = (len(pieces) - 1) / (ended - first) if len(pieces) > 1 and ended > first else 0.0
    return {"first_token_seconds": first - started, "seconds": ended - started, "tokens": len(pieces),
            "tokens_per_second": rate, "output": "".join(pieces)}


def _median(values: list[float]) -> float:
    import statistics
    return statistics.median(values) if values else 0.0


def _bench_mode(settings: LlamaCppSettings, alerts: list[tuple[str, NormalizedAlert]], runs: int,
                system: str) -> dict[str, Any]:
    started = time.perf_counter()
    llama = load_llama(settings)
    load_seconds = time.perf_counter() - started
    try:
        mode_runs = []
        for _ in range(runs):
            triage = [{"name": name, **_bench_triage(llama, alert, settings)} for name, alert in alerts]
            chat = [{"question": question, **_bench_chat(llama, settings, system, question)}
                    for question in BENCH_QUESTIONS]
            mode_runs.append({"triage": triage, "chat": chat})
        drafting = getattr(llama, "draft_model", None) is not None
    finally:
        close = getattr(llama, "close", None)
        if callable(close):
            close()
    triage_seconds = sum(item["seconds"] for run in mode_runs for item in run["triage"])
    triage_tokens = sum(item["tokens"] for run in mode_runs for item in run["triage"])
    chats = [item for run in mode_runs for item in run["chat"]]
    return {"speculative": drafting, "load_seconds": load_seconds,
            "triage_seconds": triage_seconds / runs, "triage_tokens": triage_tokens // runs,
            "triage_tokens_per_second": triage_tokens / triage_seconds if triage_seconds else 0.0,
            "grammar_retries": sum(item["retries"] for run in mode_runs for item in run["triage"]),
            "invalid_triage": sum(not item["valid"] for run in mode_runs for item in run["triage"]),
            "chat_first_token_seconds": _median([item["first_token_seconds"] for item in chats]),
            "chat_tokens_per_second": _median([item["tokens_per_second"] for item in chats]),
            "runs": mode_runs}


def _bench_differences(off: dict[str, Any], on: dict[str, Any]) -> list[dict[str, Any]]:
    differences = []
    for number, (run_off, run_on) in enumerate(zip(off["runs"], on["runs"]), start=1):
        for kind, label in (("triage", "name"), ("chat", "question")):
            for item_off, item_on in zip(run_off[kind], run_on[kind]):
                if item_off["output"] != item_on["output"]:
                    differences.append({"run": number, "kind": kind, "item": item_off[label],
                                        "speculative_off": item_off["output"], "speculative_on": item_on["output"]})
    return differences


def _bench_saved_state(settings: LlamaCppSettings, system: str) -> dict[str, Any]:
    """The first question after a restart, without and with a saved system-prompt
    state, each from an empty context."""
    import tempfile
    llama = load_llama(settings)
    try:
        with tempfile.TemporaryDirectory(prefix="lighthouse-bench-") as folder:
            llama.reset()
            cold = _bench_chat(llama, settings, system, BENCH_QUESTIONS[0])
            llama.reset()
            started = time.perf_counter()
            saver = SystemPromptState(Path(folder), settings.model_path, role="bench")
            saved = saver.ensure(llama, system)
            saver.flush()
            save_seconds = time.perf_counter() - started
            llama.reset()
            started = time.perf_counter()
            restored = SystemPromptState(Path(folder), settings.model_path, role="bench").ensure(llama, system)
            restore_seconds = time.perf_counter() - started
            warm = _bench_chat(llama, settings, system, BENCH_QUESTIONS[0])
            size = sum(file.stat().st_size for file in Path(folder).glob(f"*{STATE_FILE_SUFFIX}"))
    finally:
        close = getattr(llama, "close", None)
        if callable(close):
            close()
    return {"save": saved, "restore": restored, "file_bytes": size, "save_seconds": save_seconds,
            "restore_seconds": restore_seconds,
            "cold_first_token_seconds": cold["first_token_seconds"],
            "restored_first_token_seconds": restore_seconds + warm["first_token_seconds"],
            "identical": cold["output"] == warm["output"],
            "cold_output": cold["output"], "restored_output": warm["output"]}


def bench(settings: LlamaCppSettings, runs: int = 1, samples: Path | None = None) -> dict[str, Any]:
    """Everything twice, speculative decoding off then on, at temperature 0 (so the
    same model must give byte-identical answers), then the saved-state check. Run
    only by hand: it loads the model three times and takes minutes."""
    from .llm import compose_chat_system_prompt
    alerts, source = bench_alerts(samples)
    system = compose_chat_system_prompt()
    off = _bench_mode(replace(settings, speculative=False), alerts, runs, system)
    on = _bench_mode(replace(settings, speculative=True), alerts, runs, system)
    differences = _bench_differences(off, on)
    return {"model": str(settings.model_path), "runs": runs, "samples": source, "alerts": len(alerts),
            "questions": list(BENCH_QUESTIONS), "threads": plan_threads(settings) or "llama.cpp default",
            "modes": {"speculative_off": off, "speculative_on": on},
            "identical": not differences, "differences": differences,
            "saved_state": _bench_saved_state(settings, system)}


def format_bench(report: dict[str, Any]) -> str:
    off, on = report["modes"]["speculative_off"], report["modes"]["speculative_on"]
    rows = [("Model load (s)", "load_seconds", "{:.1f}"),
            ("Triage, all alerts (s per run)", "triage_seconds", "{:.1f}"),
            ("Triage tokens/s", "triage_tokens_per_second", "{:.1f}"),
            ("Grammar retries", "grammar_retries", "{}"),
            ("Replies failing validation", "invalid_triage", "{}"),
            ("Chat first token (s, median)", "chat_first_token_seconds", "{:.2f}"),
            ("Chat tokens/s (median)", "chat_tokens_per_second", "{:.1f}")]
    lines = [f"LightHouse local AI benchmark: {report['alerts']} alerts from {report['samples']}, "
             f"{len(report['questions'])} questions, {report['runs']} run(s), temperature 0",
             f"{'':32}{'speculative off':>18}{'speculative on':>18}"]
    lines += [f"{label:32}{fmt.format(off[key]):>18}{fmt.format(on[key]):>18}" for label, key, fmt in rows]
    if not on["speculative"]:
        lines.append("Note: speculative decoding could not be enabled; both columns ran without it.")
    if report["identical"]:
        lines.append("Answers identical with and without speculative decoding: YES")
    else:
        lines.append(f"Answers identical with and without speculative decoding: NO "
                     f"({len(report['differences'])} differ)")
        for difference in report["differences"]:
            lines += [f"  run {difference['run']}, {difference['kind']} {difference['item']}:",
                      f"    off: {difference['speculative_off']!r}", f"    on:  {difference['speculative_on']!r}"]
    state = report["saved_state"]
    lines.append(f"First question after a restart, first token: {state['cold_first_token_seconds']:.2f} s cold, "
                 f"{state['restored_first_token_seconds']:.2f} s with saved instructions "
                 f"(restore {state['restore_seconds']:.2f} s; save was '{state['save']}', restore was "
                 f"'{state['restore']}', file {state['file_bytes'] / 2**20:.0f} MB)")
    lines.append(f"Answer identical with and without the saved state: {'YES' if state['identical'] else 'NO'}")
    if not state["identical"]:
        lines += [f"    cold:     {state['cold_output']!r}", f"    restored: {state['restored_output']!r}"]
    return "\n".join(lines)


def _bench_report_path(out: Path) -> Path:
    if out.suffix.lower() == ".json" and not out.is_dir():
        return out
    return out / time.strftime("lighthouse-bench-%Y%m%d-%H%M%S.json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.local_model")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-cpu", help=f"exit 0 if this CPU can run the bundled runtime, {EXIT_UNSUPPORTED_CPU} if not")
    smoke = sub.add_parser("smoke-test", help="load the GGUF model and validate one triage")
    smoke.add_argument("--model-path", type=Path, help="defaults to LIGHTHOUSE_MODEL_PATH")
    smoke.add_argument("--threads", type=int, help="CPU threads to try (default: chosen from this processor)")
    timing = sub.add_parser("bench", help="time the local AI with and without its speed-ups and check that the "
                                          "answers are identical (takes minutes; run it by hand)")
    timing.add_argument("--model-path", type=Path, help="defaults to LIGHTHOUSE_MODEL_PATH")
    timing.add_argument("--threads", type=int, help="CPU threads to try (default: chosen from this processor)")
    timing.add_argument("--runs", type=int, default=1, help="repeat every alert and question N times (default 1)")
    timing.add_argument("--samples", type=Path, help="folder of sensor *.jsonl records (default: the repo's samples)")
    timing.add_argument("--out", type=Path, default=Path("."),
                        help="JSON report file, or a folder for a timestamped one (default: current folder)")
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
    if args.command == "bench":
        try:
            report = bench(settings, runs=max(1, args.runs), samples=args.samples)
            path = _bench_report_path(args.out)
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        except Exception as error:
            print(f"Local AI benchmark failed: {error}", file=sys.stderr)
            return 1
        print(format_bench(report))
        print(f"Report: {path}")
        return 0 if report["identical"] and report["saved_state"]["identical"] else EXIT_OUTPUTS_DIFFER
    try:
        print(json.dumps(smoke_test(settings)))
    except Exception as error:
        print(f"Local AI self-test failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
