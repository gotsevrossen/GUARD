"""Speed-ups of the llama.cpp backend that must never change an answer: speculative
decoding, chat priority over triage, and the saved system-prompt state. Fakes only:
no GGUF model is ever loaded here. Where the real llama-cpp-python 0.3.35 classes
are exercised, they run against fake llama.cpp contexts.
"""
import asyncio
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import random
import sys
import threading
import time
import types

import numpy as np
import pytest

from triage import local_model
from triage.llm import SYSTEM_PROMPT, TITLE_SYSTEM_PROMPT
from triage.local_model import (ChatBusySignal, GenerationInterrupted, LlamaCppSettings, LlamaCppTriageModel,
                                SMOKE_TEST_ALERT, STATE_FILE_MAGIC, StateFileRejected, SystemPromptState,
                                WindowsChatBusySignal, read_state_file, state_key, write_state_file)

VALID = {"severity": "high", "explanation": "Someone repeatedly failed to sign in as administrator.",
         "recommended_action": "Check who owns 192.0.2.10.", "reasoning": "Event 4625 from one address."}
REPO = Path(__file__).resolve().parent.parent


def gguf(path: Path) -> Path:
    path.write_bytes(b"GGUF" + (3).to_bytes(4, "little") + b"\0" * 32)
    return path


# --- settings ---------------------------------------------------------------------

def test_speculative_and_state_settings(monkeypatch, tmp_path):
    for name in ("LIGHTHOUSE_MODEL_SPECULATIVE", "LIGHTHOUSE_MODEL_STATE_DIR"):
        monkeypatch.delenv(name, raising=False)
    settings = LlamaCppSettings.from_env()
    assert settings.speculative is True and settings.state_dir is None, "on by default; state kept only if set"
    for value, expected in (("0", False), ("off", False), ("1", True), ("TRUE", True)):
        monkeypatch.setenv("LIGHTHOUSE_MODEL_SPECULATIVE", value)
        assert LlamaCppSettings.from_env().speculative is expected
    monkeypatch.setenv("LIGHTHOUSE_MODEL_SPECULATIVE", "maybe")
    with pytest.raises(ValueError, match="LIGHTHOUSE_MODEL_SPECULATIVE"):
        LlamaCppSettings.from_env()
    monkeypatch.delenv("LIGHTHOUSE_MODEL_SPECULATIVE")
    monkeypatch.setenv("LIGHTHOUSE_MODEL_STATE_DIR", str(tmp_path / "llm-state"))
    assert LlamaCppSettings.from_env().state_dir == tmp_path / "llm-state"


# --- speculative decoding -----------------------------------------------------------

def fake_llama_cpp(monkeypatch, drafter=None):
    """A stand-in llama_cpp package; records how Llama was constructed."""
    calls = []

    class Llama:
        def __init__(self, model_path, **options):
            calls.append(options)

    package = types.ModuleType("llama_cpp")
    package.__path__ = []
    package.Llama = Llama
    speculative = types.ModuleType("llama_cpp.llama_speculative")
    if drafter is not None:
        speculative.LlamaPromptLookupDecoding = drafter
    monkeypatch.setitem(sys.modules, "llama_cpp", package)
    monkeypatch.setitem(sys.modules, "llama_cpp.llama_speculative", speculative)
    monkeypatch.setattr(local_model, "cpu_supported", lambda: True)
    return calls


def test_draft_model_is_used_only_when_enabled(monkeypatch, tmp_path):
    class Drafter:
        def __init__(self, max_ngram_size, num_pred_tokens):
            self.sizes = (max_ngram_size, num_pred_tokens)
    calls = fake_llama_cpp(monkeypatch, Drafter)
    settings = LlamaCppSettings(model_path=gguf(tmp_path / "m.gguf"), threads=2)
    llama = local_model.load_llama(settings)
    assert calls[0]["draft_model"].sizes == (2, local_model.SPECULATIVE_DRAFT_TOKENS)
    assert calls[0]["flash_attn"] is True and type(llama).__name__ == "LighthouseLlama"
    local_model.load_llama(LlamaCppSettings(model_path=settings.model_path, threads=2, speculative=False))
    assert "draft_model" not in calls[1]


def test_a_broken_draft_model_never_stops_the_model_loading(monkeypatch, tmp_path):
    class Broken:
        def __init__(self, **kwargs):
            raise RuntimeError("numpy missing")
    calls = fake_llama_cpp(monkeypatch, Broken)
    local_model.load_llama(LlamaCppSettings(model_path=gguf(tmp_path / "m.gguf"), threads=2))
    assert len(calls) == 1 and "draft_model" not in calls[0]
    calls = fake_llama_cpp(monkeypatch, drafter=None)  # module without the class
    local_model.load_llama(LlamaCppSettings(model_path=gguf(tmp_path / "m.gguf"), threads=2))
    assert len(calls) == 1 and "draft_model" not in calls[0]


@pytest.fixture
def real_llama_class():
    if not local_model.cpu_supported():
        pytest.skip("the llama.cpp DLL needs AVX2")
    llama_cpp = pytest.importorskip("llama_cpp")
    assert llama_cpp.__version__ == "0.3.35", "eval and generate below were reviewed for this exact version"
    return llama_cpp.Llama


class FakeBatch:
    """Records what eval asks llama.cpp to compute."""
    def __init__(self):
        self.calls = []

    def set_batch(self, batch, n_past, logits_all):
        self.calls.append((list(batch), n_past, logits_all))

    def outputs(self):
        """Positions of the last batch whose logits llama.cpp would keep."""
        batch, n_past, logits_all = self.calls[-1]
        last = n_past + len(batch) - 1
        return set(range(n_past, last + 1)) if logits_all else {last}


class FakeContext:
    def __init__(self):
        self.decoded = 0
        self.removed = []

    def kv_cache_seq_rm(self, seq_id, p0, p1):
        self.removed.append(p0)
        return True

    def decode(self, batch):
        self.decoded += 1


def bare_llama(cls, draft=None, n_batch=512):
    """An instance of a real Llama class with fake llama.cpp internals."""
    llama = object.__new__(cls)
    llama._stack = ExitStack()  # Llama.__del__ closes it
    llama._ctx, llama._batch = FakeContext(), FakeBatch()
    llama.n_batch, llama.n_tokens, llama._n_ctx = n_batch, 0, 4096
    llama.input_ids = np.zeros(4096, dtype=np.intc)
    llama.scores = np.zeros((n_batch, 4), dtype=np.single)
    llama.draft_model, llama._logits_all = draft, draft is not None
    llama._requires_eval, llama.verbose = True, False
    llama._is_recurrent = llama._is_hybrid = False
    return llama


def test_eval_matches_the_stock_eval_without_a_draft(real_llama_class):
    lighthouse = bare_llama(local_model.lighthouse_llama_class(real_llama_class))
    stock = bare_llama(real_llama_class)
    for llama, run in ((lighthouse, lighthouse.eval), (stock, lambda tokens: real_llama_class.eval(stock, tokens))):
        run(list(range(1, 1201)))
        run([7])
    assert lighthouse._batch.calls == stock._batch.calls
    assert [n_past for _, n_past, _ in lighthouse._batch.calls] == [0, 512, 1024, 1200]
    assert not any(logits_all for *_, logits_all in lighthouse._batch.calls)
    assert lighthouse.n_tokens == stock.n_tokens == 1201
    assert (lighthouse.input_ids[:1201] == stock.input_ids[:1201]).all()


def test_eval_asks_for_every_position_only_when_verifying_a_draft(real_llama_class):
    llama = bare_llama(local_model.lighthouse_llama_class(real_llama_class), draft=object())
    llama.eval(list(range(1, 1201)))   # a long prompt: stock 0.3.35 fails here with a draft
    assert not any(logits_all for *_, logits_all in llama._batch.calls)
    llama.eval([5] * (local_model.SPECULATIVE_DRAFT_TOKENS + 1))
    assert llama._batch.calls[-1][2] is True
    assert llama.n_tokens == 1200 + local_model.SPECULATIVE_DRAFT_TOKENS + 1


def test_eval_stops_between_batches_when_chat_starts(real_llama_class):
    llama = bare_llama(local_model.lighthouse_llama_class(real_llama_class))
    checks = iter([False, True])
    llama.lighthouse_interrupt = lambda: next(checks)
    with pytest.raises(GenerationInterrupted):
        llama.eval(list(range(1, 1201)))
    # The first 512 tokens finished and are kept consistently; nothing after them.
    assert llama.n_tokens == 512 and llama._ctx.decoded == 1


def next_token(context) -> int:
    """A deterministic stand-in for a model: the next token depends only on the
    tokens before it (a causal model), with a small vocabulary so text repeats and
    prompt lookup finds drafts, some right and some wrong."""
    last = [int(token) for token in context[-3:]]
    return (last[-1] * 3 + sum(last) // 2 + len(context) % 5) % 9 + 1


def generated(cls, draft, prompt, count):
    llama = bare_llama(cls, draft=draft)
    llama._init_sampler = lambda **kwargs: object()
    drafts = {"kept": 0, "rejected": 0}

    def sample(**kwargs):
        idx = kwargs["idx"]
        # The real sampler reads llama.cpp's logits for this position: it must
        # have been computed in the last batch, or llama.cpp would fail.
        assert idx in llama._batch.outputs(), f"logits for position {idx} were not requested"
        token = next_token(llama.input_ids[:idx + 1])
        if idx + 1 < llama.n_tokens:  # a drafted token sits at the next position
            drafts["kept" if llama.input_ids[idx + 1] == token else "rejected"] += 1
        return token
    llama.sample = sample
    tokens = []
    stream = cls.generate(llama, prompt, temp=0.0)
    for token in stream:
        tokens.append(int(token))
        if len(tokens) == count:
            break
    stream.close()
    return tokens, len(llama._batch.calls), drafts


def test_speculative_generation_emits_exactly_the_models_own_tokens(real_llama_class):
    """Llama.generate of 0.3.35, unchanged, driven through LighthouseLlama.eval: with
    prompt-lookup drafts the emitted tokens are the ones the model picks without
    them, in fewer model calls."""
    from llama_cpp.llama_speculative import LlamaPromptLookupDecoding
    cls = local_model.lighthouse_llama_class(real_llama_class)
    prompt = [next_token([1, 2])]
    for _ in range(700):  # longer than one 512-token batch
        prompt.append(next_token([1, 2, *prompt]))
    plain, plain_calls, _ = generated(cls, None, prompt, 200)
    drafter = LlamaPromptLookupDecoding(max_ngram_size=local_model.SPECULATIVE_NGRAM_SIZE,
                                        num_pred_tokens=local_model.SPECULATIVE_DRAFT_TOKENS)
    drafted, drafted_calls, drafts = generated(cls, drafter, prompt, 200)
    assert drafted == plain
    assert drafts["kept"] and drafts["rejected"], "both the accept and the reject path were exercised"
    assert drafted_calls < plain_calls, "drafts were accepted, so fewer batches ran"


# --- chat priority over triage ---------------------------------------------------

class FakeSignal(ChatBusySignal):
    def __init__(self, busy=None):
        self.busy = busy or (lambda: False)
        self.holds = []

    def is_busy(self):
        return self.busy()

    @contextmanager
    def hold(self):
        self.holds.append(("enter", threading.get_ident()))
        try:
            yield
        finally:
            self.holds.append(("exit", threading.get_ident()))


class InterruptibleLlama:
    """Produces `tokens` tokens per completion, checking the interrupt hook before
    each, like LighthouseLlama.eval. Moves its seed on per completion, as
    llama-cpp-python does."""
    lighthouse_interrupt = None

    def __init__(self, *replies, tokens=5):
        self.replies, self.tokens = list(replies), tokens
        self._seed, self.calls, self.seeds = 1234, [], []

    def set_seed(self, seed):
        self._seed = seed

    def create_chat_completion(self, **kwargs):
        self.calls.append(kwargs)
        self._seed = random.Random(self._seed).randint(0, 2**32)
        self.seeds.append(self._seed)
        for _ in range(self.tokens):
            check = self.lighthouse_interrupt
            if check is not None and check():
                raise GenerationInterrupted()
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        return {"choices": [{"message": {"content": reply}}]}


def triage_model(llama, tmp_path, signal):
    model = LlamaCppTriageModel(LlamaCppSettings(model_path=gguf(tmp_path / "m.gguf")),
                                loader=lambda settings: llama, chat_busy=signal)
    model.CHAT_POLL_SECONDS = 0
    return model


def on_worker_thread() -> bool:
    return threading.current_thread() is not threading.main_thread()


def test_triage_gives_way_to_chat_and_reruns_the_same_attempt(tmp_path):
    states = iter([False, False, True])  # chat starts at the third token
    waits = iter([True, True, False])    # ...and is busy for two polls after
    signal = FakeSignal(lambda: next(states, False) if on_worker_thread() else next(waits, False))
    llama = InterruptibleLlama(json.dumps(VALID))
    result = asyncio.run(triage_model(llama, tmp_path, signal).triage(SMOKE_TEST_ALERT))
    assert result.severity.value == "high" and not result.retried and not result.unavailable
    assert len(llama.calls) == 2 and not any("response_format" in call for call in llama.calls), \
        "an interrupted run is re-run as the same attempt, never as the grammar retry"
    assert llama.seeds[0] == llama.seeds[1], "the re-run samples exactly as the interrupted run would have"
    assert llama.lighthouse_interrupt is None
    assert not signal.holds, "triage never marks chat busy"


def test_a_real_failure_after_an_interruption_still_gets_the_grammar_retry(tmp_path):
    first = iter([True])
    signal = FakeSignal(lambda: next(first, False) if on_worker_thread() else False)
    llama = InterruptibleLlama("not json", json.dumps(VALID))  # an interrupted call replies nothing
    result = asyncio.run(triage_model(llama, tmp_path, signal).triage(SMOKE_TEST_ALERT))
    assert [("response_format" in call) for call in llama.calls] == [False, False, True]
    assert result.retried and result.severity.value == "high"


def test_interruptions_are_bounded_per_alert(tmp_path):
    # Chat starts again during every run, but is always idle when triage checks.
    signal = FakeSignal(on_worker_thread)
    llama = InterruptibleLlama(json.dumps(VALID))
    result = asyncio.run(triage_model(llama, tmp_path, signal).triage(SMOKE_TEST_ALERT))
    assert len(llama.calls) == LlamaCppTriageModel.MAX_PREEMPTIONS + 1
    assert result.severity.value == "high" and not result.retried


def test_waiting_for_chat_is_bounded(tmp_path):
    signal = FakeSignal(lambda: True)  # a chat, or a stuck signal, that never ends
    llama = InterruptibleLlama(json.dumps(VALID))
    model = triage_model(llama, tmp_path, signal)
    model.CHAT_WAIT_SECONDS = 0.3
    started = time.monotonic()
    result = asyncio.run(asyncio.wait_for(model.triage(SMOKE_TEST_ALERT), timeout=10))
    assert time.monotonic() - started >= 0.3
    assert result.severity.value == "high" and len(llama.calls) == 1, "triaged alongside chat after the wait"
    # A signal that never clears costs that wait once, not once per alert.
    started = time.monotonic()
    asyncio.run(asyncio.wait_for(model.triage(SMOKE_TEST_ALERT), timeout=10))
    assert time.monotonic() - started < 0.25 and len(llama.calls) == 2


class ChatLlama:
    lighthouse_interrupt = None

    def __init__(self):
        self.calls = []

    def set_cache(self, cache):
        pass

    def create_chat_completion(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs.get("stream"):
            return iter([{"choices": [{"delta": {"content": "Hi"}}]}])
        return {"choices": [{"message": {"content": "Hi"}}]}


def test_chat_marks_itself_busy_on_the_thread_that_runs_the_model(tmp_path):
    signal = FakeSignal()
    model = LlamaCppTriageModel(LlamaCppSettings(model_path=gguf(tmp_path / "m.gguf")),
                                loader=lambda settings: ChatLlama(), chat_busy=signal)
    messages = [{"role": "user", "content": "Is my network safe?"}]

    async def use():
        assert await model.chat("system", messages, max_tokens=50, temperature=0.3) == "Hi"
        assert [piece async for piece in model.chat_stream("system", messages, max_tokens=50, temperature=0.3)] \
            == ["Hi"]
        assert await model.warm("system", messages)
    asyncio.run(use())
    assert [kind for kind, _ in signal.holds] == ["enter", "exit"] * 3
    for (_, entered), (_, exited) in zip(signal.holds[::2], signal.holds[1::2]):
        assert entered == exited != threading.main_thread().ident, "a mutex must be released by its owner thread"


class FakeWin32Event:
    def __init__(self, *results):
        self.results, self.released, self.created = list(results), [], []

    def CreateMutex(self, security, initial, name):
        self.created.append((security, initial, name))
        return types.SimpleNamespace(Close=lambda: self.created.append("closed"))

    def WaitForSingleObject(self, handle, milliseconds):
        return self.results.pop(0)

    def ReleaseMutex(self, handle):
        self.released.append(threading.get_ident())


def windows_signal(*results):
    win32event = FakeWin32Event(*results)
    return WindowsChatBusySignal(win32event=win32event, owner_of=lambda handle: "S-1-5-18"), win32event


def test_windows_signal_semantics():
    signal, win32event = windows_signal(0x00, 0x80, 0x102)
    assert signal.is_busy() is False and signal.is_busy() is False, "free, or abandoned by a crashed chat"
    assert len(win32event.released) == 2, "a test acquisition is released at once"
    assert signal.is_busy() is True and len(win32event.released) == 2
    assert win32event.created[0][1:] == (False, local_model.CHAT_BUSY_MUTEX)
    signal, win32event = windows_signal(0x80)
    with pytest.raises(RuntimeError):
        with signal.hold():
            raise RuntimeError("chat failed")
    assert len(win32event.released) == 1, "released even when the chat fails"
    signal, win32event = windows_signal(0x102)  # something else holds it: chat answers anyway
    with signal.hold():
        pass
    assert not win32event.released


def test_a_squatted_signal_is_ignored():
    win32event = FakeWin32Event()
    with pytest.raises(PermissionError, match="S-1-5-21-1-2-3-1001"):
        WindowsChatBusySignal(win32event=win32event, owner_of=lambda handle: "S-1-5-21-1-2-3-1001")
    assert win32event.created[-1] == "closed"
    for owner in ("S-1-5-18", "S-1-5-32-544"):
        WindowsChatBusySignal(win32event=FakeWin32Event(), owner_of=lambda handle: owner)


def test_signal_falls_back_to_no_waiting(monkeypatch):
    monkeypatch.setattr(local_model, "_chat_busy_signal", None)
    monkeypatch.setattr(sys, "platform", "linux")
    assert type(local_model.chat_busy_signal()) is ChatBusySignal
    monkeypatch.setattr(local_model, "_chat_busy_signal", None)
    monkeypatch.setattr(sys, "platform", "win32")

    def refuse(*args, **kwargs):
        raise PermissionError("owned by someone else")
    monkeypatch.setattr(local_model, "WindowsChatBusySignal", refuse)
    signal = local_model.chat_busy_signal()
    assert type(signal) is ChatBusySignal and signal.is_busy() is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptors")
def test_mutex_is_created_for_system_and_administrators_only():
    import win32security
    dacl = local_model._admin_only_security().SECURITY_DESCRIPTOR.GetSecurityDescriptorDacl()
    sids = {win32security.ConvertSidToStringSid(dacl.GetAce(index)[2]) for index in range(dacl.GetAceCount())}
    assert sids == {"S-1-5-18", "S-1-5-32-544"}


# --- saved system-prompt state: file format and key ---------------------------------

def test_state_file_round_trip(tmp_path):
    path = tmp_path / "chat-key.lhstate"
    ids = np.array([1, 2, 300, 4], dtype=np.intc)
    write_state_file(path, "key", ids, b"llama-state-bytes")
    read_ids, state = read_state_file(path, "key", n_ctx=4096, n_vocab=1000)
    assert read_ids.tolist() == [1, 2, 300, 4] and bytes(state) == b"llama-state-bytes"
    assert path.read_bytes().startswith(STATE_FILE_MAGIC)
    assert not list(tmp_path.glob("*.tmp"))


def corrupt(path: Path, offset: int, value: bytes) -> None:
    data = bytearray(path.read_bytes())
    data[offset:offset + len(value)] = value
    path.write_bytes(bytes(data))


@pytest.mark.parametrize("damage, reason", [
    (lambda p: p.write_bytes(b"\x80\x04\x95pickle" + p.read_bytes()[14:]), "not a LightHouse state file"),
    (lambda p: p.write_bytes(p.read_bytes()[:-1]), "truncated"),
    (lambda p: p.write_bytes(p.read_bytes() + b"x"), "truncated or padded"),
    (lambda p: corrupt(p, len(p.read_bytes()) - 1, b"X"), "checksum"),
    (lambda p: corrupt(p, 8, (10**6).to_bytes(4, "little")), "header size"),
    (lambda p: corrupt(p, 12, b"[]"), "unreadable header|unknown format"),
])
def test_damaged_state_files_are_rejected(tmp_path, damage, reason):
    path = tmp_path / "chat-key.lhstate"
    write_state_file(path, "key", [1, 2, 3], b"state")
    damage(path)
    with pytest.raises(StateFileRejected, match=reason):
        read_state_file(path, "key", n_ctx=4096, n_vocab=1000)


def test_state_files_for_another_key_or_runtime_are_rejected(tmp_path):
    path = tmp_path / "chat-key.lhstate"
    write_state_file(path, "key", [1, 2, 999], b"state")
    with pytest.raises(StateFileRejected, match="another model"):
        read_state_file(path, "other", n_ctx=4096, n_vocab=1000)
    with pytest.raises(StateFileRejected, match="token id out of range"):
        read_state_file(path, "key", n_ctx=4096, n_vocab=999)
    with pytest.raises(StateFileRejected, match="bad sizes"):
        read_state_file(path, "key", n_ctx=2, n_vocab=1000)


def test_state_key_covers_model_runtime_and_exact_prompt(tmp_path):
    model = gguf(tmp_path / "m.gguf")
    runtime = {"llama_cpp": "0.3.35", "n_ctx": 4096, "n_threads": 8}
    key = state_key(model, runtime, "instructions")
    assert key == state_key(model, dict(runtime), "instructions")
    assert key != state_key(model, runtime, "instructions ")
    assert key != state_key(model, {**runtime, "n_threads": 4}, "instructions")
    assert key != state_key(model, {**runtime, "llama_cpp": "0.3.36"}, "instructions")
    os.utime(model, ns=(1, 1))
    assert key != state_key(model, runtime, "instructions"), "a replaced model file gets a new key"


# --- saved system-prompt state: building, restoring, verifying ---------------------

class FakeStateLlama:
    """Tokenizes like a chat template (BOS, then role marker, characters and END per
    turn) and reuses the longest matching prefix, as llama-cpp-python does."""

    def __init__(self):
        self.ids: list[int] = []
        self.evaluated = 0
        self.completions = 0
        self.cache = "ram-cache"
        self._seed = 7

    def set_cache(self, cache):
        self.cache = cache

    def set_seed(self, seed):
        self._seed = seed

    def n_ctx(self):
        return 4096

    def n_vocab(self):
        return 0x110000

    def lighthouse_signature(self):
        return {"runtime": "fake"}

    @staticmethod
    def tokens(messages):
        ids = [1]
        for message in messages:
            ids += [2 if message["role"] == "system" else 3, *map(ord, message["content"]), 4]
        return ids

    def create_chat_completion(self, messages, **kwargs):
        self.completions += 1
        self._seed += 1
        prompt = self.tokens(messages)
        shared = local_model._shared_prefix(self.ids, prompt)
        self.evaluated += len(prompt) - shared
        self.ids = prompt
        return {"choices": [{"message": {"content": "x"}}]}

    def lighthouse_tokens(self):
        return np.array(self.ids, dtype=np.intc)

    def lighthouse_truncate(self, count):
        self.ids = self.ids[:count]

    def lighthouse_capture(self):
        return np.array(self.ids, dtype=np.intc), b"KV" + bytes(len(self.ids))

    def lighthouse_restore(self, ids, state):
        if bytes(state) != b"KV" + bytes(len(ids)):
            raise RuntimeError("llama.cpp rejected the saved state")
        self.ids = [int(token) for token in ids]

    def reset(self):
        self.ids = []


SYSTEM = "You are LightHouse."


def system_prefix(system=SYSTEM):
    return [1, 2, *map(ord, system), 4, 3]


def store(tmp_path, model=None):
    if model is None:
        model = tmp_path / "m.gguf"
        if not model.exists():  # rewriting it would change its mtime, and so the key
            gguf(model)
    return SystemPromptState(tmp_path / "llm-state", model)


def saved_files(tmp_path):
    return sorted((tmp_path / "llm-state").glob("*.lhstate"))


def test_state_is_saved_once_and_holds_only_the_instructions(tmp_path):
    (tmp_path / "llm-state").mkdir()
    states, llama = store(tmp_path), FakeStateLlama()
    assert states.ensure(llama, SYSTEM) == "saved"
    states.flush()
    [path] = saved_files(tmp_path)
    ids, _ = read_state_file(path, path.stem.split("-", 1)[1], 4096, 0x110000)
    assert ids.tolist() == system_prefix(), "the system turn and template markup, no probe or user text"
    assert llama.cache == "ram-cache" and llama._seed == 7, "probes leave no trace in the cache or seed"
    completions = llama.completions
    assert states.ensure(llama, SYSTEM) == "ready" and llama.completions == completions


def test_a_restart_restores_the_instructions_instead_of_reading_them(tmp_path):
    first = store(tmp_path)
    first.ensure(FakeStateLlama(), SYSTEM)
    first.flush()
    llama = FakeStateLlama()
    assert store(tmp_path).ensure(llama, SYSTEM) == "restored"
    probe = FakeStateLlama.tokens([{"role": "system", "content": SYSTEM},
                                   {"role": "user", "content": SystemPromptState.PROBES[0]}])
    assert llama.evaluated == len(probe) - len(system_prefix()), "only the probe's own tokens were read"
    # The question that follows reads only itself.
    before = llama.evaluated
    llama.create_chat_completion(messages=[{"role": "system", "content": SYSTEM},
                                           {"role": "user", "content": "Am I safe?"}])
    assert llama.evaluated - before == len("Am I safe?") + 1
    assert len(saved_files(tmp_path)) == 1


def test_a_file_whose_tokens_do_not_match_is_rebuilt(tmp_path):
    first = store(tmp_path)
    first.ensure(FakeStateLlama(), SYSTEM)
    first.flush()
    [path] = saved_files(tmp_path)
    key = path.stem.split("-", 1)[1]
    wrong = system_prefix()
    wrong[5] += 1  # valid format and checksum, but not this prompt's tokens
    write_state_file(path, key, wrong, b"KV" + bytes(len(wrong)))
    llama = FakeStateLlama()
    states = store(tmp_path)
    assert states.ensure(llama, SYSTEM) == "saved"
    states.flush()
    ids, _ = read_state_file(path, key, 4096, 0x110000)
    assert ids.tolist() == system_prefix()


def test_a_damaged_file_is_ignored(tmp_path):
    first = store(tmp_path)
    first.ensure(FakeStateLlama(), SYSTEM)
    first.flush()
    [path] = saved_files(tmp_path)
    corrupt(path, len(path.read_bytes()) - 1, b"!")
    states = store(tmp_path)
    assert states.ensure(FakeStateLlama(), SYSTEM) == "saved"
    states.flush()
    assert len(saved_files(tmp_path)) == 1


def test_only_the_two_newest_prompts_are_kept(tmp_path):
    model = gguf(tmp_path / "m.gguf")
    for number in range(4):
        states = store(tmp_path, model)
        states.ensure(FakeStateLlama(), f"{SYSTEM} Note {number}.")
        states.flush()
    files = saved_files(tmp_path)
    assert len(files) == local_model.STATE_FILES_KEPT
    # The newest two: the last prompt and the one before it.
    keys = {state_key(model, {"runtime": "fake"}, f"{SYSTEM} Note {number}.") for number in (2, 3)}
    assert {file.stem.split("-", 1)[1] for file in files} == keys


def test_state_failures_never_break_chat(tmp_path):
    class Broken(FakeStateLlama):
        def lighthouse_capture(self):
            raise RuntimeError("out of memory")
    assert store(tmp_path).ensure(Broken(), SYSTEM) == "failed"


def test_chat_uses_saved_state_but_titles_do_not(tmp_path):
    seen = []

    class Spy:
        def ensure(self, llama, system):
            seen.append(system)
            return "ready"
    model = LlamaCppTriageModel(LlamaCppSettings(model_path=gguf(tmp_path / "m.gguf")),
                                loader=lambda settings: ChatLlama(), chat_busy=FakeSignal(), state=Spy())
    messages = [{"role": "user", "content": "Is my network safe?"}]
    asyncio.run(model.chat(TITLE_SYSTEM_PROMPT, messages, max_tokens=16, temperature=0.2))
    asyncio.run(model.chat("chat instructions", messages, max_tokens=50, temperature=0.3))
    assert seen == ["chat instructions"]
    assert LlamaCppTriageModel(LlamaCppSettings(model_path=tmp_path / "m.gguf"))._state is None, "off unless set"
    configured = LlamaCppTriageModel(LlamaCppSettings(model_path=tmp_path / "m.gguf", state_dir=tmp_path))
    assert isinstance(configured._state, SystemPromptState)


# --- benchmark ------------------------------------------------------------------------

class BenchLlama(FakeStateLlama):
    """Deterministic replies; with `drift`, speculative mode answers differently."""

    def __init__(self, speculative, drift=False):
        super().__init__()
        self.cache = None
        self.draft_model = object() if speculative else None
        self.drift = drift and speculative

    def create_chat_completion(self, messages, **kwargs):
        super().create_chat_completion(messages)
        assert kwargs["temperature"] == 0.0 or kwargs.get("max_tokens") == 1
        if messages[0]["content"] == SYSTEM_PROMPT:
            # The zeek sample needs the grammar retry; the others pass first time.
            first_try_fails = "zeek" in messages[1]["content"].lower() and "response_format" not in kwargs
            content = "not json" if first_try_fails else json.dumps(VALID)
            return {"choices": [{"message": {"content": content}}], "usage": {"completion_tokens": 40}}
        text = f"Answer about {messages[-1]['content'][:20]}" + ("!" if self.drift else ".")
        if kwargs.get("stream"):
            return iter({"choices": [{"delta": {"content": word + " "}}]} for word in text.split())
        return {"choices": [{"message": {"content": text}}]}

    def close(self):
        pass


def run_bench(monkeypatch, tmp_path, drift=False):
    monkeypatch.setattr(local_model, "load_llama", lambda settings: BenchLlama(settings.speculative, drift))
    out = tmp_path / "report.json"
    code = local_model.main(["bench", "--model-path", str(gguf(tmp_path / "m.gguf")), "--threads", "2",
                             "--samples", str(REPO / "samples"), "--runs", "2", "--out", str(out)])
    return code, json.loads(out.read_text(encoding="utf-8"))


def test_bench_reports_speed_and_identical_answers(monkeypatch, tmp_path, capsys):
    code, report = run_bench(monkeypatch, tmp_path)
    printed = capsys.readouterr().out
    assert code == 0 and report["identical"] and report["saved_state"]["identical"]
    assert report["alerts"] == len(list((REPO / "samples").glob("*.jsonl")))
    off, on = report["modes"]["speculative_off"], report["modes"]["speculative_on"]
    assert off["speculative"] is False and on["speculative"] is True
    for mode in (off, on):
        assert len(mode["runs"]) == 2 and len(mode["runs"][0]["chat"]) == 3
        assert {"load_seconds", "triage_seconds", "triage_tokens_per_second", "grammar_retries",
                "chat_first_token_seconds", "chat_tokens_per_second"} <= set(mode)
        assert mode["grammar_retries"] == 2 and mode["invalid_triage"] == 0  # zeek, once per run
    assert report["saved_state"]["save"] == "saved" and report["saved_state"]["restore"] == "restored"
    assert "Answers identical with and without speculative decoding: YES" in printed
    assert "speculative off" in printed and "Chat first token" in printed


def test_bench_shows_any_difference(monkeypatch, tmp_path, capsys):
    code, report = run_bench(monkeypatch, tmp_path, drift=True)
    assert code == local_model.EXIT_OUTPUTS_DIFFER and not report["identical"]
    assert {difference["kind"] for difference in report["differences"]} == {"chat"}
    assert "NO (" in capsys.readouterr().out
