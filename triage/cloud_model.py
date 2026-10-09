"""Chat answers from Purdue GenAI Studio, with the local model as the fallback.

Opt-in: used only when an API key is stored (triage.cloud_key). Only chat goes
out, carrying the same owner-safe, fenced alert context as local chat and the same
system prompt, including the admin's AI instructions (owner-approved); alert
triage always stays on this computer (GenAI Studio allows 20 requests a minute
per user, far below a busy sensor's alert rate). The code-side controls (severity
floor, fixed reminders) do not depend on which model answers.

The key goes only to the fixed GenAI Studio host over HTTPS, with redirects
refused so it cannot be forwarded elsewhere, and is never logged. Any failure
before the first word of an answer (network, bad key, rate limit, a `null` reply)
falls back to the local model and pauses GenAI Studio for a minute.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, AsyncIterator

import httpx

from .llm import TriageModel
from .schema import NormalizedAlert, TriageResult

logger = logging.getLogger(__name__)

GENAI_BASE_URL = "https://genai.rcac.purdue.edu"
GENAI_CHAT_PATH = "/api/chat/completions"
DEFAULT_GENAI_MODEL = "gpt-oss:120b"
# GenAI Studio's docs suggest at least 120 s on a busy shared service.
GENAI_TIMEOUT = httpx.Timeout(120.0, connect=10.0)
COOLDOWN_SECONDS = 60.0


# What an admin may pick in the dashboard: models from GenAI Studio's list that suit
# short, careful chat answers (https://docs.rcac.purdue.edu/services/genai/models/),
# plus keeping chat on this computer. Long-thinking reasoning models (deepseek-r1,
# qwq), coding, vision and tiny models are left out on purpose.
LOCAL_CHOICE = "local"
GENAI_MODEL_CHOICES = [
    {"id": "gpt-oss:120b", "label": "GPT-OSS 120B", "note": "Best answers. Recommended."},
    {"id": "gemma4:26b-a4b", "label": "Gemma 4 26B", "note": "Fastest replies."},
    {"id": "llama3.3:70b", "label": "Llama 3.3 70B", "note": "Large, plain conversational style."},
    {"id": "llama4:latest", "label": "Llama 4", "note": "Balanced general chat."},
    {"id": LOCAL_CHOICE, "label": "On this computer only", "note": "Slower; nothing leaves this computer."},
]


def genai_model_name() -> str:
    """`LIGHTHOUSE_GENAI_MODEL`, else the one set with `cloud_key model`, else the default."""
    from .cloud_key import configured_model
    return os.getenv("LIGHTHOUSE_GENAI_MODEL", "").strip() or configured_model() or DEFAULT_GENAI_MODEL


class GenAIUnavailable(RuntimeError):
    """GenAI Studio did not answer usably; the message never contains the key."""


class PurdueChatModel(TriageModel):
    def __init__(self, local: TriageModel, key: str, model: str = DEFAULT_GENAI_MODEL,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.local, self.model = local, model
        self._key = key
        self._transport = transport  # tests substitute a mock transport
        self._paused_until = 0.0

    def __repr__(self) -> str:
        return f"PurdueChatModel(model={self.model!r})"  # never the key

    @property
    def online(self) -> bool:
        return time.monotonic() >= self._paused_until

    async def triage(self, alert: NormalizedAlert) -> TriageResult:
        return await self.local.triage(alert)

    async def warm(self, system: str, messages: list[dict[str, str]]) -> bool:
        # Nothing to pre-read remotely; only warm the local model while it is the one answering.
        return False if self.online else await self.local.warm(system, messages)

    async def chat(self, system: str, messages: list[dict[str, str]], *,
                   max_tokens: int, temperature: float) -> str | None:
        if self.online:
            try:
                text = await self._remote_chat(system, messages, temperature)
                if text:
                    return text
                raise GenAIUnavailable("empty answer")
            except Exception as error:
                self._pause(error)
        return await self.local.chat(system, messages, max_tokens=max_tokens, temperature=temperature)

    async def chat_stream(self, system: str, messages: list[dict[str, str]], *,
                          max_tokens: int, temperature: float) -> AsyncIterator[str]:
        if self.online:
            started = False
            try:
                async for piece in self._remote_stream(system, messages, temperature):
                    started = True
                    yield piece
                if started:
                    return
                raise GenAIUnavailable("empty answer")
            except Exception as error:
                if started:
                    raise  # mid-answer: stream_chat keeps the text and adds its note
                self._pause(error)
        async for piece in self.local.chat_stream(system, messages, max_tokens=max_tokens,
                                                  temperature=temperature):
            yield piece

    # --- GenAI Studio --------------------------------------------------------

    def _pause(self, error: Exception) -> None:
        self._paused_until = time.monotonic() + COOLDOWN_SECONDS
        logger.warning("Purdue GenAI Studio unavailable (%s); using the local model for %.0f s",
                       _describe(error), COOLDOWN_SECONDS)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=GENAI_BASE_URL, timeout=GENAI_TIMEOUT, follow_redirects=False,
                                 transport=self._transport)

    def _request(self, system: str, messages: list[dict[str, str]], temperature: float,
                 stream: bool) -> dict[str, Any]:
        # No max_tokens: reasoning models such as gpt-oss spend part of it thinking
        # and could return nothing. stream_chat caps the reply length instead.
        return {"model": self.model, "stream": stream, "temperature": temperature,
                "messages": [{"role": "system", "content": system}, *messages]}

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._key}"}

    async def _remote_chat(self, system: str, messages: list[dict[str, str]], temperature: float) -> str | None:
        async with self._client() as client:
            response = await client.post(GENAI_CHAT_PATH, json=self._request(system, messages, temperature, False),
                                         headers=self._headers())
        _check(response)
        body = response.json()
        if not isinstance(body, dict):
            raise GenAIUnavailable("no answer (rate limited?)")
        content = body["choices"][0]["message"].get("content")
        return content if isinstance(content, str) and content.strip() else None

    async def _remote_stream(self, system: str, messages: list[dict[str, str]],
                             temperature: float) -> AsyncIterator[str]:
        async with self._client() as client:
            async with client.stream("POST", GENAI_CHAT_PATH, json=self._request(system, messages, temperature, True),
                                     headers=self._headers()) as response:
                _check(response)
                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                    except ValueError:
                        continue
                    if not isinstance(chunk, dict):
                        raise GenAIUnavailable("unexpected stream data")
                    choices = chunk.get("choices") or []
                    piece = (choices[0].get("delta") or {}).get("content") if choices else None
                    if isinstance(piece, str) and piece:
                        yield piece


def _check(response: httpx.Response) -> None:
    if response.status_code == 429:
        raise GenAIUnavailable("rate limited")
    if response.status_code in (401, 403):
        raise GenAIUnavailable(f"key rejected (HTTP {response.status_code})")
    if not 200 <= response.status_code < 300:
        # Includes 3xx: a redirect is never followed, so the key cannot be forwarded.
        raise GenAIUnavailable(f"HTTP {response.status_code}")


def _describe(error: Exception) -> str:
    """For logs: the error type and our own message, never request headers."""
    if isinstance(error, GenAIUnavailable):
        return str(error)
    return type(error).__name__
