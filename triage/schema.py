from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator


class Source(StrEnum):
    SURICATA = "suricata"
    ZEEK = "zeek"
    WAZUH = "wazuh"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


# Rank order used whenever two severities must be compared. UNKNOWN sits above LOW
# because a triage the model could not validate still needs a human look, but below
# MEDIUM because it asserts nothing about the actual risk.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.UNKNOWN: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def coerce_severity(value: Any) -> Severity:
    """Any unrecognised value is treated as UNKNOWN rather than raising."""
    try:
        return Severity(value)
    except ValueError:
        return Severity.UNKNOWN


def max_severity(first: Any, second: Any) -> Severity:
    """Return the more severe of two values by SEVERITY_RANK."""
    left, right = coerce_severity(first), coerce_severity(second)
    return left if SEVERITY_RANK[left] >= SEVERITY_RANK[right] else right


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


CONFIDENCE_RANK: dict[Confidence, int] = {Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}


def coerce_confidence(value: Any) -> Confidence:
    """Anything unrecognised is LOW: an unreadable confidence is no confidence."""
    try:
        return Confidence(value)
    except ValueError:
        return Confidence.LOW


def min_confidence(first: Any, second: Any) -> Confidence:
    """Return the less confident of two values. Mirrors max_severity, in the other
    direction: confidence only ever moves down."""
    left, right = coerce_confidence(first), coerce_confidence(second)
    return left if CONFIDENCE_RANK[left] <= CONFIDENCE_RANK[right] else right


class GuidanceTier(StrEnum):
    STANDARD = "standard"
    CAUTION = "caution"
    REVIEW = "review"
    GET_HELP = "get_help"


class AlertStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class NormalizedAlert(BaseModel):
    source: Source
    source_event_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    title: str
    source_ip: str | None = None
    destination_ip: str | None = None
    device: str | None = None
    rule_id: str | None = None
    # Input-specific discriminator, used only for deduplication (not public API).
    dedupe_key: str | None = None
    mitre: list[str] = Field(default_factory=list)
    # Severity the sensor itself reported, derived deterministically in the readers.
    # It is the floor the model is not allowed to undercut. LOW is the safe default:
    # it never raises risk on its own, it only stops a downgrade when a sensor spoke.
    sensor_severity: Severity = Severity.LOW
    raw: dict[str, Any]

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)


UNCERTAINTY_MAX_CHARS = 400


class TriageResult(BaseModel):
    """What a model runtime returns, validated. Only these fields can come from model
    JSON; anything else the model emits is dropped by validation."""
    severity: Severity
    # A missing or unrecognised confidence becomes LOW instead of failing
    # validation: failing would force the slow grammar-constrained retry only to
    # arrive at the same conservative answer.
    confidence: Confidence = Confidence.LOW
    explanation: str = Field(min_length=1, max_length=1200)
    recommended_action: str = Field(min_length=1, max_length=600)
    reasoning: str | None = Field(default=None, max_length=2400)
    # What the model could not determine. Analyst-only.
    uncertainty: str | None = Field(default=None, max_length=UNCERTAINTY_MAX_CHARS)

    # Set by the runtime after validation. Private attributes are never populated
    # from input, so model output cannot claim it needed no retry or was available.
    _retried: bool = PrivateAttr(default=False)
    _unavailable: bool = PrivateAttr(default=False)

    @field_validator("confidence", mode="before")
    @classmethod
    def lenient_confidence(cls, value: Any) -> Confidence:
        return coerce_confidence(value)

    @field_validator("uncertainty", mode="before")
    @classmethod
    def cap_uncertainty(cls, value: Any) -> Any:
        # An analyst-only note running long is not worth discarding the triage over.
        if isinstance(value, str):
            return value[:UNCERTAINTY_MAX_CHARS] or None
        return value

    @property
    def retried(self) -> bool:
        return self._retried

    @property
    def unavailable(self) -> bool:
        return self._unavailable

    def with_runtime_flags(self, *, retried: bool = False, unavailable: bool = False) -> "TriageResult":
        copy = self.model_copy()
        copy._retried, copy._unavailable = retried, unavailable
        return copy


class ConfidenceReason(BaseModel):
    """One code check that capped confidence. Analyst-only."""
    code: str
    detail: str


class AssessedTriage(TriageResult):
    """A TriageResult after the code-side controls: sensor floor, confidence cap and
    guidance tier. These extra fields are computed by triage.service, never parsed
    from model output (runtimes validate into TriageResult, which drops them)."""
    # `model_confidence` is a domain name, not a Pydantic internal.
    model_config = ConfigDict(protected_namespaces=())

    model_confidence: Confidence | None = None
    confidence_reasons: list[ConfidenceReason] = Field(default_factory=list)
    guidance_tier: GuidanceTier


class TriagePublic(BaseModel):
    """Triage fields an owner may see. Deliberately has no `reasoning`,
    `uncertainty`, `model_confidence` or `confidence_reasons`."""
    severity: Severity
    confidence: Confidence
    guidance_tier: GuidanceTier
    explanation: str
    recommended_action: str


class AlertDetail(BaseModel):
    id: int
    source: Source
    timestamp: datetime
    title: str
    source_ip: str | None
    destination_ip: str | None
    device: str | None
    rule_id: str | None
    mitre: list[str]
    raw: dict[str, Any]
    status: AlertStatus
    duplicate_count: int
    sensor_severity: Severity = Severity.UNKNOWN
    triage: AssessedTriage | None


class AlertDetailOwner(BaseModel):
    """Owner-facing shape of an alert.

    README places technical evidence at analyst level and above, so the raw sensor
    record, the detection rule id and the analyst reasoning are absent from this
    model entirely. `from_detail` filters through the model itself, so adding a
    field to AlertDetail can never leak it here by accident.
    """
    id: int
    source: Source
    timestamp: datetime
    title: str
    source_ip: str | None
    destination_ip: str | None
    device: str | None
    mitre: list[str]
    status: AlertStatus
    duplicate_count: int
    sensor_severity: Severity = Severity.UNKNOWN
    triage: TriagePublic | None

    @classmethod
    def from_detail(cls, detail: AlertDetail) -> "AlertDetailOwner":
        # Pydantic ignores unknown keys by default, so `raw`, `rule_id`,
        # `triage.reasoning`, `triage.uncertainty`, `triage.model_confidence` and
        # `triage.confidence_reasons` are dropped by validation rather than by hand.
        return cls.model_validate(detail.model_dump())


# "Ask LightHouse" chat. The limits keep a whole request inside the local model's
# 4,096-token context and bound how long one request can hold the single
# llama.cpp context that every chat shares.
CHAT_MAX_MESSAGES = 12
CHAT_MESSAGE_MAX_CHARS = 2000
CHAT_TITLE_QUESTION_MAX_CHARS = 500


class ChatMessage(BaseModel):
    """One turn of chat history as the dashboard keeps it. Both roles come from the
    browser, so an "assistant" turn is no more trusted than a "user" one."""
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=CHAT_MESSAGE_MAX_CHARS)

    @field_validator("content")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("message must not be blank")
        return value


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=CHAT_MAX_MESSAGES)
    # Optional focus. The server reads the alert itself; the browser never supplies
    # alert text as context.
    alert_id: int | None = None

    @model_validator(mode="after")
    def ends_with_a_question(self) -> "ChatRequest":
        if self.messages[-1].role != "user":
            raise ValueError("the last message must be from the user")
        return self


class ChatReply(BaseModel):
    reply: str
    # False when the local model could not answer; `reply` is then a fixed message.
    available: bool


class ChatTitleRequest(BaseModel):
    question: str = Field(min_length=1, max_length=CHAT_TITLE_QUESTION_MAX_CHARS)


class ChatTitle(BaseModel):
    # None when the model is unavailable or its title failed validation; the
    # dashboard keeps its own fallback title.
    title: str | None


# Admin page "AI instructions": free text the business's administrator writes for
# the AI. Capped so the notes cannot crowd the alert context and the question out of
# the local model's 4,096-token window, and because every character is re-read
# before each first answer on a slow CPU.
AI_INSTRUCTIONS_MAX_CHARS = 1000
# Everything below a space except newline and tab, plus DEL and the C1 range. They
# have no meaning in a note and could hide text from the admin reading it back.
_NOTE_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def normalize_note(value: str) -> str:
    """One canonical form for an admin note, used both when it is saved and when it
    is read back for a prompt (the database is not trusted to hold a clean value)."""
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return _NOTE_CONTROL_CHARS.sub("", value).strip()


class AIInstructions(BaseModel):
    """What PUT /api/admin/ai-instructions accepts. An empty string means "not set".

    The length limit applies after normalization, so trailing blank lines or stray
    control characters never push a note over it.
    """
    business: str = Field(max_length=AI_INSTRUCTIONS_MAX_CHARS)
    style: str = Field(max_length=AI_INSTRUCTIONS_MAX_CHARS)

    @field_validator("business", "style", mode="before")
    @classmethod
    def normalized(cls, value: Any) -> Any:
        # Non-strings fall through to the type check and are rejected there.
        return normalize_note(value) if isinstance(value, str) else value


class AIInstructionsView(AIInstructions):
    """GET and PUT reply: the saved values plus the limit the dashboard enforces."""
    max_chars: int = AI_INSTRUCTIONS_MAX_CHARS
