from __future__ import annotations

import ipaddress
import re
from time import perf_counter

from .db import Database
from .guidance import guidance_tier
from .ingest.windows import SECURITY, SYSMON
from .llm import TriageModel, build_prompt, evidence_excerpt
from .schema import (AssessedTriage, Confidence, ConfidenceReason, NormalizedAlert, Severity, Source,
                     TriageResult, max_severity, min_confidence)


class TriageService:
    def __init__(self, db: Database, model: TriageModel):
        self.db, self.model = db, model

    async def process(self, alert: NormalizedAlert) -> tuple[int, bool]:
        duplicate = self.db.is_duplicate(alert)
        if duplicate:
            self.db.suppress(duplicate, alert.raw)
            return duplicate, True
        started = perf_counter()
        result = await self.model.triage(alert)
        latency_ms = int((perf_counter() - started) * 1000)
        return self.db.store(alert, assess(alert, result), type(self.model).__name__, latency_ms), False


def assess(alert: NormalizedAlert, result: TriageResult) -> AssessedTriage:
    """Every code-side control, in one place: severity floor, confidence cap, tier."""
    floored = apply_sensor_floor(alert, result)
    confidence, reasons = apply_confidence_cap(alert, result)
    return AssessedTriage(
        **floored.model_dump(exclude={"confidence"}),
        confidence=confidence,
        model_confidence=None if result.unavailable else result.confidence,
        confidence_reasons=reasons,
        guidance_tier=guidance_tier(floored.severity, confidence, alert.sensor_severity))


def apply_sensor_floor(alert: NormalizedAlert, result: TriageResult) -> TriageResult:
    """Clamp the model's severity to the floor the sensor already established.

    This is the control that survives prompt injection. Text inside an alert can
    steer the model's wording, and it can persuade the model to return "low" for an
    intrusion the attacker triggered themselves. It cannot move this line: the
    stored severity is max(sensor floor, model severity) by rank, computed outside
    the model. The model may raise severity and owns the plain-English text; it can
    never lower risk below what the detector reported.
    """
    final = max_severity(alert.sensor_severity, result.severity)
    if final == result.severity:
        return result
    return result.model_copy(update={"severity": final})


# Rules LightHouse has been exercised against: the fixture records in samples/
# (tests keep this in step with them) and every event the Windows reader maps. A
# model's confident read of a rule nobody here has seen it handle is still a guess.
SAMPLE_RULES = frozenset({(Source.SURICATA, "2001219"), (Source.WAZUH, "5710")})
KNOWN_RULES = frozenset({
    *SAMPLE_RULES,
    *((Source.WAZUH, f"Microsoft-Windows-Security-Auditing:{event_id}") for event_id in SECURITY),
    (Source.WAZUH, "Microsoft-Windows-Eventlog:1102"),
    *((Source.WAZUH, f"Microsoft-Windows-Sysmon:{event_id}") for event_id in SYSMON),
})

# Below this many characters of serialized raw record there is little more than a
# timestamp and an id to reason from. Both fixture records are ~260-300 characters.
THIN_EVIDENCE_CHARS = 120

# Severity steps for the jump check. UNKNOWN is left out: it asserts nothing about
# risk, so it is neither a jump nor a floor to jump from (an unknown floor counts as low).
_STEP = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}

_IPV4 = re.compile(r"(?<!\d)(?<!\d\.)\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
# No bare "js": "Node.js" in an explanation would read as an invented file and
# needlessly push an alert to "get help".
_FILE = re.compile(r"(?<![\w.-])[\w-]+(?:\.[\w-]+)*\.(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|vbe|jse|wsf|hta|"
                   r"scr|msi|lnk|jar)(?!\w)", re.IGNORECASE)


def _addresses(text: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    found = set()
    for match in (*_IPV4.findall(text), *_IPV6.findall(text)):
        try:
            found.add(ipaddress.ip_address(match))
        except ValueError:
            pass  # a version number or a clock time, not an address
    return found


def _unverified_references(alert: NormalizedAlert, result: TriageResult) -> list[str]:
    """Addresses and file names in the model's text that it was never shown.

    Compared against the prompt itself, so "present" means "the model saw it", not
    "somewhere in a raw record it was never given".
    """
    seen = build_prompt(alert)
    written = f"{result.explanation}\n{result.recommended_action}"
    known_addresses = _addresses(seen)
    missing = [str(address) for address in _addresses(written) - known_addresses]
    # Whole names, not substrings: "svchost.exe" must not pass because the
    # evidence contains "notsvchost.exe".
    known_files = {name.lower() for name in _FILE.findall(seen)}
    missing += [name for name in dict.fromkeys(_FILE.findall(written)) if name.lower() not in known_files]
    return missing


def apply_confidence_cap(alert: NormalizedAlert, result: TriageResult) -> tuple[Confidence, list[ConfidenceReason]]:
    """Final confidence = min(model's own confidence, every code check that fired).

    The same principle as the severity floor, pointed the other way: the model may
    lower its own confidence, code may lower it further, and nothing raises it.
    Text inside an alert can talk the model into "high"; it cannot switch these
    checks off. Every check that fires is recorded, even when the model was already
    less confident, so an analyst sees all the reasons. Reads the model's own
    severity, before the floor is applied.
    """
    confidence = result.confidence
    reasons: list[ConfidenceReason] = []

    def cap(ceiling: Confidence, code: str, detail: str) -> None:
        nonlocal confidence
        confidence = min_confidence(confidence, ceiling)
        reasons.append(ConfidenceReason(code=code, detail=detail[:200]))

    if result.unavailable:
        cap(Confidence.LOW, "model_unavailable", "No validated model output; kept for human review.")
    if (alert.source, alert.rule_id or "") not in KNOWN_RULES:
        # Windows events reuse the Wazuh alert shape internally; name what they are.
        origin = ("the Windows event log" if (alert.rule_id or "").startswith("Microsoft-Windows-")
                  else str(alert.source).capitalize())
        cap(Confidence.MEDIUM, "unfamiliar_rule",
            f"Rule {alert.rule_id or '(none)'} from {origin} is not in LightHouse's tested set.")
    evidence_chars = len(evidence_excerpt(alert))
    if evidence_chars < THIN_EVIDENCE_CHARS:
        cap(Confidence.MEDIUM, "thin_evidence",
            f"The sensor record is only {evidence_chars} characters (threshold {THIN_EVIDENCE_CHARS}).")
    if result.severity in _STEP and _STEP[result.severity] - _STEP.get(alert.sensor_severity, 0) >= 2:
        cap(Confidence.MEDIUM, "severity_jump",
            f"Model rated {result.severity}, two or more steps above the sensor's {alert.sensor_severity}.")
    for reference in _unverified_references(alert, result):
        cap(Confidence.LOW, "unverified_reference",
            f"The explanation mentions {reference!r}, which is not in the alert the model was shown.")
    if result.retried:
        cap(Confidence.MEDIUM, "needed_retry", "The first reply failed validation; the constrained retry was used.")
    return confidence, reasons
