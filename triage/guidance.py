"""How cautious the owner-facing output is, from final severity and final confidence.

The tier is computed here, in code, from values the model cannot raise (the
floored severity and the capped confidence). The dashboard renders a fixed banner
per tier, so text inside an alert can never remove or soften a "get help" message.
Tweak the table, not the function.
"""
from __future__ import annotations

from typing import Any

from .schema import Confidence, GuidanceTier, Severity, coerce_confidence, coerce_severity

_S, _C, _R, _H = GuidanceTier.STANDARD, GuidanceTier.CAUTION, GuidanceTier.REVIEW, GuidanceTier.GET_HELP

#                       high conf  medium conf  low conf
GUIDANCE_TIERS: dict[Severity, tuple[GuidanceTier, GuidanceTier, GuidanceTier]] = {
    Severity.LOW:      (_S, _S, _C),
    Severity.MEDIUM:   (_S, _C, _R),
    Severity.HIGH:     (_C, _R, _H),
    Severity.CRITICAL: (_R, _H, _H),
    Severity.UNKNOWN:  (_R, _R, _R),
}
_COLUMN = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


def guidance_tier(severity: Any, confidence: Any, sensor_floor: Any = Severity.LOW) -> GuidanceTier:
    """Pure lookup. Unrecognised inputs fall to UNKNOWN severity / LOW confidence.

    The sensor-floor escalation is a safety net: apply_sensor_floor already lifts an
    UNKNOWN result to the floor, so a stored UNKNOWN normally means a low floor.
    """
    severity, confidence = coerce_severity(severity), coerce_confidence(confidence)
    if severity is Severity.UNKNOWN and coerce_severity(sensor_floor) in (Severity.HIGH, Severity.CRITICAL):
        return GuidanceTier.GET_HELP
    return GUIDANCE_TIERS[severity][_COLUMN[confidence]]
