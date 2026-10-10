from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from ..schema import NormalizedAlert, Severity, Source

logger = logging.getLogger(__name__)

def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def suricata_severity(alert: dict[str, Any]) -> Severity:
    """Suricata counts down: 1 is the most severe. Anything absent or odd is LOW,
    which is a floor that never raises risk on its own."""
    level = _as_int(alert.get("severity"))
    if level is None:
        return Severity.LOW
    if level <= 1:
        return Severity.HIGH
    if level == 2:
        return Severity.MEDIUM
    return Severity.LOW


def wazuh_severity(rule: dict[str, Any]) -> Severity:
    """Wazuh rule levels run 0-15 and count up."""
    level = _as_int(rule.get("level"))
    if level is None:
        return Severity.LOW
    if level >= 12:
        return Severity.CRITICAL
    if level >= 10:
        return Severity.HIGH
    if level >= 7:
        return Severity.MEDIUM
    return Severity.LOW


MITRE_MAX_IDS = 20


def suricata_mitre(alert: dict[str, Any]) -> list[str]:
    """MITRE ATT&CK technique ids from a Suricata alert's rule metadata.

    Emerging Threats rules write `metadata: {"mitre_technique_id": ["T1046"]}`
    (every metadata value is a list of strings); `metadata.mitre` as a list of
    {"technique_id": ...} objects is accepted too. The record is attacker-shaped,
    so anything else (null, a list, numbers) yields nothing instead of raising.
    """
    metadata = alert.get("metadata")
    if not isinstance(metadata, dict):
        return []
    found: list[Any] = []
    mitre = metadata.get("mitre")
    if isinstance(mitre, list):
        found.extend(entry.get("technique_id") for entry in mitre if isinstance(entry, dict))
    technique = metadata.get("mitre_technique_id")
    found.extend(technique if isinstance(technique, list) else [technique])
    ids = [value.strip() for value in found if isinstance(value, str) and value.strip()]
    return list(dict.fromkeys(ids))[:MITRE_MAX_IDS]


def parse_record(source: Source, raw: dict[str, Any]) -> NormalizedAlert:
    """Convert native JSON records into the one shape used downstream.

    sensor_severity is set here, from the sensor's own rating, and is the floor the
    triage model is not permitted to undercut.
    """
    if source is Source.SURICATA:
        alert = raw.get("alert")
        if not isinstance(alert, dict):
            event_type = raw.get("event_type")
            if event_type not in {"flow", "http", "tls", "dns", "smb"}:
                raise ValueError("Suricata record has no alert object or supported protocol event")
            return NormalizedAlert(source=source,
                source_event_id=str(raw.get("flow_id", "")) or None,
                timestamp=raw["timestamp"], title=f"Suricata {event_type} activity",
                source_ip=raw.get("src_ip"), destination_ip=raw.get("dest_ip"),
                device=raw.get("src_ip"), rule_id=f"eve:{event_type}",
                sensor_severity=Severity.LOW, raw=raw)
        mitre = suricata_mitre(alert)
        return NormalizedAlert(source=source, source_event_id=str(raw.get("flow_id", "")) or None,
            timestamp=raw["timestamp"], title=alert.get("signature", "Unnamed Suricata alert"), source_ip=raw.get("src_ip"),
            destination_ip=raw.get("dest_ip"), rule_id=str(alert.get("signature_id", "")) or None, mitre=mitre,
            sensor_severity=suricata_severity(alert), raw=raw)
    if source is Source.ZEEK:
        if not raw.get("ts"):
            raise ValueError("Zeek record has no ts")
        note = raw.get("note") or raw.get("service") or raw.get("_path")
        # Zeek logs carry no severity rating, so they set no floor.
        return NormalizedAlert(source=source, source_event_id=raw.get("uid"), timestamp=raw["ts"],
            title=f"Zeek {note or 'network activity'}", source_ip=raw.get("id.orig_h"), destination_ip=raw.get("id.resp_h"),
            device=raw.get("id.orig_h"), sensor_severity=Severity.LOW, raw=raw)
    if source is Source.WAZUH:
        rule = raw.get("rule")
        if not isinstance(rule, dict) or not raw.get("timestamp"):
            raise ValueError("Wazuh record requires timestamp and rule")
        mitre = [item.get("id") for item in rule.get("mitre", {}).get("technique", []) if item.get("id")]
        return NormalizedAlert(source=source, source_event_id=str(raw.get("id", "")) or None, timestamp=raw["timestamp"],
            title=rule.get("description", "Unnamed Wazuh alert"), source_ip=raw.get("data", {}).get("srcip"),
            device=raw.get("agent", {}).get("name"), rule_id=str(rule.get("id", "")) or None, mitre=mitre,
            sensor_severity=wazuh_severity(rule), raw=raw)
    raise ValueError(f"Unsupported source: {source}")


def parse_line(source: Source, line: str, line_number: int) -> NormalizedAlert | None:
    """One sensor log line, or None (logged) when it cannot be used.

    Catches everything, not just the expected parse errors: the line is
    attacker-controlled, and one shaped to raise something unforeseen (a JSON array,
    a null where an object belongs) must cost that record, never the reader. The
    line itself is never logged at warning level, for the same reason.
    """
    try:
        return parse_record(source, json.loads(line))
    except Exception as error:
        logger.warning("Skipping unreadable %s record (line %d read since the log was opened): %s",
                       source, line_number, type(error).__name__)
        logger.debug("Unreadable %s record detail", source, exc_info=True)
        return None


async def tail_json_lines(path: Path, source: Source) -> AsyncIterator[NormalizedAlert]:
    """Tail a JSON-lines file. Caller owns retry/restart policy for rotated files."""
    # errors="replace": a stray non-UTF-8 byte spoils one record, not the reader.
    with path.open(encoding="utf-8", errors="replace") as handle:
        handle.seek(0, 2)
        pending = ""
        lines = 0
        while True:
            chunk = handle.readline()
            if not chunk:
                await asyncio.sleep(0.5)
                continue
            pending += chunk
            if not pending.endswith("\n"):
                # The sensor is still writing this record; wait for the newline
                # rather than trying to parse half a JSON object.
                continue
            line, pending = pending, ""
            lines += 1
            alert = parse_line(source, line, lines)
            if alert is not None:
                yield alert
