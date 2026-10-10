"""Native Windows inputs; imports of pywin32 stay lazy for Linux installs/tests."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

from . import health
from .readers import parse_line, parse_record
from ..schema import Source

logger = logging.getLogger(__name__)
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SECURITY = {4624: ("Successful logon", 3), 4625: ("Failed logon", 7),
            4648: ("Explicit credentials logon", 3), 4672: ("Privileged logon", 3),
            4720: ("User account created", 7), 4726: ("User account deleted", 7),
            4732: ("Member added to local security group", 7),
            1102: ("Security audit log cleared", 10)}
SYSMON = {1: "Process created", 3: "Network connection", 6: "Driver loaded",
          8: "Remote thread created", 10: "Process access", 11: "File created",
          12: "Registry object changed", 13: "Registry value set", 22: "DNS query",
          25: "Process tampering", 26: "File deleted", 29: "Executable detected"}
# Per-occurrence identifiers, timestamps and ephemeral ports. They differ on every
# event (each logon attempt has a new IpPort/LogonId, each process a new GUID),
# so hashing them would make every event unique and switch deduplication off.
VOLATILE_FIELDS = frozenset({
    "UtcTime", "CreationUtcTime", "PreviousCreationUtcTime",
    "ProcessGuid", "ProcessId", "ParentProcessGuid", "ParentProcessId",
    "SourceProcessGuid", "SourceProcessGUID", "SourceProcessId", "SourceThreadId",
    "TargetProcessGuid", "TargetProcessGUID", "TargetProcessId", "NewThreadId", "StartAddress",
    "LogonGuid", "LogonId", "TargetLogonGuid", "SubjectLogonId", "TargetLogonId", "TargetLinkedLogonId",
    "SourcePort", "SourcePortName", "IpPort", "QueryResults"})


def channel_settings() -> tuple[str | None, str | None]:
    """(Sysmon, Security) channel names from the service settings; None where an
    empty value switched that input off. The one place these are read, so the
    readers and the owner's status page cannot disagree about what is watched."""
    return (os.getenv("LIGHTHOUSE_SYSMON_CHANNEL", "Microsoft-Windows-Sysmon/Operational").strip() or None,
            os.getenv("LIGHTHOUSE_SECURITY_CHANNEL", "Security").strip() or None)


def configured_channels() -> list[str]:
    return list(dict.fromkeys(value for value in channel_settings() if value))


def event_identity(xml: str) -> dict:
    root = ET.fromstring(xml)
    return {"id": int(root.findtext("e:System/e:EventRecordID", namespaces=NS)),
            "time": root.find("e:System/e:TimeCreated", NS).attrib["SystemTime"]}


def normalize_event(xml: str):
    """Adapt to the existing Wazuh host-alert shape, retaining native provenance.

    Windows event levels describe logging importance, not threat severity. Use
    explicit policy floors; routine telemetry remains LOW. No new DB/UI source
    enum is required, and no Wazuh process is used on Windows.
    """
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    event_id = int(system.findtext("e:EventID", namespaces=NS))
    channel = system.findtext("e:Channel", namespaces=NS)
    provider = system.find("e:Provider", NS).attrib["Name"]
    data = {item.attrib.get("Name", str(i)): item.text or ""
            for i, item in enumerate(root.findall("e:EventData/e:Data", NS))}
    # Eventlog 1102 uses UserData/LogFileCleared in a different XML namespace.
    user_data = root.find("e:UserData", NS)
    if user_data is not None:
        data.update({item.tag.rsplit("}", 1)[-1]: item.text or ""
                     for item in user_data.iter() if len(item) == 0})
    if provider == "Microsoft-Windows-Eventlog" and channel == "Security" and event_id == 1102:
        title, level = SECURITY[1102]
    elif provider == "Microsoft-Windows-Security-Auditing":
        if event_id not in SECURITY:
            return None
        title, level = SECURITY[event_id]
    elif provider == "Microsoft-Windows-Sysmon":
        title = SYSMON.get(event_id, f"Event {event_id}")
        level = 10 if event_id == 25 else 3
    else:
        return None
    identity = event_identity(xml)
    raw = {"timestamp": identity["time"],
           "id": f"{channel}:{identity['id']}:{identity['time']}",
           "rule": {"id": f"{provider}:{event_id}", "description": f"{provider}: {title}", "level": level},
           "agent": {"name": system.findtext("e:Computer", namespaces=NS)},
           "data": {"srcip": data.get("SourceIp") or data.get("IpAddress"),
                    "win": {"channel": channel, "provider": provider, "event_id": event_id,
                            "record_id": identity["id"], "eventdata": data}}}
    alert = parse_record(Source.WAZUH, raw)
    # Distinguish by what happened (command lines, images, accounts, target paths,
    # remote addresses), so repeats of one activity dedupe and different activity
    # on the same host does not.
    evidence = {key: value for key, value in data.items() if key not in VOLATILE_FIELDS}
    key = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
    return alert.model_copy(update={"destination_ip": data.get("DestinationIp"), "dedupe_key": key})


class EventLogReader:
    def __init__(self, channel: str):
        import win32evtlog
        import pywintypes
        self.api = win32evtlog
        self.error = pywintypes.error
        self.channel = channel

    def read(self, query="*", reverse=False, count=32):
        api = self.api
        flags = api.EvtQueryChannelPath | (api.EvtQueryReverseDirection if reverse else api.EvtQueryForwardDirection)
        handle = api.EvtQuery(self.channel, flags, query)
        try:
            try:
                events = api.EvtNext(handle, count)
            except self.error as error:
                if getattr(error, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                    return []
                raise
            try:
                return [api.EvtRender(event, api.EvtRenderEventXml) for event in events]
            finally:
                for event in events:
                    event.Close()
        finally:
            handle.Close()


def read_checkpoint(path: Path, channel: str) -> dict | None:
    """The last committed event, or None to start by following new events.

    A damaged checkpoint (empty after a hard reset, or not ours) must not stop
    ingestion of every channel. Starting fresh skips only events logged while the
    service was down; replaying the whole retained log instead could queue hours
    of model triage on a slow CPU.
    """
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict) and isinstance(value.get("id"), int) and isinstance(value.get("time"), str):
            return value
    except (OSError, ValueError):
        pass
    logger.warning("Checkpoint for %s is damaged; following new events from now on", channel)
    return None


async def tail_channel(service, channel: str, *, reader=None, state_dir=None, poll_seconds=1):
    reader = reader or EventLogReader(channel)
    directory = Path(state_dir or health.state_directory())
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / health.channel_filename(channel)
    status = health.ChannelHealth(directory, channel)
    status.set("starting")
    cursor = read_checkpoint(path, channel)

    while True:
        try:
            if cursor is None:
                # First start follows new events; subsequent starts resume after
                # the last committed event, including events emitted while down.
                latest = await asyncio.to_thread(reader.read, "*", True, 1)
                cursor = event_identity(latest[0]) if latest else {"id": 0, "time": ""}
                health.write_json(path, cursor)
            if cursor["id"]:
                anchor = await asyncio.to_thread(reader.read, f"*[System[EventRecordID={cursor['id']}]]", False, 1)
                if not anchor or event_identity(anchor[0]) != cursor:
                    logger.warning("%s cleared or rolled over; resuming retained events", channel)
                    cursor = {"id": 0, "time": ""}
            events = await asyncio.to_thread(reader.read, f"*[System[EventRecordID>{cursor['id']}]]")
            # A successful read proves channel access without waiting for model
            # triage of the backlog. After a failure, stay in error until a
            # pending event is actually processed.
            if not events or status.status != "error":
                status.set("ok")
            for xml in events:
                identity = event_identity(xml)
                try:
                    alert = normalize_event(xml)
                except (ValueError, KeyError, AttributeError, ET.ParseError):
                    logger.exception("Skipping malformed event in %s record %s", channel, identity["id"])
                    alert = None
                if alert is not None:
                    await service.process(alert)
                # A failed DB/model call never advances the checkpoint.
                health.write_json(path, identity)
                cursor = identity
                status.set("ok")
            if not events:
                await asyncio.sleep(poll_seconds)
        except asyncio.CancelledError:
            status.set("stopped")
            raise
        except Exception:
            status.set("error")
            logger.exception("Windows channel %s failed; retrying", channel)
            await asyncio.sleep(max(poll_seconds, 5))


@dataclass
class TailPosition:
    """Where a tail_windows_json_lines reader got to: the file it was reading and
    the offset just past the last whole record. Kept by the caller, so a reader
    restarted after a failure carries on from there instead of skipping to the end
    of the log and losing whatever was written in between."""
    identity: tuple[int, int] | None = None
    offset: int = 0


async def tail_windows_json_lines(path, source, position: TailPosition | None = None):
    """Wait for the sensor, follow partial writes and reopen on rotation/truncate."""
    handle = None
    identity = None
    pending = ""
    first = True
    lines = 0
    position = position if position is not None else TailPosition()
    try:
        while True:
            try:
                stat = path.stat()
                current = (stat.st_dev, stat.st_ino)
                if handle is None or current != identity or stat.st_size < handle.tell():
                    if handle is not None:
                        handle.close()
                    handle = _open_shared_log(path)
                    identity, pending, lines = current, "", 0
                    if first:
                        if position.identity == current and position.offset <= stat.st_size:
                            handle.seek(position.offset)  # resuming the same file
                        else:
                            handle.seek(0, 2)
                        first = False
                chunk = handle.readline()
                if chunk:
                    pending += chunk
                    if pending.endswith("\n"):
                        line, pending = pending, ""
                        lines += 1
                        position.identity, position.offset = identity, handle.tell()
                        alert = parse_line(source, line, lines)
                        if alert is not None:
                            yield alert
                    continue
            except OSError:
                if handle is not None:
                    handle.close()
                    handle = None
            await asyncio.sleep(0.5)
    finally:
        if handle is not None:
            handle.close()


def _open_shared_log(path):
    # errors="replace": a stray non-UTF-8 byte (a record cut by rotation, say) spoils
    # that one record. A decode error would instead escape readline() and, resumed
    # from the same offset, stop the reader on that byte for good.
    if sys.platform != "win32":
        return path.open(encoding="utf-8", errors="replace")
    import msvcrt
    import win32file
    import win32con
    import pywintypes
    try:
        native = win32file.CreateFile(str(path), win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None, win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL, None)
    except pywintypes.error as error:
        raise OSError(error.winerror, error.strerror, str(path)) from error
    fd = msvcrt.open_osfhandle(native.Detach(), os.O_RDONLY | os.O_BINARY)
    return os.fdopen(fd, encoding="utf-8", errors="replace")
