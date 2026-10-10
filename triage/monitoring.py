"""Pause and resume LightHouse's background monitoring, or shut it all down.

For a laptop that leaves the office: pausing stops the services that capture and
triage (Suricata and ingestion, the CPU- and memory-heavy ones) and switches them
to manual start, so a restart keeps them off until someone resumes. The API
service is never stopped, or nothing could turn monitoring back on; it is small
when idle. Admin only, enforced in triage/api.py, because a paused monitor is
exactly what an intruder would want.
"""
from __future__ import annotations

import json
import logging
import os
import time
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Literal, Protocol

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

# Stopped in this order and started in reverse: ingestion depends on Suricata.
MONITORING_SERVICES = ("LightHouse-Ingestion", "LightHouse-Suricata")


class Services(Protocol):
    def state(self, name: str) -> str | None: ...        # running/stopped/starting/stopping/other, None if missing
    def start_type(self, name: str) -> str | None: ...   # automatic/manual/disabled/other, None if unknown
    def set_automatic(self, name: str, automatic: bool) -> None: ...
    def stop(self, name: str) -> None: ...
    def request_stop(self, name: str) -> None: ...        # ask, don't wait (used to stop the API itself)
    def start(self, name: str) -> None: ...


ERROR_ACCESS_DENIED = 5


@contextmanager
def _access_checked() -> Iterator[None]:
    """Turn "access denied" into PermissionError. The installed API runs as SYSTEM
    and may change services; a copy started by hand (e.g. a developer's) may not,
    and should say so instead of suggesting a restart will help."""
    import pywintypes
    try:
        yield
    except pywintypes.error as error:
        if error.winerror == ERROR_ACCESS_DENIED:
            raise PermissionError("not allowed to change Windows services") from error
        raise


class WindowsServices:
    """The Service Control Manager, through pywin32 (the API runs as SYSTEM)."""

    def state(self, name: str) -> str | None:
        import pywintypes
        import win32service
        import win32serviceutil
        try:
            status = win32serviceutil.QueryServiceStatus(name)[1]
        except pywintypes.error:
            return None
        return {win32service.SERVICE_RUNNING: "running", win32service.SERVICE_STOPPED: "stopped",
                win32service.SERVICE_START_PENDING: "starting",
                win32service.SERVICE_STOP_PENDING: "stopping"}.get(status, "other")

    def start_type(self, name: str) -> str | None:
        """How Windows starts the service; None when it cannot be read. Delayed
        automatic start is still automatic."""
        import pywintypes
        import win32service
        try:
            manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
            try:
                service = win32service.OpenService(manager, name, win32service.SERVICE_QUERY_CONFIG)
                try:
                    start = win32service.QueryServiceConfig(service)[1]
                finally:
                    win32service.CloseServiceHandle(service)
            finally:
                win32service.CloseServiceHandle(manager)
        except pywintypes.error:
            return None
        return {win32service.SERVICE_AUTO_START: "automatic", win32service.SERVICE_DEMAND_START: "manual",
                win32service.SERVICE_DISABLED: "disabled"}.get(start, "other")

    def set_automatic(self, name: str, automatic: bool) -> None:
        import win32service
        with _access_checked():
            manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
            try:
                service = win32service.OpenService(manager, name, win32service.SERVICE_CHANGE_CONFIG)
                try:
                    start = win32service.SERVICE_AUTO_START if automatic else win32service.SERVICE_DEMAND_START
                    win32service.ChangeServiceConfig(service, win32service.SERVICE_NO_CHANGE, start,
                                                     win32service.SERVICE_NO_CHANGE, None, None, False,
                                                     None, None, None, None)
                finally:
                    win32service.CloseServiceHandle(service)
            finally:
                win32service.CloseServiceHandle(manager)

    def stop(self, name: str) -> None:
        import pywintypes
        import win32service
        import win32serviceutil
        with _access_checked():
            try:
                win32serviceutil.StopService(name)
            except pywintypes.error as error:
                if error.winerror != 1062:  # ERROR_SERVICE_NOT_ACTIVE: already stopped
                    raise
        win32serviceutil.WaitForServiceStatus(name, win32service.SERVICE_STOPPED, 60)

    def request_stop(self, name: str) -> None:
        import win32serviceutil
        with _access_checked():
            win32serviceutil.StopService(name)

    def start(self, name: str) -> None:
        import pywintypes
        import win32serviceutil
        with _access_checked():
            try:
                win32serviceutil.StartService(name)
            except pywintypes.error as error:
                if error.winerror != 1056:  # ERROR_SERVICE_ALREADY_RUNNING
                    raise


def status(services: Services | None) -> dict:
    """{"available", "paused", "services"}; unavailable when not installed as services."""
    if services is None:
        return {"available": False, "paused": False, "services": {}}
    states = {name: services.state(name) for name in MONITORING_SERVICES}
    available = all(state is not None for state in states.values())
    # Paused means an administrator paused it: pause() (and shut down) switch the
    # services to manual start. Stopped while still set to start automatically is a
    # crash or someone stopping them, and must show as "not reporting" so it gets
    # looked at, never as a deliberate pause. Disabled is not LightHouse's doing either.
    paused = (available and not any(state in ("running", "starting") for state in states.values())
              and all(services.start_type(name) == "manual" for name in MONITORING_SERVICES))
    return {"available": available, "paused": paused, "services": states}


def pause(services: Services) -> None:
    for name in MONITORING_SERVICES:
        services.set_automatic(name, False)
        services.stop(name)
    logger.warning("Monitoring paused by an administrator: %s stopped", ", ".join(MONITORING_SERVICES))


def resume(services: Services) -> None:
    for name in reversed(MONITORING_SERVICES):
        services.set_automatic(name, True)
        services.start(name)
    logger.warning("Monitoring resumed by an administrator")


# Shut down: everything LightHouse runs goes off, the API (and the chat AI it holds)
# included, and stays off after a restart until someone opens LightHouse again. The
# shortcut's launcher may start the API without admin rights (install.ps1 grants
# only that); the API then reads the marker, as SYSTEM, and puts back what was
# running. Windows' own logging, Sysmon (it writes into the event log, so LightHouse
# catches up on its return) and the Npcap driver are left alone.
API_SERVICE = "LightHouse-API"


def shutdown(services: Services, marker: Path) -> None:
    """Stop monitoring and set every LightHouse service to manual start. The caller
    stops the API itself last, once its reply has been sent."""
    # Monitoring comes back afterwards unless an administrator had paused it; a
    # service that had merely stopped is meant to be running and is started again.
    resume_monitoring = not status(services)["paused"]
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"resume_monitoring": resume_monitoring}), encoding="utf-8")
    try:
        for name in MONITORING_SERVICES:
            services.set_automatic(name, False)
            services.stop(name)
        services.set_automatic(API_SERVICE, False)
    except Exception:
        # Half shut down helps nobody: put back what was running, then report.
        with suppress(Exception):
            restore_after_shutdown(services, marker)
        raise
    logger.warning("LightHouse shut down by an administrator")


def restore_after_shutdown(services: Services, marker: Path) -> bool:
    """On API start: undo a shut down, if there was one. True when there was."""
    if not marker.is_file():
        return False
    try:
        resume_monitoring = json.loads(marker.read_text(encoding="utf-8")).get("resume_monitoring") is True
    except (OSError, ValueError, AttributeError):
        resume_monitoring = True  # unreadable: err on the side of monitoring
    services.set_automatic(API_SERVICE, True)
    if resume_monitoring:
        resume(services)
    marker.unlink(missing_ok=True)
    logger.warning("LightHouse started again after a shut down%s", "" if resume_monitoring else " (monitoring stays paused)")
    return True


# "Is LightHouse watching?": the status behind GET /api/status. Every role reads it,
# owners included, so it carries only a fixed state, a fixed sentence and a time per
# sensor. Never a path, process id, service or channel name, or anything read from a
# sensor record: that text is attacker-controlled. Each state rests on a "reader is
# alive" signal, not on alerts arriving, because a quiet network is not a failure.

SURICATA_SERVICE, INGESTION_SERVICE = MONITORING_SERVICES[1], MONITORING_SERVICES[0]
# Sysinternals registers the 64-bit build as Sysmon64 and the 32-bit one as Sysmon.
SYSMON_SERVICES = ("Sysmon64", "Sysmon")

# How long silence may last before a sensor counts as not reporting (minutes;
# LIGHTHOUSE_STATUS_READER_STALE_MINUTES and LIGHTHOUSE_STATUS_NETWORK_QUIET_MINUTES).
# An idle Event Log reader rewrites its health file every 30 s, but not while one
# alert is being triaged on a slow CPU or waits for a chat, so allow minutes.
# Suricata logs flow and DNS records for ordinary background traffic, so a connected
# computer's eve.json changes within minutes; half an hour of nothing means capture
# has stopped (wrong adapter, crashed engine) rather than a quiet network.
READER_STALE_MINUTES = 10
NETWORK_QUIET_MINUTES = 30

SensorId = Literal["network", "computer", "sign_ins", "local_ai"]
SensorState = Literal["working", "not_reporting", "paused", "not_installed"]
WATCHED: tuple[SensorId, ...] = ("network", "computer", "sign_ins")

# Fixed wording, written for the owner. The dashboard shows it as given.
MESSAGES: dict[str, dict[str, str]] = {
    "network": {
        "working": "Watching your network traffic.",
        "not_reporting": "The network sensor has stopped reporting. Ask your IT contact to check it.",
        "paused": "Paused by an administrator. Your network is not being watched.",
        "not_installed": "The network sensor is not set up on this computer.",
    },
    "computer": {
        "working": "Watching programs, files and settings on this computer.",
        "not_reporting": "The computer sensor has stopped reporting. Ask your IT contact to check it.",
        "paused": "Paused by an administrator. This computer is not being watched.",
        "not_installed": "The computer sensor is not set up on this computer. Ask your IT contact to install it.",
    },
    "sign_ins": {
        "working": "Watching sign-ins and account changes.",
        "not_reporting": "Sign-in monitoring has stopped reporting. Ask your IT contact to check it.",
        "paused": "Paused by an administrator. Sign-ins are not being watched.",
        "not_installed": "Sign-in monitoring is not set up on this computer.",
    },
    "local_ai": {
        "working": "Ready to explain new alerts in plain English.",
        "not_installed": "The built-in AI can't run on this computer, so new alerts are kept for a person to review.",
    },
}


class SensorStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: SensorId
    state: SensorState
    message: str
    last_heard: datetime | None = None


class WatchStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Over the three sensors only: a CPU that cannot run the AI is a permanent fact
    # of the machine, not monitoring that needs a check.
    overall: Literal["working", "attention", "paused"]
    sensors: list[SensorStatus]


def _limit_seconds(variable: str, default_minutes: int) -> float:
    """A bad value falls back to the default: the status page must still answer."""
    value = os.getenv(variable, "").strip()
    if not value:
        return default_minutes * 60.0
    try:
        minutes = int(value)
    except ValueError:
        minutes = 0
    if minutes < 1:
        logger.warning("%s must be a whole number of minutes, at least 1; using %d", variable, default_minutes)
        minutes = default_minutes
    return minutes * 60.0


# eve.json path -> (size, when that size was first seen). Windows can be slow to
# move a held-open log's modification time, while a size that changed between two
# looks is proof of writing either way.
_eve_progress: dict[str, tuple[int, float]] = {}


def network_activity(path: Path | None, now: float) -> float | None:
    """When Suricata last wrote its log (unix time), or None if there is none."""
    if path is None:
        return None
    try:
        info = path.stat()
    except OSError:
        return None
    previous = _eve_progress.get(str(path))
    if previous is None or previous[0] != info.st_size:
        _eve_progress[str(path)] = (info.st_size, now if previous is not None else info.st_mtime)
    return min(max(info.st_mtime, _eve_progress[str(path)][1]), now)


def _sensor(sensor: SensorId, state: SensorState, heard: float | None = None) -> SensorStatus:
    try:
        last_heard = datetime.fromtimestamp(heard, timezone.utc) if heard is not None and heard > 0 else None
    except (OverflowError, OSError, ValueError):
        last_heard = None
    return SensorStatus(id=sensor, state=state, message=MESSAGES[sensor][state], last_heard=last_heard)


def watch_status(services: Services | None, *, state_dir: Path, eve_path: Path | None, ai_ready: bool,
                 channels: tuple[str | None, str | None] | None = None, now: float | None = None) -> WatchStatus:
    """Whether each sensor is reporting, from the service states, the Event Log
    readers' health files and the network log's last write. Never raises for a
    missing or damaged file; it just counts as not heard from."""
    from .ingest.health import last_report
    from .ingest.windows import channel_settings
    now = time.time() if now is None else now
    sysmon_channel, security_channel = channels if channels is not None else channel_settings()
    monitoring = status(services)

    if services is None or not monitoring["available"]:
        # Not running as the installed app (a developer's copy): nothing is captured.
        sensors = [_sensor(sensor, "not_installed") for sensor in WATCHED]
    elif monitoring["paused"]:
        sensors = [_sensor(sensor, "paused") for sensor in WATCHED]
    else:
        def running(state: str | None) -> bool:
            return state in ("running", "starting")

        ingesting = running(monitoring["services"][INGESTION_SERVICE])
        reader_limit = _limit_seconds("LIGHTHOUSE_STATUS_READER_STALE_MINUTES", READER_STALE_MINUTES)
        network_limit = _limit_seconds("LIGHTHOUSE_STATUS_NETWORK_QUIET_MINUTES", NETWORK_QUIET_MINUTES)

        def reader(sensor: SensorId, channel: str | None, source_running: bool = True) -> SensorStatus:
            report = last_report(state_dir, channel) if channel is not None else None
            # A time from the future is a damaged file or a clock jump, not news.
            heard = report[1] if report is not None and report[1] <= now + 5 else None
            alive = (ingesting and source_running and heard is not None and now - heard <= reader_limit
                     and report is not None and report[0] in ("ok", "starting"))
            return _sensor(sensor, "working" if alive else "not_reporting", heard)

        network_heard = network_activity(eve_path, now)
        network_alive = (ingesting and running(monitoring["services"][SURICATA_SERVICE])
                         and network_heard is not None and now - network_heard <= network_limit)
        sysmon = [services.state(name) for name in SYSMON_SERVICES]
        sensors = [
            _sensor("network", "working" if network_alive else "not_reporting", network_heard),
            reader("computer", sysmon_channel, any(running(state) for state in sysmon))
            if sysmon_channel is not None and any(state is not None for state in sysmon)
            else _sensor("computer", "not_installed"),
            reader("sign_ins", security_channel) if security_channel is not None else _sensor("sign_ins", "not_installed"),
        ]

    sensors.append(_sensor("local_ai", "working" if ai_ready else "not_installed"))
    overall = ("paused" if monitoring["paused"] else
               "working" if all(sensor.state == "working" for sensor in sensors if sensor.id in WATCHED) else "attention")
    return WatchStatus(overall=overall, sensors=sensors)
