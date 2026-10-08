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
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Iterator, Protocol

logger = logging.getLogger(__name__)

# Stopped in this order and started in reverse: ingestion depends on Suricata.
MONITORING_SERVICES = ("LightHouse-Ingestion", "LightHouse-Suricata")


class Services(Protocol):
    def state(self, name: str) -> str | None: ...        # running/stopped/starting/stopping/other, None if missing
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
    paused = available and not any(state in ("running", "starting") for state in states.values())
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
