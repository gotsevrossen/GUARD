"""Pause and resume LightHouse's background monitoring.

For a laptop that leaves the office: pausing stops the services that capture and
triage (Suricata and ingestion, the CPU- and memory-heavy ones) and switches them
to manual start, so a restart keeps them off until someone resumes. The API
service is never stopped, or nothing could turn monitoring back on; it is small
when idle. Admin only, enforced in triage/api.py, because a paused monitor is
exactly what an intruder would want.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator, Protocol

logger = logging.getLogger(__name__)

# Stopped in this order and started in reverse: ingestion depends on Suricata.
MONITORING_SERVICES = ("LightHouse-Ingestion", "LightHouse-Suricata")


class Services(Protocol):
    def state(self, name: str) -> str | None: ...        # running/stopped/starting/stopping/other, None if missing
    def set_automatic(self, name: str, automatic: bool) -> None: ...
    def stop(self, name: str) -> None: ...
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
