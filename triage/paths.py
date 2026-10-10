"""Filesystem locations that differ between the desktop build and the appliance.

The appliance runs from a checkout with a working directory it controls, so its
defaults are relative paths. The desktop build runs from a PyInstaller bundle,
launched from a menu entry with an arbitrary working directory, and writes to a
per-user data directory instead. Every path decision that differs between the two
lives here rather than being re-derived at each call site.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Directory name under the user's data home. Kept lowercase to match the
# systemd unit, the .desktop id and the Debian package name.
APP_DIR_NAME = "lighthouse"

# The generated admin password is dropped here on first run so the desktop
# window can show it. The desktop entry point deletes it once displayed.
FIRST_RUN_PASSWORD_FILE = "first-run-password.txt"


def _flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() not in ("", "0", "false", "no", "off")


def is_frozen() -> bool:
    """True inside a PyInstaller bundle."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def is_desktop() -> bool:
    """True when this process is the desktop application rather than the appliance.

    A frozen build is always the desktop app. Running from source, the flag has to
    be set explicitly, so importing triage.api in a test or on an appliance never
    silently relocates the database.
    """
    return is_frozen() or _flag("LIGHTHOUSE_DESKTOP")


def bundle_dir() -> Path:
    """Root for read-only files shipped with the application.

    PyInstaller extracts --add-data payloads to sys._MEIPASS, which is not the
    working directory; from source the repository root is the working directory,
    as every existing relative default already assumes.
    """
    if is_frozen():
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path.cwd()


def data_dir() -> Path:
    """Per-user writable directory, created 0700 on first use.

    Holds the database, which holds password hashes and live session tokens, so
    the mode matters as much here as it does on the appliance.
    """
    root = os.getenv("XDG_DATA_HOME", "").strip() or str(Path.home() / ".local" / "share")
    directory = Path(root) / APP_DIR_NAME
    directory.mkdir(parents=True, exist_ok=True)
    try:
        directory.chmod(0o700)
    except OSError:
        # Windows and some mounts cannot express this mode. Linux, the only
        # platform this build targets, can.
        pass
    return directory


def install_root() -> Path | None:
    """The Windows install folder this Python runtime belongs to
    (`<install>\\runtime\\python.exe`), or None for any other Python (a developer's
    copy, tests, Linux).

    Every default that must follow the install folder chosen in setup comes from
    here, never from `C:\\` or ProgramData: any user may create
    `C:\\ProgramData\\LightHouse` and own it, and the install may be on another drive.
    """
    install = Path(sys.executable).resolve().parent.parent
    if sys.platform != "win32" or not (install / "setup" / "install.ps1").is_file():
        return None
    return install


def first_run_handoff_configured() -> bool:
    """True when an installer chose where the one-time password goes.

    The Windows installer sets LIGHTHOUSE_FIRST_RUN_DIR to the Administrators/
    SYSTEM-only data directory: its services log to files that NSSM rotates and
    renames on every restart, so the stdout banner alone is easy to lose there.
    """
    return bool(os.getenv("LIGHTHOUSE_FIRST_RUN_DIR", "").strip())


def first_run_password_path() -> Path:
    """Where the one-time admin password is handed over on first run.

    Running from source, writer and reader are the same user and the per-user
    data directory is the obvious place. Installed, they are not: the background
    service runs as the `lighthouse` system account and the window runs as the
    person sitting at the machine, so the package points both at a handoff
    directory (0750 lighthouse:lighthouse, with the desktop user in that group)
    through LIGHTHOUSE_FIRST_RUN_DIR. The file is 0640 and is deleted the moment
    it has been displayed once.
    """
    override = os.getenv("LIGHTHOUSE_FIRST_RUN_DIR", "").strip()
    if override:
        return Path(override) / FIRST_RUN_PASSWORD_FILE
    return data_dir() / FIRST_RUN_PASSWORD_FILE
