"""Is a newer LightHouse release out?

Asks GitHub's public releases API for the latest published release of the
LightHouse repository and compares its tag (e.g. `v0.2.0`) with the installed
version. Sends nothing about this computer or its monitoring data: a plain GET of a
public URL. Cached so that reloading the dashboard does not hit GitHub's
unauthenticated rate limit. Offline, it simply reports no update.

Installing (an admin asks from the dashboard): the installer and its checksum file
are downloaded from that release only, the SHA-256 must match, and only then is the
installer started silently as SYSTEM through a one-time scheduled task. Setup stops
the API service during an upgrade, which would kill any child process of it; a
scheduled task runs outside the service. Anyone who can publish a release on the
repository can therefore run code on every LightHouse computer: protect that
GitHub account with two-factor sign-in.

Releasing: bump `version` in pyproject.toml and `AppVersion` in lighthouse.iss,
build, and publish a GitHub release tagged `vX.Y.Z` with `LightHouse-Setup.exe`
and `LightHouse-Setup.exe.sha256` (both written by build.ps1) attached.
"""
from __future__ import annotations

import asyncio
import hashlib
from importlib import metadata
import json
import logging
from pathlib import Path
import re
import subprocess
import time
from typing import Callable
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

REPOSITORY = "gotsevrossen/LightHouse"
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPOSITORY}/releases/"
CACHE_SECONDS = 15 * 60
FAILURE_CACHE_SECONDS = 5 * 60

INSTALLER_NAME = "LightHouse-Setup.exe"
CHECKSUM_NAME = INSTALLER_NAME + ".sha256"
# Assets come only from this repository's release downloads; GitHub answers those
# with a redirect to its asset storage, the only other hosts allowed.
DOWNLOAD_PREFIX = f"https://github.com/{REPOSITORY}/releases/download/"
ASSET_HOSTS = frozenset({"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"})
MAX_REDIRECTS = 5
MAX_INSTALLER_BYTES = 2 * 1024 ** 3
MAX_CHECKSUM_BYTES = 1024
TASK_NAME = "LightHouse-Update"

_cache: dict = {"at": 0.0, "ttl": 0.0, "release": None}
# What the dashboard shows while an update runs: idle, downloading, installing, failed.
_install: dict = {"state": "idle", "error": None}
_install_task: asyncio.Task | None = None


class UpdateError(Exception):
    """A plain-English reason the update did not go ahead; shown to the admin."""


def installed_version() -> str:
    """The highest installed version record. An upgrade that merged files instead of
    replacing them left the old record beside the new one, and Python reads the first
    alphabetically: the install then claimed its old version and offered the same
    update forever. Setup now clears the runtime first; this is the second guard."""
    versions = [dist.version for dist in metadata.distributions(name="lighthouse-security-copilot")
                if version_tuple(dist.version) is not None]
    return max(versions, key=version_tuple) if versions else "0.0.0"


def version_tuple(value: object) -> tuple[int, int, int] | None:
    """`v1.2.3`, `1.2` or `1.2.3-beta` -> (1, 2, 3); None if it is not a version."""
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?", value.strip())
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


async def _latest_release(transport: httpx.AsyncBaseTransport | None = None) -> dict | None:
    async with httpx.AsyncClient(timeout=httpx.Timeout(8.0), follow_redirects=True, transport=transport) as client:
        response = await client.get(LATEST_RELEASE_API, headers={
            "Accept": "application/vnd.github+json", "User-Agent": f"LightHouse/{installed_version()}"})
    if response.status_code == 404:
        return None  # no releases published yet
    response.raise_for_status()
    body = response.json()
    return body if isinstance(body, dict) else None


def _asset_url(release: dict, name: str) -> str | None:
    for asset in release.get("assets") or []:
        if isinstance(asset, dict) and asset.get("name") == name:
            url = asset.get("browser_download_url")
            if isinstance(url, str) and url.startswith(DOWNLOAD_PREFIX):
                return url
    return None


async def check(transport: httpx.AsyncBaseTransport | None = None, now: float | None = None) -> dict:
    """{"current", "latest", "available", "url", "installable", "install"}. Never raises."""
    now = time.monotonic() if now is None else now
    if now - _cache["at"] >= _cache["ttl"]:
        try:
            _cache.update(release=await _latest_release(transport), at=now, ttl=CACHE_SECONDS)
        except Exception as error:
            logger.info("Update check failed: %s", type(error).__name__)
            _cache.update(release=None, at=now, ttl=FAILURE_CACHE_SECONDS)
    current = installed_version()
    release = _cache["release"] or {}
    latest, url = release.get("tag_name"), release.get("html_url")
    # Only this repository's release pages are ever offered as a link.
    if not (isinstance(url, str) and url.startswith(RELEASES_PAGE)):
        url = None
    newer = version_tuple(latest) is not None and version_tuple(current) is not None and \
        version_tuple(latest) > version_tuple(current)
    installable = bool(newer and url and _asset_url(release, INSTALLER_NAME) and _asset_url(release, CHECKSUM_NAME))
    install = dict(_install)
    # Checked first, always: it also forgets the record once the version has moved on.
    if install["state"] == "idle" and _attempt_failed(latest, current) and installable:
        # Never loop: the same update was installed from here and the version did
        # not change, so offer the release page with an explanation instead.
        installable = False
        install = {"state": "failed", "error": f"The last attempt to install {latest} did not finish. "
                                                "Download the installer from the release page and run it."}
    return {"current": current, "latest": latest if isinstance(latest, str) else None,
            "available": bool(newer and url), "url": url, "installable": installable,
            "install": install}


def _attempt_file() -> Path | None:
    install = install_dir()
    return install / "data" / "config" / "update-attempt.json" if install else None


def _record_attempt(latest: str, current: str) -> None:
    path = _attempt_file()
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"tag": latest, "from": current}), encoding="utf-8")


def _attempt_failed(latest: object, current: str) -> bool:
    """True when this exact update was started from here and the installed version is
    still the one it started from. A changed version means it worked: forget it."""
    path = _attempt_file()
    if path is None or not path.is_file():
        return False
    try:
        attempt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(attempt, dict) or attempt.get("from") != current:
        path.unlink(missing_ok=True)
        return False
    return attempt.get("tag") == latest


def install_dir() -> Path | None:
    """The installed app folder (`<install>\\runtime\\python.exe`), or None when this
    is not the installed service (e.g. a developer's copy), which must not update."""
    from .paths import install_root
    return install_root()


async def _fetch(client: httpx.AsyncClient, url: str, sink: Callable[[bytes], object], limit: int) -> None:
    """GET `url` into `sink`, following redirects only to GitHub's hosts over HTTPS
    and refusing anything bigger than `limit`."""
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in ASSET_HOSTS:
            raise UpdateError("The update was offered from an unexpected address, so it was not downloaded.")
        async with client.stream("GET", url) as response:
            if response.is_redirect and response.next_request is not None:
                url = str(response.next_request.url)
                continue
            if response.status_code != 200:
                raise UpdateError("GitHub did not provide the update. Try again later.")
            received = 0
            async for chunk in response.aiter_bytes():
                received += len(chunk)
                if received > limit:
                    raise UpdateError("The update file is larger than expected, so it was not used.")
                sink(chunk)
            return
    raise UpdateError("GitHub redirected the download too many times.")


def _expected_sha256(text: str) -> str:
    """`<64 hex>  LightHouse-Setup.exe` (sha256sum style) or the bare hash."""
    words = text.split()
    token = words[0].lower() if words else ""
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise UpdateError("The update's checksum file is not valid, so the update was not used.")
    return token


def _run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=30,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _launch(installer: Path, install: Path) -> None:
    """Run setup silently as SYSTEM through a one-time scheduled task, so it survives
    setup stopping this service. The task's script sits in the admin-only data
    folder next to the installer, so nobody else can change what SYSTEM runs."""
    log = install / "data" / "logs" / "update-install.log"
    if any(char in str(path) for path in (installer, log) for char in '%"^&'):
        raise UpdateError("The install folder's name stops automatic updates. Run the new installer by hand.")
    script = installer.parent / "run-update.cmd"
    script.write_text("@echo off\r\n"
                      f'"{installer}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG="{log}"\r\n'
                      # If setup failed half way, bring the dashboard back so the admin sees it.
                      "net start LightHouse-API >nul 2>&1\r\n", encoding="ascii")
    create = ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", f'"{script}"', "/SC", "ONCE",
              "/ST", "23:59", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"]
    for command in (create, ["schtasks", "/Run", "/TN", TASK_NAME]):
        result = _run(command)
        if result.returncode != 0:
            logger.error("schtasks %s failed: %s", command[1], (result.stderr or result.stdout).strip())
            if "denied" in (result.stderr or "").lower():
                raise PermissionError("not allowed to schedule the update")
            raise UpdateError("Windows could not start the update. Try again, or run the new installer by hand.")


async def _download_and_launch(transport: httpx.AsyncBaseTransport | None,
                               launch: Callable[[Path, Path], None]) -> None:
    install = install_dir()
    if install is None:
        raise PermissionError("not the installed LightHouse service")
    _cache.update(at=0.0, ttl=0.0)  # ask GitHub again: install exactly what is current
    info = await check(transport)
    release = _cache["release"] or {}
    installer_url, checksum_url = _asset_url(release, INSTALLER_NAME), _asset_url(release, CHECKSUM_NAME)
    if not (info["installable"] and installer_url and checksum_url):
        raise UpdateError("This release cannot be installed automatically. Download it from the release page.")
    folder = install / "data" / "updates"
    folder.mkdir(parents=True, exist_ok=True)
    partial = folder / (INSTALLER_NAME + ".part")
    digest = hashlib.sha256()
    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0), follow_redirects=False, transport=transport,
                                 headers={"User-Agent": f"LightHouse/{installed_version()}"}) as client:
        checksum = bytearray()
        await _fetch(client, checksum_url, checksum.extend, MAX_CHECKSUM_BYTES)
        expected = _expected_sha256(checksum.decode("ascii", "replace"))
        with partial.open("wb") as handle:
            def write(chunk: bytes) -> None:
                digest.update(chunk)
                handle.write(chunk)
            await _fetch(client, installer_url, write, MAX_INSTALLER_BYTES)
    if digest.hexdigest() != expected:
        partial.unlink(missing_ok=True)
        raise UpdateError("The downloaded update did not match its checksum, so it was not installed.")
    # Named from the parsed version, never the raw tag, so a tag cannot shape the path.
    version = ".".join(map(str, version_tuple(info["latest"]) or (0, 0, 0)))
    installer = folder / f"LightHouse-Setup-{version}.exe"
    installer.unlink(missing_ok=True)
    partial.replace(installer)
    await asyncio.to_thread(launch, installer, install)
    _record_attempt(info["latest"], info["current"])
    _install.update(state="installing", error=None)
    logger.warning("Installing LightHouse %s (verified SHA-256 %s)", info["latest"], expected)


async def start_install(transport: httpx.AsyncBaseTransport | None = None,
                        launch: Callable[[Path, Path], None] | None = None) -> dict:
    """Download, verify and start the update in the background; returns the state at
    once. Raises PermissionError when this copy may not update itself."""
    global _install_task
    if install_dir() is None:
        raise PermissionError("not the installed LightHouse service")
    if _install["state"] in ("downloading", "installing"):
        return dict(_install)  # a second click does not start a second download
    _install.update(state="downloading", error=None)

    async def run() -> None:
        try:
            await _download_and_launch(transport, launch or _launch)
        except UpdateError as error:
            _install.update(state="failed", error=str(error))
        except PermissionError:
            _install.update(state="failed", error="Only the installed LightHouse app can install updates.")
        except Exception:
            logger.exception("Update failed")
            _install.update(state="failed", error="The update could not be downloaded. Try again later.")
    _install_task = asyncio.get_running_loop().create_task(run(), name="update-install")
    return dict(_install)


def cleanup() -> None:
    """After an update: remove the one-time task and the downloaded installer.
    Skipped while the task still runs (setup is finishing). Never raises."""
    install = install_dir()
    if install is None:
        return
    try:
        query = _run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "CSV", "/NH"])
        if query.returncode != 0 or "running" in query.stdout.lower():
            return  # no update was started from the dashboard, or setup is still finishing
        _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
        for leftover in (install / "data" / "updates").glob("*"):
            leftover.unlink(missing_ok=True)
    except Exception:
        logger.warning("Could not tidy up after an update", exc_info=True)
