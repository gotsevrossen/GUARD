"""The Purdue GenAI Studio API key, kept only in an encrypted file.

Windows DPAPI with machine scope: the administrator who sets the key and the
LightHouse service (SYSTEM) are different accounts, so per-user DPAPI cannot
work. Machine scope alone would let any local account decrypt a copy, so the file
lives in LightHouse's data folder, which is Administrators/SYSTEM only, and an
app-specific entropy value is mixed in. A copy taken to another computer cannot
be decrypted. The key is never logged, returned by the API, put in an environment
variable, the registry, git, the browser or the installer.

    python -m triage.cloud_key set      # prompts with hidden input
    python -m triage.cloud_key status   # configured or not; never prints the key
    python -m triage.cloud_key clear
    python -m triage.cloud_key model gpt-oss:120b   # which GenAI Studio model answers

The model name is not secret and sits beside the key in plain JSON.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys

KEY_FILE_NAME = "genai-key.bin"
_ENTROPY = b"LightHouse/Purdue-GenAI-Studio/v1"
_MAX_KEY_CHARS = 512


def key_path() -> Path:
    """`LIGHTHOUSE_GENAI_KEY_FILE`, else the data folder of the install this Python
    runtime belongs to (`<install>\\runtime\\python.exe` -> `<install>\\data`).

    No `ProgramData` fallback: any user may create `C:\\ProgramData\\LightHouse` and
    own it, so an admin running the CLI with some other Python would have written the
    key into a folder that user controls (machine-scope DPAPI lets every local
    account decrypt it). Setup moves old data out of there anyway."""
    configured = os.getenv("LIGHTHOUSE_GENAI_KEY_FILE", "").strip()
    if configured:
        return Path(configured)
    return Path(sys.executable).resolve().parent.parent / "data" / "config" / KEY_FILE_NAME


def installed_runtime() -> bool:
    """Whether this Python is LightHouse's own (`<install>\\runtime\\python.exe`), whose
    data folder setup locked to Administrators and SYSTEM."""
    return (Path(sys.executable).resolve().parent.parent / "setup" / "install.ps1").is_file()


def _crypt(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(value: bytes) -> Blob:
        buffer = ctypes.create_string_buffer(value, len(value))
        return Blob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    source, entropy, result = blob(data), blob(_ENTROPY), Blob()
    flags = 0x1 | 0x4  # CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE
    call = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if protect:
        ok = call(ctypes.byref(source), "LightHouse GenAI Studio key", ctypes.byref(entropy), None, None,
                  flags, ctypes.byref(result))
    else:
        ok = call(ctypes.byref(source), None, ctypes.byref(entropy), None, None, flags, ctypes.byref(result))
    if not ok:
        raise OSError(ctypes.get_last_error(), "DPAPI could not process the GenAI Studio key")
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel32.LocalFree(result.pbData)


def clean_key(value: str) -> str:
    key = value.strip()
    if not key or len(key) > _MAX_KEY_CHARS or any(ch.isspace() for ch in key):
        raise ValueError("That does not look like a GenAI Studio API key.")
    return key


def save(key: str, path: Path | None = None) -> Path:
    path = path or key_path()
    if not path.parent.is_dir():
        raise FileNotFoundError(f"LightHouse's data folder was not found at {path.parent}.")
    temporary = path.with_suffix(".tmp")
    # Written inside the protected folder, so it inherits the admin/SYSTEM-only ACL.
    temporary.write_bytes(_crypt(clean_key(key).encode("utf-8"), protect=True))
    temporary.replace(path)
    return path


def load(path: Path | None = None) -> str | None:
    """The key, or None when none is set or it cannot be decrypted. Never raises."""
    if sys.platform != "win32":
        return None
    path = path or key_path()
    try:
        return clean_key(_crypt(path.read_bytes(), protect=False).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def clear(path: Path | None = None) -> bool:
    path = path or key_path()
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


MODEL_FILE_NAME = "genai.json"


def configured_model(path: Path | None = None) -> str | None:
    """The chosen GenAI Studio model name, or None for the default. Never raises."""
    path = path or key_path().with_name(MODEL_FILE_NAME)
    try:
        name = json.loads(path.read_text(encoding="utf-8")).get("model")
    except (OSError, ValueError, AttributeError):
        return None
    return name.strip() if isinstance(name, str) and 0 < len(name.strip()) <= 128 else None


def save_model(name: str, path: Path | None = None) -> None:
    """Remember which model answers chat (not secret, plain JSON beside the key)."""
    path = path or key_path().with_name(MODEL_FILE_NAME)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"model": name}), encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.cloud_key")
    parser.add_argument("command", choices=("set", "status", "clear", "model"))
    parser.add_argument("name", nargs="?", help="model name, for the 'model' command")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        print("The GenAI Studio key store is Windows-only.", file=sys.stderr)
        return 2
    if args.command != "status" and not (os.getenv("LIGHTHOUSE_GENAI_KEY_FILE", "").strip() or installed_runtime()):
        # Anywhere else the key could land in a folder other users can read.
        print("Run this with LightHouse's own Python, as administrator:\n"
              '  & "<install folder>\\runtime\\python.exe" -m triage.cloud_key ' + args.command, file=sys.stderr)
        return 2
    path = key_path()
    try:
        if args.command == "set":
            saved = save(getpass.getpass("GenAI Studio API key (input hidden): "), path)
            print(f"Saved, encrypted, to {saved}. Restart the dashboard service: Restart-Service LightHouse-API -Force, "
                  "then Start-Service LightHouse-Ingestion unless monitoring is paused")
        elif args.command == "model":
            if not args.name or len(args.name) > 128 or any(ch.isspace() for ch in args.name):
                print("Give one model name, as listed by GenAI Studio, e.g. gpt-oss:120b", file=sys.stderr)
                return 1
            save_model(args.name, path.with_name(MODEL_FILE_NAME))
            print(f"Chat model set to {args.name}. Restart the dashboard service: Restart-Service LightHouse-API -Force, "
                  "then Start-Service LightHouse-Ingestion unless monitoring is paused")
        elif args.command == "clear":
            print("Removed." if clear(path) else "No key was set.")
            print("Restart the dashboard service: Restart-Service LightHouse-API -Force, "
                  "then Start-Service LightHouse-Ingestion unless monitoring is paused")
        else:
            print(f"GenAI Studio key: {'configured' if load(path) else 'not configured'} ({path})")
            print(f"Chat model: {configured_model() or 'default'}")
    except PermissionError:
        print("Run this from PowerShell opened as administrator.", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
