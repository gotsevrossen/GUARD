"""Reset a LightHouse sign-in when its password is lost, from the computer itself.

Passwords are stored only as bcrypt hashes, so a lost one cannot be shown; it can
only be replaced. This gives the account a new random password, prints it once,
signs the account out everywhere and makes it choose its own at next sign-in (the
same rule as an admin's reset in the dashboard). Needs Windows administrator
rights: the database sits in the Administrators/SYSTEM-only data folder, so anyone
who can run this could already replace the database itself.

    & "<install folder>\\runtime\\python.exe" -m triage.reset_password          # the admin account
    & "<install folder>\\runtime\\python.exe" -m triage.reset_password owner1   # any other account
"""
from __future__ import annotations

import argparse
import os
import secrets
import sqlite3
import sys
from pathlib import Path

from .db import Database
from .paths import FIRST_RUN_PASSWORD_FILE


def _install_data_dir() -> Path:
    """`<install>\\data` of the install this Python runtime belongs to."""
    return Path(sys.executable).resolve().parent.parent / "data"


def installed_runtime() -> bool:
    return (Path(sys.executable).resolve().parent.parent / "setup" / "install.ps1").is_file()


def db_path() -> Path:
    """`LIGHTHOUSE_DB_PATH`, else the installed data folder. No other fallback: a
    reset written to some other database would look like it worked and change nothing."""
    configured = os.getenv("LIGHTHOUSE_DB_PATH", "").strip()
    return Path(configured) if configured else _install_data_dir() / "lighthouse.db"


def reset(db: Database, username: str) -> str | None:
    """New one-time password for `username`, or None when there is no such account."""
    user = next((u for u in db.users() if u["username"] == username), None)
    if user is None:
        return None
    password = secrets.token_urlsafe(18)
    db.set_password(user["id"], password, must_change_password=True)
    db.revoke_user_sessions(user["id"])
    return password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.reset_password")
    parser.add_argument("username", nargs="?", default="admin", help="account to reset (default: admin)")
    args = parser.parse_args(argv)
    if not (os.getenv("LIGHTHOUSE_DB_PATH", "").strip() or installed_runtime()):
        print("Run this with LightHouse's own Python, as administrator:\n"
              '  & "<install folder>\\runtime\\python.exe" -m triage.reset_password ' + args.username, file=sys.stderr)
        return 2
    path = db_path()
    try:
        if not path.is_file():
            print(f"LightHouse's database was not found at {path}.", file=sys.stderr)
            return 1
        password = reset(Database(str(path)), args.username)
    except (PermissionError, sqlite3.OperationalError):
        print("Run this from PowerShell opened as administrator.", file=sys.stderr)
        return 1
    if password is None:
        print(f"There is no LightHouse account named {args.username!r}.", file=sys.stderr)
        return 1
    if args.username == "admin":
        # The original one-time password no longer works; don't leave it on disk.
        try:
            (path.parent / FIRST_RUN_PASSWORD_FILE).unlink(missing_ok=True)
        except OSError:
            pass
    print(f"New password for {args.username}: {password}")
    print("Sign in with it; LightHouse then asks you to choose your own.")
    print("Every place this account was signed in has been signed out.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
