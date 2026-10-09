from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import secrets
import sqlite3
from typing import Any

import bcrypt

from .dedupe import fingerprint
from .paths import data_dir, first_run_handoff_configured, first_run_password_path, is_desktop
from .guidance import guidance_tier
from .schema import AlertDetail, AlertStatus, AssessedTriage, NormalizedAlert

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, source TEXT NOT NULL, source_event_id TEXT,
  timestamp TEXT NOT NULL, title TEXT NOT NULL, source_ip TEXT, destination_ip TEXT, device TEXT,
  rule_id TEXT, mitre TEXT NOT NULL, raw TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  duplicate_count INTEGER NOT NULL DEFAULT 0, sensor_severity TEXT NOT NULL DEFAULT 'unknown', created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_alerts_filter ON alerts(timestamp DESC, status, source);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint, timestamp DESC);
CREATE TABLE IF NOT EXISTS triage_results (alert_id INTEGER PRIMARY KEY REFERENCES alerts(id), severity TEXT NOT NULL,
  explanation TEXT NOT NULL, recommended_action TEXT NOT NULL, reasoning TEXT, model TEXT, latency_ms INTEGER,
  confidence TEXT NOT NULL DEFAULT 'low', model_confidence TEXT, confidence_reasons TEXT NOT NULL DEFAULT '[]',
  guidance_tier TEXT, uncertainty TEXT);
CREATE TABLE IF NOT EXISTS alert_occurrences (id INTEGER PRIMARY KEY, alert_id INTEGER REFERENCES alerts(id),
  seen_at TEXT NOT NULL, raw TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash BLOB NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('owner','analyst','admin')), must_change_password INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS user_settings (user_id INTEGER NOT NULL REFERENCES users(id), key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(user_id,key));
"""

# bcrypt itself refuses passwords longer than this; bcrypt >= 4.1 raises ValueError
# rather than truncating, so length is checked here before bcrypt ever sees it.
MAX_PASSWORD_BYTES = 72
SESSION_HOURS = 8
# Keys in the settings table for the Admin page's "AI instructions".
AI_BUSINESS_KEY = "ai_business_context"
AI_STYLE_KEY = "ai_answer_style"
LEGACY_CONFIDENCE_REASONS = json.dumps([{"code": "legacy",
                                         "detail": "Triaged before LightHouse checked AI confidence."}])

# Compared against when the requested username does not exist, so that a failed
# login costs one bcrypt verification either way and cannot be used to tell
# whether an account is real. Built with the same cost factor as real hashes.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"lighthouse-no-such-account", bcrypt.gensalt())


class PasswordTooLongError(ValueError):
    """Raised for a password over MAX_PASSWORD_BYTES instead of letting bcrypt throw."""


def default_db_path() -> str:
    """Where the database lives when LIGHTHOUSE_DB_PATH does not say.

    The appliance keeps the relative path it has always used; the desktop build
    cannot, because it is launched from a menu entry with no meaningful working
    directory and may be running from a read-only bundle.
    """
    configured = os.getenv("LIGHTHOUSE_DB_PATH", "").strip()
    if configured:
        return configured
    if is_desktop():
        return str(data_dir() / "lighthouse.db")
    return "lighthouse.db"


def hash_token(token: str) -> str:
    """Session tokens are stored only as this digest, never in the clear."""
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str) -> bytes:
    encoded = password.encode()
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordTooLongError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes")
    return bcrypt.hashpw(encoded, bcrypt.gensalt())


def verify_password(password: str, password_hash: bytes) -> bool:
    """Never raises: an over-long or malformed input is simply a failed check."""
    encoded = password.encode()
    if len(encoded) > MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(encoded, password_hash)
    except (ValueError, TypeError):
        return False


def _write_first_run_password(password: str) -> None:
    """Hand the generated password to the desktop window through a one-shot file.

    On the appliance the operator reads it from the journal, which is fine for
    someone already at a terminal. The desktop app has no terminal to read, so the
    password is written 0600 to the per-user data directory and the desktop entry
    point displays it and deletes it. It is written only in desktop mode or when an
    installer configured the handoff directory (Windows), and only on the single
    run that generates it. On Windows it stays until the admin replaces the
    password; see discard_first_run_password.
    """
    path = first_run_password_path()
    # 0600 at creation time, and O_NOFOLLOW where the platform has it, so the
    # file cannot be pre-created as a symlink pointing the password somewhere
    # else. O_NOFOLLOW is POSIX-only; Linux is the platform this build targets.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    # 0640 rather than 0600 because when the background service writes this the
    # reader is a different account: the person at the machine, placed in the
    # lighthouse group by the package. The containing directory is 0750, so
    # "group" is that one person and not every local user.
    try:
        descriptor = os.open(str(path), flags, 0o640)
    except OSError:
        return
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(password)
    except OSError:
        # A failed write is not fatal: the banner on stdout is still the source
        # of truth, and the account can be re-provisioned.
        pass


def discard_first_run_password() -> None:
    """Delete the one-time password file once it has stopped being useful.

    Called after the seeded admin chooses their own password: from then on the
    file is only a stale credential on disk. Never raises; a leftover file holds a
    password that no longer works.
    """
    if not (is_desktop() or first_run_handoff_configured()):
        return
    try:
        first_run_password_path().unlink(missing_ok=True)
    except OSError:
        pass


def _print_seed_banner(password: str) -> None:
    """Shown once, on stdout only. This value is never logged."""
    line = "=" * 70
    print(line)
    print("LightHouse created the initial administrator account.")
    print("")
    print("    username: admin")
    print(f"    password: {password}")
    print("")
    print("This password is displayed once and is stored only as a bcrypt hash.")
    print("Log in and change it immediately: every request except login, logout")
    print("and the password change is refused until you do.")
    print(line, flush=True)


class Database:
    def __init__(self, path: str = "lighthouse.db"):
        self.path = path

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def initialize(self) -> str | None:
        """Create the schema and seed the admin account.

        Returns the generated admin password on the run that creates it, and None
        on every later run. The caller must not persist the returned value.
        """
        seeded: str | None = None
        with self.connect() as con:
            # Runs before any statement can open a transaction. WAL keeps ingest
            # writes from blocking dashboard reads.
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(SCHEMA_SQL)
            self._migrate(con)
            if not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
                seeded = secrets.token_urlsafe(18)
                con.execute(
                    "INSERT INTO users(username,password_hash,role,must_change_password) VALUES(?,?,?,1)",
                    ("admin", hash_password(seeded), "admin"),
                )
        self._restrict_permissions()
        if seeded:
            _print_seed_banner(seeded)
            if is_desktop() or first_run_handoff_configured():
                _write_first_run_password(seeded)
        return seeded

    def _migrate(self, con: sqlite3.Connection) -> None:
        """Add columns introduced after a database was first created."""
        user_columns = {row["name"] for row in con.execute("PRAGMA table_info(users)")}
        if "must_change_password" not in user_columns:
            con.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
        alert_columns = {row["name"] for row in con.execute("PRAGMA table_info(alerts)")}
        if "sensor_severity" not in alert_columns:
            con.execute("ALTER TABLE alerts ADD COLUMN sensor_severity TEXT NOT NULL DEFAULT 'unknown'")
        triage_columns = {row["name"] for row in con.execute("PRAGMA table_info(triage_results)")}
        # Rows triaged before confidence existed default to LOW: nothing checked them,
        # so claiming more would be the very overconfidence this feature removes.
        for column, definition in (("confidence", "TEXT NOT NULL DEFAULT 'low'"), ("model_confidence", "TEXT"),
                                   ("confidence_reasons", "TEXT NOT NULL DEFAULT '[]'"),
                                   ("guidance_tier", "TEXT"), ("uncertainty", "TEXT")):
            if column not in triage_columns:
                con.execute(f"ALTER TABLE triage_results ADD COLUMN {column} {definition}")
        pending = con.execute("SELECT t.alert_id,t.severity,t.confidence,a.sensor_severity FROM triage_results t "
                              "JOIN alerts a ON a.id=t.alert_id WHERE t.guidance_tier IS NULL").fetchall()
        for row in pending:
            con.execute("UPDATE triage_results SET guidance_tier=?, confidence_reasons=? WHERE alert_id=?",
                        (str(guidance_tier(row["severity"], row["confidence"], row["sensor_severity"])),
                         LEGACY_CONFIDENCE_REASONS, row["alert_id"]))

    def _restrict_permissions(self) -> None:
        """Owner-only on the database and its WAL sidecars: it holds password hashes."""
        if self.path == ":memory:":
            return
        for suffix in ("", "-wal", "-shm"):
            candidate = self.path + suffix
            try:
                if os.path.exists(candidate):
                    os.chmod(candidate, 0o600)
            except OSError:
                # Windows dev machines and some mounts cannot express this mode.
                # The Linux appliance can, which is the deployment that matters.
                pass

    def is_duplicate(self, alert: NormalizedAlert, window_minutes: int = 30) -> int | None:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
        with self.connect() as con:
            row = con.execute("SELECT id FROM alerts WHERE fingerprint=? AND timestamp>=? ORDER BY timestamp DESC LIMIT 1", (fingerprint(alert), cutoff)).fetchone()
            return int(row["id"]) if row else None

    def store(self, alert: NormalizedAlert, triage: AssessedTriage, model: str | None = None, latency_ms: int | None = None) -> int:
        """Takes only an AssessedTriage (see triage.service.assess), so nothing reaches
        the database without the severity floor and confidence cap applied."""
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as con:
            cur = con.execute(
                """INSERT INTO alerts(source,source_event_id,timestamp,title,source_ip,destination_ip,device,rule_id,mitre,raw,fingerprint,sensor_severity,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (alert.source, alert.source_event_id, alert.timestamp.isoformat(), alert.title, alert.source_ip,
                 alert.destination_ip, alert.device, alert.rule_id, json.dumps(alert.mitre), json.dumps(alert.raw),
                 fingerprint(alert), str(alert.sensor_severity), now))
            alert_id = cur.lastrowid
            con.execute(
                """INSERT INTO triage_results(alert_id,severity,explanation,recommended_action,reasoning,model,latency_ms,
                   confidence,model_confidence,confidence_reasons,guidance_tier,uncertainty) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (alert_id, str(triage.severity), triage.explanation, triage.recommended_action, triage.reasoning, model, latency_ms,
                 str(triage.confidence), str(triage.model_confidence) if triage.model_confidence else None,
                 json.dumps([reason.model_dump() for reason in triage.confidence_reasons]),
                 str(triage.guidance_tier), triage.uncertainty))
            return int(alert_id)

    def suppress(self, alert_id: int, raw: dict[str, Any]) -> None:
        with self.connect() as con:
            con.execute("INSERT INTO alert_occurrences(alert_id,seen_at,raw) VALUES(?,?,?)", (alert_id, datetime.now(timezone.utc).isoformat(), json.dumps(raw)))
            con.execute("UPDATE alerts SET duplicate_count=duplicate_count+1 WHERE id=?", (alert_id,))

    def list_alerts(self, severity: str | None = None, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        clauses, params = [], []
        if severity: clauses.append("t.severity=?"); params.append(severity)
        if status: clauses.append("a.status=?"); params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as con:
            rows = con.execute(f"SELECT a.id,a.source,a.timestamp,a.title,a.source_ip,a.destination_ip,a.device,a.status,a.duplicate_count,a.sensor_severity,t.severity,t.confidence,t.guidance_tier,t.explanation,t.recommended_action FROM alerts a JOIN triage_results t ON t.alert_id=a.id {where} ORDER BY a.timestamp DESC LIMIT ?", (*params, limit)).fetchall()
            return [dict(row) for row in rows]

    def get_alert(self, alert_id: int) -> AlertDetail | None:
        with self.connect() as con:
            row = con.execute("SELECT a.*,t.severity,t.explanation,t.recommended_action,t.reasoning,t.confidence,t.model_confidence,t.confidence_reasons,t.guidance_tier,t.uncertainty FROM alerts a LEFT JOIN triage_results t ON t.alert_id=a.id WHERE a.id=?", (alert_id,)).fetchone()
        if not row: return None
        triage = AssessedTriage(
            severity=row["severity"], explanation=row["explanation"], recommended_action=row["recommended_action"],
            reasoning=row["reasoning"], confidence=row["confidence"], model_confidence=row["model_confidence"],
            confidence_reasons=json.loads(row["confidence_reasons"] or "[]"), uncertainty=row["uncertainty"],
            guidance_tier=row["guidance_tier"] or guidance_tier(row["severity"], row["confidence"], row["sensor_severity"]),
        ) if row["severity"] else None
        return AlertDetail(id=row["id"], source=row["source"], timestamp=row["timestamp"], title=row["title"], source_ip=row["source_ip"],
                           destination_ip=row["destination_ip"], device=row["device"], rule_id=row["rule_id"], mitre=json.loads(row["mitre"]),
                           raw=json.loads(row["raw"]), status=row["status"], duplicate_count=row["duplicate_count"],
                           sensor_severity=row["sensor_severity"], triage=triage)

    def update_status(self, alert_id: int, status: AlertStatus) -> bool:
        with self.connect() as con:
            return con.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id)).rowcount == 1

    def trends(self) -> list[dict[str, Any]]:
        with self.connect() as con:
            return [dict(r) for r in con.execute("SELECT substr(a.timestamp,1,10) AS day,t.severity,COUNT(*) AS count FROM alerts a JOIN triage_results t ON t.alert_id=a.id GROUP BY day,t.severity ORDER BY day")]

    def devices(self) -> list[dict[str, Any]]:
        """Activity summary; Zeek records normally populate device with origin host."""
        with self.connect() as con:
            return [dict(r) for r in con.execute("SELECT COALESCE(device,source_ip,'Unknown') AS device, COUNT(*) AS events, MAX(timestamp) AS last_seen FROM alerts GROUP BY COALESCE(device,source_ip,'Unknown') ORDER BY events DESC LIMIT 50")]

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        """Return a new session on success, None otherwise.

        A bcrypt verification always runs, including for a username that does not
        exist, so neither the response time nor an exception discloses whether an
        account is real.
        """
        with self.connect() as con:
            row = con.execute("SELECT id,username,password_hash,role,must_change_password FROM users WHERE username=?", (username,)).fetchone()
            stored_hash = row["password_hash"] if row is not None else _DUMMY_PASSWORD_HASH
            password_ok = verify_password(password, stored_hash)
            if row is None or not password_ok:
                return None
            token = secrets.token_urlsafe(32)
            expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat()
            con.execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)", (hash_token(token), row["id"], expires))
            # The plaintext token is handed back here and nowhere else; only its
            # digest reaches the database.
            return {"token": token, "username": row["username"], "role": row["role"],
                    "must_change_password": bool(row["must_change_password"])}

    def user_for_token(self, token: str) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as con:
            con.execute("DELETE FROM sessions WHERE expires_at<?", (now,))
            row = con.execute("SELECT u.id,u.username,u.role,u.must_change_password FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (hash_token(token),)).fetchone()
        if not row: return None
        # The raw token travels with the user so a request can revoke its own session.
        return {"id": row["id"], "username": row["username"], "role": row["role"],
                "must_change_password": bool(row["must_change_password"]), "token": token}

    def revoke_token(self, token: str) -> bool:
        with self.connect() as con:
            return con.execute("DELETE FROM sessions WHERE token=?", (hash_token(token),)).rowcount > 0

    def revoke_user_sessions(self, user_id: int, except_token: str | None = None) -> int:
        with self.connect() as con:
            if except_token is None:
                cur = con.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            else:
                cur = con.execute("DELETE FROM sessions WHERE user_id=? AND token<>?", (user_id, hash_token(except_token)))
            return cur.rowcount

    def users(self) -> list[dict[str, Any]]:
        with self.connect() as con:
            return [{"id": r["id"], "username": r["username"], "role": r["role"], "must_change_password": bool(r["must_change_password"])}
                    for r in con.execute("SELECT id,username,role,must_change_password FROM users ORDER BY username")]

    def create_user(self, username: str, password: str, role: str, must_change_password: bool = False) -> None:
        password_hash = hash_password(password)
        with self.connect() as con:
            con.execute("INSERT INTO users(username,password_hash,role,must_change_password) VALUES(?,?,?,?)",
                        (username, password_hash, role, 1 if must_change_password else 0))

    def check_password(self, user_id: int, password: str) -> bool:
        with self.connect() as con:
            row = con.execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()
        return verify_password(password, row["password_hash"] if row is not None else _DUMMY_PASSWORD_HASH)

    def set_password(self, user_id: int, password: str, must_change_password: bool = False) -> bool:
        """Replace a user's password hash. Returns False when the user no longer exists."""
        password_hash = hash_password(password)
        with self.connect() as con:
            cur = con.execute("UPDATE users SET password_hash=?, must_change_password=? WHERE id=?",
                              (password_hash, 1 if must_change_password else 0, user_id))
            return cur.rowcount == 1

    def user_settings(self, username: str) -> dict[str, str]:
        with self.connect() as con:
            return {r["key"]: r["value"] for r in con.execute("SELECT s.key,s.value FROM user_settings s JOIN users u ON u.id=s.user_id WHERE u.username=?", (username,))}

    def set_user_setting(self, username: str, key: str, value: str) -> None:
        with self.connect() as con:
            con.execute("INSERT INTO user_settings(user_id,key,value) SELECT id,?,? FROM users WHERE username=? ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value", (key, value, username))

    def ai_instructions(self) -> dict[str, str]:
        """The admin's AI notes as stored, "" for any not set. Read straight from the
        database on every use: the ingestion service is a separate process from the
        API that saves them, and this is how a change reaches it without a restart."""
        with self.connect() as con:
            rows = {r["key"]: r["value"] for r in con.execute(
                "SELECT key,value FROM settings WHERE key IN (?,?)", (AI_BUSINESS_KEY, AI_STYLE_KEY))}
        return {"business": rows.get(AI_BUSINESS_KEY, ""), "style": rows.get(AI_STYLE_KEY, "")}

    def set_ai_instructions(self, business: str, style: str) -> None:
        """Both notes in one transaction, so triage never sees half an update."""
        with self.connect() as con:
            con.executemany("INSERT INTO settings(key,value) VALUES(?,?) "
                            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            ((AI_BUSINESS_KEY, business), (AI_STYLE_KEY, style)))
