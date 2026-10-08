from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import platform
import shutil
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .db import Database, PasswordTooLongError, default_db_path, discard_first_run_password
from .llm import CHAT_CONTEXT_MAX_ALERTS, TriageModel, answer_chat, suggest_title
from .paths import bundle_dir, is_desktop
from .schema import AlertDetailOwner, AlertStatus, ChatReply, ChatRequest, ChatTitle, ChatTitleRequest

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12
# bcrypt's own limit. Values above it are rejected, never silently truncated.
MAX_PASSWORD_LENGTH = 72
ALL_ROLES = ("owner", "analyst", "admin")


def _flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() not in ("", "0", "false", "no", "off")


db = Database(default_db_path())
db.initialize()


async def _ingestion_task() -> None:
    """Tail the configured sensor logs for the lifetime of the API process.

    Deliberately swallows everything below CancelledError. The desktop build runs
    ingestion inside the API process so there is one service to install and one to
    supervise, and the cost of that choice is exactly this: a parsing bug in a
    sensor record must not be allowed to propagate out of this task and take the
    dashboard down with it. A dead ingestion loop is a degraded install; a dead API
    is an install the owner cannot even log in to.
    """
    try:
        # Imported here rather than at module scope: triage.main pulls in the model
        # runtime and the readers, which the appliance's API process has no use for.
        from .main import build_service, configured_sources, run_ingestion, unreadable_sources

        configured = configured_sources()
        if not configured:
            logger.warning("No sensor log paths configured; live ingestion is not running.")
            return
        unreadable = unreadable_sources(configured)
        if unreadable:
            # Not fatal here, unlike the CLI: the dashboard is still worth serving
            # with a sensor misconfigured, and the owner has no terminal to read an
            # error on.
            logger.error("Cannot read configured sensor log: %s", "; ".join(unreadable))
            return
        await run_ingestion(build_service(mock=False), configured)
    except asyncio.CancelledError:
        raise
    except Exception:
        # The whole body, not just the tail loop: building the service and reading
        # the configuration can fail too, and an exception escaping this task would
        # be re-raised when the lifespan awaits it, turning a degraded install into
        # a failed shutdown.
        logger.exception("Live ingestion stopped; the API keeps serving without it.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background ingestion alongside the API, desktop build only.

    The appliance keeps ingestion in its own `python -m triage.main tail` process
    and its own systemd unit, so nothing starts here for it.
    """
    task = asyncio.create_task(_ingestion_task(), name="ingestion") if is_desktop() else None
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            # Belt and braces alongside the task's own handler: shutting the window
            # must never fail because ingestion did.
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


# The schema, the route table and the version string are only published when the
# operator explicitly asks for them. A LAN scanner gets nothing.
_dev_mode = _flag("LIGHTHOUSE_DEV")
app = FastAPI(
    title="LightHouse Local API",
    version="0.1.0",
    docs_url="/docs" if _dev_mode else None,
    redoc_url="/redoc" if _dev_mode else None,
    openapi_url="/openapi.json" if _dev_mode else None,
    lifespan=lifespan,
)

# Production serves the dashboard same-origin, so no CORS middleware is installed
# at all unless LIGHTHOUSE_CORS_ORIGINS names the origins that need it.
CORS_ORIGINS = [origin.strip() for origin in os.getenv("LIGHTHOUSE_CORS_ORIGINS", "").split(",") if origin.strip()]
if CORS_ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

security = HTTPBearer()


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    role: str


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class Setting(BaseModel): key: str; value: str
class StatusChange(BaseModel): status: AlertStatus


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    """Anything unexpected becomes one identical, detail-free 500.

    Without this, a failure that only occurs for a real account (an over-long
    password reaching bcrypt, for instance) is itself an account-existence oracle.
    """
    logger.exception("Unhandled error serving %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def current_user(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    user = db.user_for_token(credentials.credentials)
    if not user: raise HTTPException(401, "Invalid or expired session")
    return user


def active_user(user=Depends(current_user)):
    """A user who still owes a password change may not use the appliance.

    Only login, logout, the password change itself and /health skip this, and they
    do so by not depending on it.
    """
    if user["must_change_password"]:
        raise HTTPException(403, "Password change required")
    return user


def require(*roles: str):
    """Role gate. Every route that is not an auth or health route goes through here,
    so it also inherits the must-change-password check via active_user."""
    def check(user=Depends(active_user)):
        if user["role"] not in roles: raise HTTPException(403, "Insufficient role")
        return user
    return check


@app.post("/api/auth/login")
def login(body: Login):
    user = db.authenticate(body.username, body.password)
    if not user: raise HTTPException(401, "Invalid credentials")
    return user


@app.post("/api/auth/logout", status_code=204)
def logout(user=Depends(current_user)):
    db.revoke_token(user["token"])
    return Response(status_code=204)


@app.post("/api/auth/password")
def change_password(body: PasswordChange, user=Depends(current_user)):
    if not db.check_password(user["id"], body.current_password):
        raise HTTPException(401, "Current password is incorrect")
    try:
        db.set_password(user["id"], body.new_password)
    except PasswordTooLongError:
        raise HTTPException(422, f"Password must be at most {MAX_PASSWORD_LENGTH} bytes")
    # Keep this session, drop everywhere else the old password is still logged in.
    db.revoke_user_sessions(user["id"], except_token=user["token"])
    if user["username"] == "admin":
        # The seeded admin's one-time password is now useless; don't leave it on disk.
        discard_first_run_password()
    return {"ok": True}


@app.patch("/api/users/{user_id}/password")
def reset_password(user_id: int, body: PasswordReset, user=Depends(require("admin"))):
    try:
        # An admin-chosen password is known to someone other than its owner, so the
        # owner is required to replace it at next login.
        updated = db.set_password(user_id, body.new_password, must_change_password=True)
    except PasswordTooLongError:
        raise HTTPException(422, f"Password must be at most {MAX_PASSWORD_LENGTH} bytes")
    if not updated: raise HTTPException(404, "User not found")
    db.revoke_user_sessions(user_id)
    return {"ok": True}


@app.get("/api/alerts")
def alerts(severity: str | None = None, status: str | None = None, user=Depends(require(*ALL_ROLES))): return db.list_alerts(severity, status)


@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: int, user=Depends(require(*ALL_ROLES))):
    result = db.get_alert(alert_id)
    if not result: raise HTTPException(404, "Alert not found")
    if user["role"] == "owner":
        # Raw sensor evidence and analyst reasoning are filtered here, on the
        # server. The dashboard hiding the Advanced tab is presentation, not access
        # control.
        return AlertDetailOwner.from_detail(result)
    return result


@app.patch("/api/alerts/{alert_id}/status")
def change_status(alert_id: int, body: StatusChange, user=Depends(require(*ALL_ROLES))):
    if not db.update_status(alert_id, body.status): raise HTTPException(404, "Alert not found")
    return {"ok": True}


@app.get("/api/trends")
def trends(user=Depends(require(*ALL_ROLES))): return db.trends()


@app.get("/api/preferences")
def preferences(user=Depends(require(*ALL_ROLES))): return db.user_settings(user["username"])


@app.put("/api/preferences")
def set_preference(body: Setting, user=Depends(require(*ALL_ROLES))):
    if body.key not in {"notification_threshold", "alert_sensitivity"}: raise HTTPException(422, "Unsupported preference")
    db.set_user_setting(user["username"], body.key, body.value)
    return {"ok": True}


# Built on the first chat request, never at import or startup: the installer waits
# on /api/health, and API startup must stay fast. Building is cheap; the runtime
# itself loads the weights lazily, on the first chat it answers.
#
# On Windows the API and ingestion run as separate services, so this is a second
# model in a second process. llama.cpp memory-maps the GGUF (use_mmap), so the two
# processes share the ~2.5 GB of weights through the OS page cache instead of
# holding two copies; only the KV cache for the context window is per process.
_chat_model: TriageModel | None = None


def chat_model() -> TriageModel | None:
    """The cached chat model, or None when it cannot even be configured."""
    global _chat_model
    if _chat_model is None:
        try:
            # Imported here for the same reason as in _ingestion_task.
            from .main import build_model
            _chat_model = build_model(mock=False)
        except Exception as error:
            # Misconfiguration (an unknown backend, a bad numeric setting) must not
            # turn a chat into a 500; the dashboard shows the fixed unavailable text.
            logger.error("Local AI chat is unavailable: %s", error)
            return None
    return _chat_model


def _chat_alerts(alert_id: int | None) -> list[AlertDetailOwner] | None:
    """Alert context for a chat, in the owner-safe shape for every role. None when
    the requested alert does not exist.

    The owner shape even for analysts: chat answers are written for the owner, and
    raw records, rule ids and analyst reasoning are exactly the attacker-written or
    analyst-only text the prompt must not carry.
    """
    if alert_id is not None:
        detail = db.get_alert(alert_id)
        return None if detail is None else [AlertDetailOwner.from_detail(detail)]
    rows = db.list_alerts(status=str(AlertStatus.OPEN))
    # Stable sort: newest first stays the order within each group, get-help first,
    # matching the dashboard's own ordering.
    rows.sort(key=lambda row: row["guidance_tier"] != "get_help")
    alerts = []
    for row in rows[:CHAT_CONTEXT_MAX_ALERTS]:
        detail = db.get_alert(row["id"])
        if detail is not None:
            alerts.append(AlertDetailOwner.from_detail(detail))
    return alerts


@app.post("/api/chat", response_model=ChatReply)
async def chat(body: ChatRequest, user=Depends(require(*ALL_ROLES))) -> ChatReply:
    alerts = await asyncio.to_thread(_chat_alerts, body.alert_id)
    if alerts is None: raise HTTPException(404, "Alert not found")
    # Inference runs in a worker thread inside the model runtime; this await keeps
    # the event loop, and so every other dashboard request, responsive meanwhile.
    reply, available = await answer_chat(chat_model(), body.messages, alerts, focused=body.alert_id is not None)
    return ChatReply(reply=reply, available=available)


@app.post("/api/chat/title", response_model=ChatTitle)
async def chat_title(body: ChatTitleRequest, user=Depends(require(*ALL_ROLES))) -> ChatTitle:
    return ChatTitle(title=await suggest_title(chat_model(), body.question))


@app.get("/api/advanced/health")
def health(user=Depends(require("analyst", "admin"))):
    from .llm import model_backend, model_name
    try:
        backend, model = model_backend(), model_name()
    except ValueError:
        backend = model = "misconfigured"
    return {"database": "available", "model": model, "model_backend": backend, "platform": platform.platform(), "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None, "disk_free_bytes": shutil.disk_usage(".").free}


@app.get("/api/advanced/devices")
def devices(user=Depends(require("analyst", "admin"))): return db.devices()


@app.get("/api/advanced/ingestion")
def ingestion_health(user=Depends(require("analyst", "admin"))):
    from .ingest.health import snapshot
    return snapshot()


@app.get("/api/users")
def users(user=Depends(require("admin"))):
    return db.users()


@app.post("/api/users", status_code=201)
def create_user(body: UserCreate, user=Depends(require("admin"))):
    if body.role not in set(ALL_ROLES): raise HTTPException(422, "Invalid role")
    try:
        # The admin choosing this password knows it, so the owner of the account must
        # replace it at first login — same rule as an admin-driven password reset.
        db.create_user(body.username, body.password, body.role, must_change_password=True)
    except sqlite3.IntegrityError:
        # Only a constraint violation is a name collision. A full disk or a locked
        # database must not be reported as one.
        raise HTTPException(409, "Username already exists")
    except PasswordTooLongError:
        raise HTTPException(422, f"Password must be at most {MAX_PASSWORD_LENGTH} bytes")
    return {"ok": True}


@app.get("/health")
def healthcheck(): return {"ok": True}


@app.get("/api/health")
def api_healthcheck():
    """Unauthenticated liveness probe, under /api so the static mount cannot shadow it.

    The desktop launcher calls this before deciding whether to start its own
    server, so it has to answer before anybody has logged in. It therefore says
    nothing a caller on loopback could not already infer from the login screen —
    the detailed, fingerprintable view stays behind /api/advanced/health.
    """
    return {"ok": True}


# Mounted last so it can never shadow an /api route. In production the built
# dashboard is served from here, same-origin, instead of exposing the Vite dev
# server on the LAN. Absent in development, where the directory does not exist.
# bundle_dir() is the working directory from source and the PyInstaller extraction
# directory in a frozen build, where nothing is relative to the working directory.
STATIC_DIR = Path(os.getenv("LIGHTHOUSE_STATIC_DIR", "").strip() or bundle_dir() / "dashboard" / "dist")
if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="dashboard")
