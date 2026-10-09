from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import platform
import sys
import shutil
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .db import Database, PasswordTooLongError, default_db_path, discard_first_run_password
from .llm import (CHAT_CONTEXT_MAX_ALERTS, CHAT_SYSTEM_PROMPT, TriageModel, answer_chat, compose_chat_system_prompt,
                  stream_chat, suggest_title, warm_chat)
from .paths import bundle_dir, is_desktop
from .schema import (AI_INSTRUCTIONS_MAX_CHARS, AIInstructions, AIInstructionsView, AlertDetailOwner, AlertStatus,
                     ChatReply, ChatRequest, ChatTitle, ChatTitleRequest, normalize_note)

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


CHAT_PRELOAD_DELAY_SECONDS = 30


async def _preload_chat() -> None:
    """Load the local chat model and pre-read its instructions and the current
    alerts shortly after the service starts, so the owner's first question does not
    wait for either. Skipped when GenAI Studio answers chat or monitoring is
    paused (the owner asked for the laptop to be left alone). Never raises."""
    try:
        await asyncio.sleep(CHAT_PRELOAD_DELAY_SECONDS)
        from .llm import warm_chat
        from .monitoring import status
        if _uses_genai_studio() or status(_services)["paused"]:
            return
        model = chat_model()
        if model is not None:
            await warm_chat(model, await asyncio.to_thread(_chat_alerts, None) or [], focused=False,
                            system=await asyncio.to_thread(_chat_system_prompt))
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.warning("Chat preload failed; the first question will load the model instead", exc_info=True)


def _shutdown_marker() -> Path | None:
    """`<install>\\data\\config\\shutdown.json`; None outside the installed service."""
    from .updates import install_dir
    install = install_dir()
    return install / "data" / "config" / "shutdown.json" if install else None


async def _restore_after_shutdown() -> None:
    """Opened again after a shut down: back to automatic start, and monitoring
    resumes if it was running. Never raises."""
    try:
        marker = _shutdown_marker()
        if marker is not None and _services is not None:
            from .monitoring import restore_after_shutdown
            await asyncio.to_thread(restore_after_shutdown, _services, marker)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Could not restore LightHouse after a shut down; use Resume monitoring")


UPDATE_CLEANUP_DELAY_SECONDS = 10 * 60


async def _cleanup_after_update() -> None:
    """Remove the one-time update task and installer once setup has surely finished
    (setup restarts this service before it exits). Never raises."""
    try:
        await asyncio.sleep(UPDATE_CLEANUP_DELAY_SECONDS)
        from .updates import cleanup
        await asyncio.to_thread(cleanup)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.warning("Update cleanup failed", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background ingestion alongside the API, desktop build only.

    The appliance keeps ingestion in its own `python -m triage.main tail` process
    and its own systemd unit, so nothing starts here for it.
    """
    task = asyncio.create_task(_ingestion_task(), name="ingestion") if is_desktop() else None
    background = [asyncio.create_task(_restore_after_shutdown(), name="restore-after-shutdown"),
                  asyncio.create_task(_preload_chat(), name="chat-preload"),
                  asyncio.create_task(_cleanup_after_update(), name="update-cleanup")] \
        if sys.platform == "win32" else []
    try:
        yield
    finally:
        for job in background:
            job.cancel()
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
# The local runtime, kept across model switches so its loaded weights are reused.
_local_chat_model: TriageModel | None = None
# Whether a GenAI Studio key file existed when _chat_model was built.
_chat_key_stored = False


def chat_model() -> TriageModel | None:
    """The cached chat model, or None when it cannot even be configured."""
    global _chat_model, _local_chat_model, _chat_key_stored
    stored = _genai_key_stored()
    if _chat_model is not None and stored != _chat_key_stored:
        # A key was stored or cleared since: follow it now, not at the next service
        # restart. Above all, a cleared key must stop questions going out at once
        # (the cached GenAI Studio model holds the key in memory).
        _chat_model = None
    if _chat_model is None:
        if _local_chat_model is None:
            try:
                # Imported here for the same reason as in _ingestion_task.
                from .main import build_model
                _local_chat_model = build_model(mock=False)
            except Exception as error:
                # Misconfiguration (an unknown backend, a bad numeric setting) must not
                # turn a chat into a 500; the dashboard shows the fixed unavailable text.
                logger.error("Local AI chat is unavailable: %s", error)
                return None
        _chat_model, _chat_key_stored = _with_genai_studio(_local_chat_model), stored
    return _chat_model


def _with_genai_studio(local: TriageModel) -> TriageModel:
    """Opt-in: with a stored Purdue GenAI Studio key, and unless an admin chose to
    keep chat on this computer, chat answers come from GenAI Studio with the local
    model as the fallback. Otherwise nothing leaves this computer."""
    from .cloud_key import load
    from .cloud_model import LOCAL_CHOICE, PurdueChatModel, genai_model_name
    model = genai_model_name()
    key = load() if model != LOCAL_CHOICE else None
    if not key:
        return local
    logger.info("Chat answers come from Purdue GenAI Studio (%s); alert triage stays local", model)
    return PurdueChatModel(local, key, model)


def _genai_key_stored() -> bool:
    from .cloud_key import key_path
    return key_path().is_file()


def _uses_genai_studio() -> bool:
    from .cloud_model import LOCAL_CHOICE, genai_model_name
    return _genai_key_stored() and genai_model_name() != LOCAL_CHOICE


@app.get("/api/chat/provider")
def chat_provider(user=Depends(require(*ALL_ROLES))) -> dict[str, str]:
    """Who answers chat, so the dashboard can say whether questions leave this
    computer. Taken from the model that will actually answer, not from settings on
    disk, so the footer cannot say "local" while questions still go out."""
    from .cloud_model import PurdueChatModel
    return {"provider": "purdue" if isinstance(chat_model(), PurdueChatModel) else "local"}


def _windows_services():
    """The real Service Control Manager on Windows; None elsewhere (dev, tests)."""
    if sys.platform != "win32":
        return None
    from .monitoring import WindowsServices
    return WindowsServices()


_services = _windows_services()


class MonitoringChange(BaseModel):
    paused: bool


@app.get("/api/monitoring")
def monitoring_status(user=Depends(require(*ALL_ROLES))) -> dict:
    """Whether monitoring is running, so every role sees when it is paused."""
    from .monitoring import status
    return status(_services)


@app.post("/api/monitoring")
def change_monitoring(body: MonitoringChange, user=Depends(require("admin"))) -> dict:
    """Pause (e.g. taking the laptop home) or resume background monitoring. Admin
    only: a paused monitor is exactly what an intruder would want."""
    global _chat_model, _local_chat_model
    from .monitoring import pause, resume, status
    if not status(_services)["available"]:
        raise HTTPException(409, "Monitoring services are not installed on this computer")
    try:
        if body.paused:
            pause(_services)
            # Free the chat AI's memory too; it reloads on the next question.
            _chat_model = _local_chat_model = None
        else:
            resume(_services)
    except PermissionError:
        # Only the installed LightHouse-API service (SYSTEM) may do this, not a
        # copy someone started by hand.
        raise HTTPException(403, "Only the installed LightHouse app can pause or resume monitoring. "
                                 "This copy is not running as the LightHouse service.")
    except Exception:
        logger.exception("Could not %s monitoring", "pause" if body.paused else "resume")
        raise HTTPException(502, "Windows could not change the LightHouse services. Try again, or restart the computer.")
    logger.warning("Monitoring %s by %s", "paused" if body.paused else "resumed", user["username"])
    return status(_services)


SHUTDOWN_STOP_DELAY_SECONDS = 1.5


def _stop_api_soon() -> None:
    """Runs after the shut-down reply is sent. Stopping our own service ends this
    process, so it is the very last thing done."""
    time.sleep(SHUTDOWN_STOP_DELAY_SECONDS)
    from .monitoring import API_SERVICE
    try:
        _services.request_stop(API_SERVICE)
    except Exception:
        logger.exception("Could not stop the LightHouse-API service")


@app.post("/api/shutdown", status_code=202)
def shut_down(background: BackgroundTasks, user=Depends(require("admin"))) -> dict:
    """Shut LightHouse down: monitoring, the local AI and this service, until someone
    opens LightHouse again (see triage/monitoring.py). Admin only, like pausing."""
    global _chat_model, _local_chat_model
    from .monitoring import shutdown, status
    marker = _shutdown_marker()
    if marker is None or not status(_services)["available"]:
        raise HTTPException(403, "Only the installed LightHouse app can shut down. "
                                 "This copy is not running as the LightHouse service.")
    try:
        shutdown(_services, marker)
    except PermissionError:
        raise HTTPException(403, "Only the installed LightHouse app can shut down. "
                                 "This copy is not running as the LightHouse service.")
    except Exception:
        logger.exception("Could not shut down")
        raise HTTPException(502, "Windows could not stop the LightHouse services. Try again, or restart the computer.")
    _chat_model = _local_chat_model = None  # free the chat AI now; the process ends shortly
    logger.warning("Shut down by %s", user["username"])
    background.add_task(_stop_api_soon)
    return {"ok": True}


@app.get("/api/updates")
async def update_check(user=Depends(require("admin"))) -> dict:
    """Whether a newer LightHouse release exists on GitHub (checked at most every
    15 minutes; sends nothing about this computer). Admins install updates."""
    from .updates import check
    return await check()


@app.post("/api/updates/install", status_code=202)
async def update_install(user=Depends(require("admin"))) -> dict:
    """Download the newer release, verify its SHA-256 and install it silently (see
    triage/updates.py). Admin only: it replaces the code every service runs as
    SYSTEM. Progress comes back on GET /api/updates as `install`."""
    from .updates import start_install
    try:
        state = await start_install()
    except PermissionError:
        raise HTTPException(403, "Only the installed LightHouse app can install updates. "
                                 "This copy is not running as the LightHouse service.")
    logger.warning("Update requested by %s", user["username"])
    return state


class ChatModelChoice(BaseModel):
    model: str = Field(min_length=1, max_length=64)


@app.get("/api/chat/models")
def chat_models(user=Depends(require("admin"))) -> dict:
    """The curated chat models an admin may choose from, and the current one."""
    from .cloud_key import key_path
    from .cloud_model import GENAI_MODEL_CHOICES, genai_model_name
    return {"choices": GENAI_MODEL_CHOICES, "current": genai_model_name(), "key_configured": key_path().is_file()}


@app.put("/api/chat/model")
def set_chat_model(body: ChatModelChoice, user=Depends(require("admin"))) -> dict:
    """Switch the chat model; takes effect on the next question, no restart. Only
    the curated choices, since this decides where owners' questions are sent."""
    global _chat_model
    from .cloud_key import key_path, save_model
    from .cloud_model import GENAI_MODEL_CHOICES, LOCAL_CHOICE
    if body.model not in {choice["id"] for choice in GENAI_MODEL_CHOICES}:
        raise HTTPException(422, "Not one of the available chat models")
    if os.getenv("LIGHTHOUSE_GENAI_MODEL", "").strip():
        # The service setting wins over this choice; saying "switched" would be false,
        # and for "On this computer only" questions would still leave the machine.
        raise HTTPException(409, "The chat model is fixed by the LIGHTHOUSE_GENAI_MODEL service setting")
    if body.model != LOCAL_CHOICE and not key_path().is_file():
        raise HTTPException(409, "Set a Purdue GenAI Studio key first (see the README)")
    save_model(body.model)
    _chat_model = None  # rebuilt on the next question, around the same local runtime
    return {"ok": True, "current": body.model}


@app.get("/api/admin/ai-instructions", response_model=AIInstructionsView)
def ai_instructions(user=Depends(require("admin"))) -> AIInstructionsView:
    """The Admin page's "AI instructions". Admin only: the business note shapes
    every alert's triage, and both notes go into every chat answer."""
    return _saved_ai_instructions()


@app.put("/api/admin/ai-instructions", response_model=AIInstructionsView)
def set_ai_instructions(body: AIInstructions, user=Depends(require("admin"))) -> AIInstructionsView:
    """Save both notes. Chat uses them from the next question; the ingestion
    service from its next alert (it reads them per alert), with no restart."""
    db.set_ai_instructions(body.business, body.style)
    logger.warning("AI instructions changed by %s", user["username"])
    return _saved_ai_instructions()


def _saved_ai_instructions() -> AIInstructionsView:
    # Normalized and capped again on the way out, as the prompts do (llm._admin_note),
    # so the reply shows what the AI is given and a bad stored value is not a 500.
    saved = db.ai_instructions()
    return AIInstructionsView(**{field: normalize_note(saved[field])[:AI_INSTRUCTIONS_MAX_CHARS]
                                 for field in ("business", "style")})


def _chat_system_prompt() -> str:
    """The chat system prompt with the admin's notes, read per request so a saved
    change applies to the next question. The same text goes to the local model, its
    warm-up and GenAI Studio. Never raises: without readable notes, chat still works
    with the built-in prompt."""
    try:
        saved = db.ai_instructions()
        return compose_chat_system_prompt(saved["business"], saved["style"])
    except Exception:
        logger.warning("Could not read the AI instructions; chat uses the built-in prompt", exc_info=True)
        return CHAT_SYSTEM_PROMPT


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
    system = await asyncio.to_thread(_chat_system_prompt)
    reply, available = await answer_chat(chat_model(), body.messages, alerts, focused=body.alert_id is not None,
                                         system=system)
    return ChatReply(reply=reply, available=available)


@app.post("/api/chat/stream")
async def chat_stream(body: ChatRequest, user=Depends(require(*ALL_ROLES))) -> StreamingResponse:
    """/api/chat as newline-delimited JSON events, so the owner sees the answer
    being written instead of a minute of nothing. Same checks and same fixed text.

    Validation, auth and the 404 all happen before the response starts; after that
    the stream never errors, it ends with a "done" event. Starlette cancels the
    generator when the browser disconnects, which stops generation.
    """
    alerts = await asyncio.to_thread(_chat_alerts, body.alert_id)
    if alerts is None: raise HTTPException(404, "Alert not found")
    system = await asyncio.to_thread(_chat_system_prompt)

    async def events():
        async for event in stream_chat(chat_model(), body.messages, alerts, focused=body.alert_id is not None,
                                       system=system):
            yield json.dumps(event) + "\n"

    # no-store: an answer about this network must not sit in any cache.
    return StreamingResponse(events(), media_type="application/x-ndjson", headers={"Cache-Control": "no-store"})


class ChatWarm(BaseModel):
    alert_id: int | None = None


@app.post("/api/chat/warm")
async def chat_warm(body: ChatWarm, user=Depends(require(*ALL_ROLES))) -> dict[str, bool]:
    """Called when the owner starts typing: the model reads the instructions and the
    alert context it will need, so the answer starts sooner. Same owner-safe context
    as /api/chat. Cheap to repeat (an unchanged prompt is already read) and skipped
    while the model is busy."""
    alerts = await asyncio.to_thread(_chat_alerts, body.alert_id)
    if alerts is None: raise HTTPException(404, "Alert not found")
    system = await asyncio.to_thread(_chat_system_prompt)
    return {"warmed": await warm_chat(chat_model(), alerts, focused=body.alert_id is not None, system=system)}


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
