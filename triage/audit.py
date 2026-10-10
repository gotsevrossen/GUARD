"""The Admin page's activity log: who did what, recorded by the API and by the
administrator command-line tools (as db.CLI_AUDIT_USER).

Every row is written by the server from fixed vocabulary. The action is one of
AuditAction, the detail is text the route composes from enum values, and the
target is an alert id, a username or a chat model id (curated in the dashboard;
an administrator's own choice at the command line). Sensor and model
text never reaches this table: an alert's title is attacker-controlled, so alerts
are named by id only.
"""
from __future__ import annotations

from enum import StrEnum
import unicodedata

from pydantic import BaseModel

# A username can be up to 150 characters (api.UserCreate); nothing longer is ever
# a legitimate target.
AUDIT_TARGET_MAX_CHARS = 150
AUDIT_DETAIL_MAX_CHARS = 120
AUDIT_PAGE_MAX = 200


class AuditAction(StrEnum):
    SIGN_IN = "sign_in"
    SIGN_IN_FAILED = "sign_in_failed"
    PASSWORD_CHANGED = "password_changed"
    ALERT_STATUS = "alert_status"
    MONITORING_PAUSED = "monitoring_paused"
    MONITORING_RESUMED = "monitoring_resumed"
    SHUT_DOWN = "shut_down"
    AI_INSTRUCTIONS_CHANGED = "ai_instructions_changed"
    CHAT_MODEL_CHANGED = "chat_model_changed"
    # Set or removed at the command line (python -m triage.cloud_key); never the key.
    GENAI_KEY_SET = "genai_key_set"
    GENAI_KEY_CLEARED = "genai_key_cleared"
    UPDATE_INSTALL_STARTED = "update_install_started"
    USER_CREATED = "user_created"
    USER_ROLE_CHANGED = "user_role_changed"
    USER_PASSWORD_RESET = "user_password_reset"
    USER_REMOVED = "user_removed"
    USER_SIGNED_OUT = "user_signed_out"


def clean(value: object, limit: int) -> str | None:
    """Short, single-line text or None. Usernames are user input, so control and
    formatting characters (newlines, bidi overrides) are dropped: a log line must
    not be able to fake a second entry or reorder what an admin reads."""
    if value is None:
        return None
    text = "".join(ch for ch in str(value) if unicodedata.category(ch)[0] != "C").strip()
    return text[:limit] or None


class AuditEntry(BaseModel):
    id: int
    timestamp: str
    username: str
    action: str
    target: str | None = None
    detail: str | None = None


class AuditPage(BaseModel):
    entries: list[AuditEntry]
    # Pass the last entry's id as `before` to read the next (older) page.
    more: bool
