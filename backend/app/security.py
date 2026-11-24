"""Password hashing, server-side sessions and role checks."""

import hashlib
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.models import ApiToken, Role, User, UserSession

SESSION_COOKIE = "magma_session"
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    if not password_hash:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def as_utc(dt: datetime) -> datetime:
    # SQLite returns naive datetimes; everything is stored in UTC.
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def create_session(db: Session, user: User, settings: Settings, hours: int | None = None) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    db.execute(delete(UserSession).where(UserSession.expires_at < now))
    db.add(
        UserSession(
            token_hash=_token_hash(token),
            user_id=user.id,
            expires_at=now + timedelta(hours=hours or settings.session_hours),
        )
    )
    return token


def drop_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(UserSession).where(UserSession.token_hash == _token_hash(token)))


def drop_user_sessions(db: Session, user: User, keep_token: str | None = None) -> None:
    """Sign the user out everywhere (e.g. after a password change), except the given session."""
    q = delete(UserSession).where(UserSession.user_id == user.id)
    if keep_token:
        q = q.where(UserSession.token_hash != _token_hash(keep_token))
    db.execute(q)


TOKEN_PREFIX = "mgm_"


def new_api_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def _bearer_user(db: Session, token: str) -> tuple[User, list[str]]:
    now = datetime.now(UTC)
    tok = db.scalar(select(ApiToken).where(ApiToken.token_hash == _token_hash(token)))
    if (
        tok is None
        or (tok.expires_at is not None and as_utc(tok.expires_at) <= now)
        or not tok.user.active
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API token")
    if tok.last_used_at is None or now - as_utc(tok.last_used_at) > timedelta(minutes=5):
        db.execute(update(ApiToken).where(ApiToken.id == tok.id).values(last_used_at=now))
        db.commit()
    return tok.user, list(tok.scopes or [])


# What an API token may call, by scope. Everything else is refused for bearer tokens, so a leaked
# SIEM token cannot edit the catalogue even though its account has the analyst role.
TOKEN_SCOPES = ("siem", "read")
_SIEM_PATH = re.compile(r"^/api/integrations/siem(/[^/]+/(rules|alerts))?$")


def token_allows(scopes: list[str], method: str, path: str) -> bool:
    if path == "/api/auth/me":
        return True  # "who am I", to test a token
    if "siem" in scopes and _SIEM_PATH.match(path) and method in ("GET", "PUT", "POST"):
        return True
    return "read" in scopes and method in ("GET", "HEAD")


# What a red team account may call: its own account and the campaigns it is assigned to (PROJ-3).
_RED_TEAM_PATH = re.compile(r"^/api/(auth/|campaigns|tests|test-attachments)")


def _gate(user: User, request: Request, db: Session) -> User:
    """Red team accounts: refuse everything but their campaigns, and refuse expired accounts."""
    if user.role != Role.red_team:
        return user
    from app import purple  # late: purple imports this module

    if purple.account_expired(user, db):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This account has expired")
    if not _RED_TEAM_PATH.match(request.url.path):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this action")
    return user


def current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> User:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        user, scopes = _bearer_user(db, auth[7:].strip())
        if not token_allows(scopes, request.method, request.url.path):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "This API token's scope does not allow this call (scopes: "
                + (", ".join(scopes) or "none")
                + ")",
            )
        return _gate(user, request, db)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sess = db.scalar(select(UserSession).where(UserSession.token_hash == _token_hash(token)))
        if sess and as_utc(sess.expires_at) > datetime.now(UTC) and sess.user.active:
            return _gate(sess.user, request, db)
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")


CurrentUser = Annotated[User, Depends(current_user)]


def require_roles(*roles: Role) -> Callable[[User], User]:
    def check(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this action")
        return user

    return check


# Permission profiles (docs/PLAN.md section 5a)
Reader = Annotated[User, Depends(current_user)]
Editor = Annotated[User, Depends(require_roles(Role.admin, Role.analyst))]
Admin = Annotated[User, Depends(require_roles(Role.admin))]
AuditReader = Annotated[User, Depends(require_roles(Role.admin, Role.auditor))]


def check_password_policy(password: str, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if len(password) < settings.min_password_length:
        raise HTTPException(
            422,
            f"Password must be at least {settings.min_password_length} characters",
        )
