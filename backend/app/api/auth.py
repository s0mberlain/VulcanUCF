import threading
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import or_, select, update

from app import audit, totp
from app.api.deps import DB, SettingsDep
from app.models import AuthSource, User
from app.schemas import AuthConfigOut, LoginIn, PasswordChange, UserOut
from app.security import (
    SESSION_COOKIE,
    CurrentUser,
    as_utc,
    check_password_policy,
    create_session,
    drop_session,
    drop_user_sessions,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

TOTP_REQUIRED = "totp_required"

# Verified against when the username does not exist, so timing does not reveal valid names.
_DUMMY_HASH = hash_password("timing-equaliser-not-a-password")


@router.get("/config", response_model=AuthConfigOut)
def auth_config(settings: SettingsDep) -> AuthConfigOut:
    return AuthConfigOut(
        local_login_enabled=settings.local_login_enabled,
        sso_enabled=settings.sso_enabled,
        sso_label=settings.oidc_button_label,
    )


def _locked(user: User) -> bool:
    return bool(user.locked_until and as_utc(user.locked_until) > datetime.now(UTC))


LOCKED = "Account temporarily locked, try again later"
_recovery_lock = threading.Lock()


def _count_failure(db, user: User, settings) -> None:
    """A wrong password or code: after MAX_FAILED_LOGINS the account is locked for a while."""
    user.failed_logins += 1
    if user.failed_logins >= settings.max_failed_logins:
        user.locked_until = datetime.now(UTC) + timedelta(minutes=settings.lockout_minutes)
        user.failed_logins = 0
        audit.record(db, user, "lockout", "user", user.username)
    db.commit()


def _require_password(db, user: User, password: str, settings, message: str) -> None:
    """Re-check the password for account changes. Wrong guesses count toward the lockout, so a
    stolen session cannot be used to guess the password without limit."""
    if _locked(user):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, LOCKED)
    if not verify_password(user.password_hash, password):
        _count_failure(db, user, settings)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, message)


@router.post("/login", response_model=UserOut)
def login(
    body: LoginIn, request: Request, response: Response, db: DB, settings: SettingsDep
) -> User:
    if not settings.local_login_enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Local login is disabled")
    limiter = request.app.state.login_limiter
    ip = request.client.host if request.client else None
    if limiter.blocked(ip):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed sign-ins, try again later"
        )
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    user = db.scalar(select(User).where(User.username == body.username))
    now = datetime.now(UTC)

    if user is None or user.auth_source != AuthSource.local:
        verify_password(_DUMMY_HASH, body.password)
        limiter.failed(ip)
        raise invalid
    password_ok = verify_password(user.password_hash, body.password)
    if _locked(user):
        # only someone who knows the password learns that the account exists and is locked
        if password_ok and user.active:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, LOCKED)
        limiter.failed(ip)
        raise invalid

    def fail(exc: HTTPException) -> HTTPException:
        limiter.failed(ip)
        _count_failure(db, user, settings)
        return exc

    if not password_ok or not user.active:
        raise fail(invalid)
    from app import purple  # late import: purple imports security

    if purple.account_expired(user, db):
        raise fail(invalid)
    if user.totp_enabled:
        if not body.otp:
            # password was right: ask for the second factor (does not count as a failure)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, TOTP_REQUIRED)
        how = _check_second_factor(db, user, body.otp, settings)
        if how is None:
            raise fail(HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication code"))
        if how == "recovery":
            audit.record(
                db,
                user,
                "recovery_code_used",
                "user",
                user.username,
                {"left": len(user.recovery_codes)},
            )

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    token = create_session(db, user, settings)
    audit.record(db, user, "login", "user", user.username)
    db.commit()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: DB) -> None:
    drop_session(db, request.cookies.get(SESSION_COOKIE))
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> User:
    return user


class LocaleIn(BaseModel):
    locale: Literal["en", "de", "nl"] | None


@router.put("/me/locale", response_model=UserOut)
def set_locale(body: LocaleIn, user: CurrentUser, db: DB) -> User:
    """UI language of the signed-in user (also allowed for auditors: it is a preference)."""
    user.locale = body.locale
    db.commit()
    return user


@router.post("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: PasswordChange, request: Request, user: CurrentUser, db: DB, settings: SettingsDep
) -> None:
    if user.auth_source != AuthSource.local:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "SSO accounts have no local password")
    _require_password(db, user, body.current_password, settings, "Current password is wrong")
    check_password_policy(body.new_password)
    user.password_hash = hash_password(body.new_password)
    # other browsers (possibly an attacker's) are signed out; this one stays signed in
    drop_user_sessions(db, user, keep_token=request.cookies.get(SESSION_COOKIE))
    audit.record(db, user, "password_change", "user", user.username)
    db.commit()


# ---------------------------------------------------------------- two-factor login (TOTP)


def _check_second_factor(db, user: User, code: str, settings) -> str | None:
    """'totp' or 'recovery' when the code is valid (and consumes it), else None."""
    secret = totp.decrypt(user.totp_secret or "", settings.secret_key)
    if secret:
        step = totp.verify(secret, code, user.totp_last_step)
        if step is not None:
            # claim the time step in the database, so two parallel requests with the same code
            # cannot both pass (replay)
            claimed = db.execute(
                update(User)
                .where(
                    User.id == user.id,
                    or_(User.totp_last_step.is_(None), User.totp_last_step < step),
                )
                .values(totp_last_step=step)
                .execution_options(synchronize_session=False)
            ).rowcount
            if claimed != 1:
                return None
            user.totp_last_step = step
            return "totp"
    h = totp.hash_code(code)
    # One at a time, and on the row as it is in the database now: two sign-ins sending the same
    # recovery code at the same moment must not both pass. The use is committed before the lock
    # is released (the row lock covers other replicas on PostgreSQL).
    with _recovery_lock:
        db.refresh(user, with_for_update=True)
        if h not in (user.recovery_codes or []):
            db.commit()
            return None
        user.recovery_codes = [c for c in user.recovery_codes if c != h]
        db.commit()
    return "recovery"


class TotpPassword(BaseModel):
    password: str


class TotpCode(BaseModel):
    code: str


class TotpConfirm(BaseModel):
    password: str
    code: str


class TotpSetupOut(BaseModel):
    secret: str
    uri: str
    qr_svg: str


class RecoveryOut(BaseModel):
    recovery_codes: list[str]


def _local(user: User) -> None:
    if user.auth_source != AuthSource.local:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "SSO accounts use the second factor of the identity provider",
        )


@router.post("/me/totp/setup", response_model=TotpSetupOut)
def totp_setup(
    body: TotpPassword, user: CurrentUser, db: DB, settings: SettingsDep
) -> TotpSetupOut:
    """Start setting up an authenticator app; nothing changes for login until it is confirmed."""
    _local(user)
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor login is already on")
    _require_password(db, user, body.password, settings, "Password is wrong")
    secret = totp.new_secret()
    user.totp_secret = totp.encrypt(secret, settings.secret_key)
    user.totp_last_step = None
    db.commit()
    uri = totp.otpauth_uri(secret, user.username, settings.app_name)
    return TotpSetupOut(secret=secret, uri=uri, qr_svg=totp.qr_svg(uri))


@router.post("/me/totp/enable", response_model=RecoveryOut)
def totp_enable(
    body: TotpCode, request: Request, user: CurrentUser, db: DB, settings: SettingsDep
) -> RecoveryOut:
    _local(user)
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor login is already on")
    secret = totp.decrypt(user.totp_secret or "", settings.secret_key)
    if not secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start the setup first")
    step = totp.verify(secret, body.code, None)
    if step is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "The code does not match, check the time on your phone"
        )
    codes = totp.new_recovery_codes()
    user.totp_enabled = True
    user.totp_last_step = step
    user.recovery_codes = [totp.hash_code(c) for c in codes]
    drop_user_sessions(db, user, keep_token=request.cookies.get(SESSION_COOKIE))
    audit.record(db, user, "totp_enable", "user", user.username)
    db.commit()
    return RecoveryOut(recovery_codes=codes)


def _confirm(db, user: User, body: TotpConfirm, settings) -> None:
    _local(user)
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor login is off")
    _require_password(db, user, body.password, settings, "Password is wrong")
    if _check_second_factor(db, user, body.code, settings) is None:
        _count_failure(db, user, settings)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid authentication code")


@router.post("/me/totp/disable", status_code=status.HTTP_204_NO_CONTENT)
def totp_disable(body: TotpConfirm, user: CurrentUser, db: DB, settings: SettingsDep) -> None:
    _confirm(db, user, body, settings)
    totp.clear_totp(user)
    audit.record(db, user, "totp_disable", "user", user.username)
    db.commit()


@router.post("/me/totp/recovery-codes", response_model=RecoveryOut)
def totp_new_codes(
    body: TotpConfirm, user: CurrentUser, db: DB, settings: SettingsDep
) -> RecoveryOut:
    _confirm(db, user, body, settings)
    codes = totp.new_recovery_codes()
    user.recovery_codes = [totp.hash_code(c) for c in codes]
    audit.record(db, user, "recovery_codes_renewed", "user", user.username)
    db.commit()
    return RecoveryOut(recovery_codes=codes)
