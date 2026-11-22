from fastapi import APIRouter, HTTPException, status
from sqlalchemy import delete, func, select

from app import audit, purple
from app.api.deps import DB
from app.models import AuthSource, Role, TestAttachment, TestCase, User, UserSession
from app.schemas import UserCreate, UserOut, UserUpdate
from app.security import Admin, check_password_policy, hash_password

router = APIRouter(prefix="/users", tags=["users"])


def _get(db, user_id: int) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


def _active_admins(db) -> int:
    return db.scalar(
        select(func.count()).select_from(User).where(User.role == Role.admin, User.active)
    )


def _shown(db, user: User) -> User:
    """The account with the date its expiry applies now (red team accounts)."""
    user.effective_expires_at = purple.account_expiry(user, db)  # type: ignore[attr-defined]
    return user


@router.get("", response_model=list[UserOut])
def list_users(_: Admin, db: DB) -> list[User]:
    return [_shown(db, u) for u in db.scalars(select(User).order_by(User.username))]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, admin: Admin, db: DB) -> User:
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")
    check_password_policy(body.password)
    if body.role == Role.red_team and body.expires_at is None and not body.expiry_follows_campaign:
        raise HTTPException(422, "A red team account needs an expiry date")
    user = User(
        username=body.username,
        display_name=body.display_name,
        email=body.email,
        role=body.role,
        auth_source=AuthSource.local,
        password_hash=hash_password(body.password),
        expires_at=body.expires_at if body.role == Role.red_team else None,
        expiry_follows_campaign=body.expiry_follows_campaign and body.role == Role.red_team,
    )
    db.add(user)
    audit.record(
        db,
        admin,
        "create",
        "user",
        body.username,
        {"role": body.role}
        | (
            {"expires_at": body.expires_at, "follows": body.expiry_follows_campaign}
            if body.role == Role.red_team
            else {}
        ),
    )
    db.commit()
    return _shown(db, user)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, admin: Admin, db: DB) -> User:
    user = _get(db, user_id)
    data = body.model_dump(exclude_unset=True)
    for k in ("role", "active", "display_name"):
        if k in data and data[k] is None:
            raise HTTPException(422, f"{k} cannot be empty")
    if user.auth_source == AuthSource.service and data.get("role") == Role.admin:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "API token accounts can only be analyst or auditor"
        )
    if user.auth_source == AuthSource.sso and "role" in data and data["role"] != user.role:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "The role of an SSO account comes from the identity provider groups (OIDC_ROLE_MAP) "
            "and would be reset at the next sign-in. Change the group there.",
        )
    demoting = ("role" in data and data["role"] != Role.admin) or data.get("active") is False
    if user.role == Role.admin and user.active and demoting and _active_admins(db) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot remove the last active admin")

    new_role = data.get("role", user.role)
    if new_role == Role.red_team and user.auth_source != AuthSource.local:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Only local accounts can be red team accounts"
        )
    if new_role == Role.red_team:
        follows = data.get("expiry_follows_campaign", user.expiry_follows_campaign)
        if not follows and data.get("expires_at", user.expires_at) is None:
            raise HTTPException(422, "A red team account needs an expiry date")
    changes = {}
    if "password" in data:
        password = data.pop("password")
        if password:
            if user.auth_source != AuthSource.local:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "SSO accounts have no password")
            check_password_policy(password)
            user.password_hash = hash_password(password)
            user.failed_logins = 0
            user.locked_until = None
            changes["password"] = ["***", "***"]
            db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    before = {k: getattr(user, k) for k in data}
    for k, v in data.items():
        setattr(user, k, v)
    changes |= audit.diff(before, data)
    if data.get("active") is False or "role" in data:
        db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    audit.record(db, admin, "update", "user", user.username, changes)
    db.commit()
    return _shown(db, user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, admin: Admin, db: DB) -> None:
    user = _get(db, user_id)
    if user.id == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "You cannot delete yourself")
    if user.role == Role.admin and user.active and _active_admins(db) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot remove the last active admin")
    if user.role == Role.red_team and (
        db.scalar(
            select(func.count())
            .select_from(TestCase)
            .where((TestCase.created_by == user.username) | (TestCase.red_by == user.username))
        )
        or db.scalar(
            select(func.count())
            .select_from(TestAttachment)
            .where(TestAttachment.uploaded_by == user.username)
        )
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This red team account has entries in campaigns; lock it instead of deleting it",
        )
    audit.record(db, admin, "delete", "user", user.username)
    db.delete(user)
    db.commit()


@router.delete("/{user_id}/totp", response_model=UserOut)
def reset_totp(user_id: int, admin: Admin, db: DB) -> User:
    """Turn off two-factor login, e.g. when someone lost their phone and recovery codes."""
    from app.api.auth import clear_totp

    user = _get(db, user_id)
    clear_totp(user)
    db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    audit.record(db, admin, "totp_reset", "user", user.username)
    db.commit()
    return user
