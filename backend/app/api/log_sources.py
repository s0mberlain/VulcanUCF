"""Verification of log sources (issue #75, PROJ-6).

A log source (reference list entry of kind log_source) is checked at intervals: log intake,
configuration, filtering and responsibilities, each ok / issues / not applicable with a note.
Only a check without issues counts as verified and moves the due date, as for rules. Each log
source can have an owner and its own interval; the default interval is an admin setting
(`log_sources.verification`, falling back to DEFAULT_VERIFICATION_DAYS).

The status of a log source is shown in the overview and on the rules that use it:
- never: never verified;
- ok: verified, next check due later than the chosen window;
- due: verified, next check due within the window;
- overdue: verified, but the next check is past its due date;
- issues: the last check found issues (whatever the due date).
"""

from datetime import date, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app import audit, interviews
from app.api.deps import DB, SettingsDep
from app.models import (
    LOG_SOURCE_CHECKS,
    AppSetting,
    L3UseCase,
    LogSourceProfile,
    LogSourceVerification,
    ReferenceItem,
    RefKind,
    VerificationResult,
    l3_references,
)
from app.schemas import NOTE_MAX, TEXT_MAX, not_in_future
from app.security import Admin, Editor, Reader

router = APIRouter(tags=["log sources"])

SETTING_KEY = "log_sources.verification"
Status = Literal["never", "ok", "due", "overdue", "issues"]
CheckResult = Literal["ok", "issues", "na"]


class CheckIn(BaseModel):
    result: CheckResult = "ok"
    note: Annotated[str, Field(max_length=NOTE_MAX)] = ""


class VerifyLogSourceIn(BaseModel):
    checks: dict[str, CheckIn]
    note: Annotated[str, Field(max_length=TEXT_MAX)] = ""
    verified_at: date | None = None

    _past = field_validator("verified_at")(not_in_future)

    @field_validator("checks")
    @classmethod
    def _all_checks(cls, v: dict[str, CheckIn]) -> dict[str, CheckIn]:
        unknown = sorted(set(v) - set(LOG_SOURCE_CHECKS))
        if unknown:
            raise ValueError(f"unknown check: {', '.join(unknown)}")
        missing = [c for c in LOG_SOURCE_CHECKS if c not in v]
        if missing:
            raise ValueError(f"missing check: {', '.join(missing)}")
        return v


class LogSourceVerificationOut(BaseModel):
    id: int
    verified_at: date
    username: str
    result: VerificationResult
    note: str
    checks: dict[str, CheckIn]


class ProfileIn(BaseModel):
    owner: Annotated[str, Field(max_length=255)] = ""
    verification_interval_days: Annotated[int, Field(ge=1, le=3650)] | None = None


class LogSourceStatusOut(BaseModel):
    id: int
    name: str
    description: str
    owner: str
    verification_interval_days: int | None
    interval: int
    last_verified_at: date | None
    last_verified_by: str | None
    due: date | None
    days_left: int | None
    status: Status
    issues_at: date | None
    rules: list[str]
    systems: list[str]


class LogSourceSettings(BaseModel):
    default_days: Annotated[int, Field(ge=1, le=3650)]


def default_days(db, fallback: int) -> int:
    row = db.get(AppSetting, SETTING_KEY)
    if row and isinstance(row.value, dict) and row.value.get("default_days"):
        return int(row.value["default_days"])
    return fallback


def _item(db, item_id: int) -> ReferenceItem:
    item = db.get(ReferenceItem, item_id)
    if item is None or item.kind != RefKind.log_source:
        raise HTTPException(404, "Log source not found")
    return item


def _profile(db, item_id: int) -> LogSourceProfile:
    p = db.get(LogSourceProfile, item_id)
    if p is None:
        p = LogSourceProfile(item_id=item_id, owner="")
        db.add(p)
    return p


def statuses(db, fallback_days: int, window: int = 30) -> list[LogSourceStatusOut]:
    """Status of every log source; also used for the warnings on rules."""
    today = date.today()
    default = default_days(db, fallback_days)
    items = list(
        db.scalars(
            select(ReferenceItem)
            .where(ReferenceItem.kind == RefKind.log_source)
            .order_by(ReferenceItem.name)
        )
    )
    profiles = {p.item_id: p for p in db.scalars(select(LogSourceProfile))}
    # newest check per log source: "issues" when it found issues
    latest: dict[int, LogSourceVerification] = {}
    for v in db.scalars(
        select(LogSourceVerification).order_by(
            LogSourceVerification.verified_at, LogSourceVerification.id
        )
    ):
        latest[v.item_id] = v
    rules: dict[int, list[str]] = {}
    for item_id, code in db.execute(
        select(l3_references.c.item_id, L3UseCase.code).join(
            L3UseCase, L3UseCase.id == l3_references.c.l3_id
        )
    ):
        rules.setdefault(item_id, []).append(code)
    systems = interviews.log_source_users(db)
    out = []
    for i in items:
        p = profiles.get(i.id)
        interval = (p.verification_interval_days if p else None) or default
        last = p.last_verified_at if p else None
        due = last + timedelta(days=interval) if last else None
        newest = latest.get(i.id)
        issues_at = (
            newest.verified_at
            if newest is not None and newest.result == VerificationResult.issues
            else None
        )
        if issues_at:
            status: Status = "issues"
        elif last is None:
            status = "never"
        elif due < today:
            status = "overdue"
        elif due <= today + timedelta(days=window):
            status = "due"
        else:
            status = "ok"
        out.append(
            LogSourceStatusOut(
                id=i.id,
                name=i.name,
                description=i.description,
                owner=p.owner if p else "",
                verification_interval_days=p.verification_interval_days if p else None,
                interval=interval,
                last_verified_at=last,
                last_verified_by=p.last_verified_by if p else None,
                due=due,
                days_left=(due - today).days if due else None,
                status=status,
                issues_at=issues_at,
                rules=sorted(rules.get(i.id, [])),
                systems=sorted(systems.get(i.id, [])),
            )
        )
    return out


@router.get("/log-sources/verification", response_model=list[LogSourceStatusOut])
def overview(
    _: Reader,
    db: DB,
    settings: SettingsDep,
    within_days: int = Query(30, ge=0, le=3650),
) -> list[LogSourceStatusOut]:
    return statuses(db, settings.default_verification_days, within_days)


@router.get("/log-sources/settings", response_model=LogSourceSettings)
def get_settings_(_: Reader, db: DB, settings: SettingsDep) -> LogSourceSettings:
    return LogSourceSettings(default_days=default_days(db, settings.default_verification_days))


@router.put("/log-sources/settings", response_model=LogSourceSettings)
def put_settings(body: LogSourceSettings, user: Admin, db: DB, settings: SettingsDep):
    old = default_days(db, settings.default_verification_days)
    row = db.get(AppSetting, SETTING_KEY)
    if row is None:
        db.add(AppSetting(key=SETTING_KEY, value=body.model_dump(), updated_by=user.username))
    else:
        row.value, row.updated_by = body.model_dump(), user.username
    audit.record(
        db, user, "update", "settings", SETTING_KEY, {"default_days": [old, body.default_days]}
    )
    db.commit()
    return body


@router.put("/log-sources/{item_id}/profile", response_model=LogSourceStatusOut)
def put_profile(item_id: int, body: ProfileIn, user: Editor, db: DB, settings: SettingsDep):
    item = _item(db, item_id)
    p = _profile(db, item_id)
    before = {"owner": p.owner or "", "verification_interval_days": p.verification_interval_days}
    p.owner = body.owner.strip()
    p.verification_interval_days = body.verification_interval_days
    changes = audit.diff(
        before, {"owner": p.owner, "verification_interval_days": p.verification_interval_days}
    )
    if changes:
        audit.record(db, user, "update", "log_source", item.name, changes)
    db.commit()
    return next(s for s in statuses(db, settings.default_verification_days) if s.id == item_id)


@router.post(
    "/log-sources/{item_id}/verify", response_model=LogSourceVerificationOut, status_code=201
)
def verify(item_id: int, body: VerifyLogSourceIn, user: Editor, db: DB) -> LogSourceVerification:
    item = _item(db, item_id)
    when = body.verified_at or date.today()
    result = (
        VerificationResult.issues
        if any(c.result == "issues" for c in body.checks.values())
        else VerificationResult.ok
    )
    checks = {k: body.checks[k].model_dump() for k in LOG_SOURCE_CHECKS}
    v = LogSourceVerification(
        item_id=item_id,
        verified_at=when,
        username=user.username,
        result=result,
        note=body.note,
        checks=checks,
    )
    db.add(v)
    # only a check without issues moves the due date (same rule as for use cases and rules)
    if result == VerificationResult.ok:
        p = _profile(db, item_id)
        if p.last_verified_at is None or when >= p.last_verified_at:
            p.last_verified_at, p.last_verified_by = when, user.username
    audit.record(
        db,
        user,
        "verify",
        "log_source",
        item.name,
        {"result": result.value, "verified_at": when, "checks": checks, "note": body.note},
    )
    db.commit()
    return v


@router.get("/log-sources/{item_id}/verifications", response_model=list[LogSourceVerificationOut])
def history(item_id: int, _: Reader, db: DB) -> list[LogSourceVerification]:
    _item(db, item_id)
    q = (
        select(LogSourceVerification)
        .where(LogSourceVerification.item_id == item_id)
        .order_by(LogSourceVerification.verified_at.desc(), LogSourceVerification.id.desc())
    )
    return list(db.scalars(q))
