"""Lifecycle status changes with drivers, definition of done and the change log."""

from datetime import UTC, date, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, lifecycle
from app.api.deps import DB
from app.models import L2UseCase, L3UseCase, Lifecycle, LifecycleEvent, Role
from app.security import Editor, Reader

router = APIRouter(tags=["lifecycle"])


class DodItemOut(BaseModel):
    key: str
    label: str
    hint: str


class DriverOut(BaseModel):
    key: str
    label: str


class MetaOut(BaseModel):
    dod_items: list[DodItemOut]
    drivers: dict[str, list[DriverOut]]


class EventOut(BaseModel):
    id: int
    level: str
    code: str
    name: str
    from_status: Lifecycle | None
    to_status: Lifecycle
    driver_type: str
    driver: str
    note: str
    dod_override: bool
    username: str
    at: datetime


class DodState(BaseModel):
    key: str
    done: bool
    by: str | None = None
    at: str | None = None


class LifecycleOut(BaseModel):
    status: Lifecycle
    dod: list[DodState]
    dod_complete: bool
    # statuses the use case may change to from here
    allowed: list[Lifecycle] = []
    events: list[EventOut]


class ChangeIn(BaseModel):
    to_status: Lifecycle
    driver_type: Annotated[str, Field(max_length=32)] = "unspecified"
    driver: Annotated[str, Field(max_length=64)] = ""
    note: Annotated[str, Field(max_length=2000)] = ""
    override: bool = False


class DodIn(BaseModel):
    items: dict[str, bool]


def _owner(db: Session, level: str, code: str):
    model = {"l2": L2UseCase, "l3": L3UseCase}[level]
    obj = db.scalar(select(model).where(model.code == code))
    if obj is None:
        raise HTTPException(404, f"{level.upper()} use case not found")
    return obj


def event_out(db: Session, ev: LifecycleEvent, obj=None) -> EventOut:
    if obj is None:
        obj = db.get(L3UseCase, ev.l3_id) if ev.l3_id else db.get(L2UseCase, ev.l2_id)
    return EventOut(
        id=ev.id,
        level="l3" if ev.l3_id else "l2",
        code=obj.code,
        name=obj.name,
        from_status=ev.from_status,
        to_status=ev.to_status,
        driver_type=ev.driver_type,
        driver=ev.driver,
        note=ev.note,
        dod_override=ev.dod_override,
        username=ev.username,
        at=ev.at,
    )


def _state(db: Session, level: str, obj) -> LifecycleOut:
    col = LifecycleEvent.l2_id if level == "l2" else LifecycleEvent.l3_id
    events = db.scalars(
        select(LifecycleEvent).where(col == obj.id).order_by(LifecycleEvent.at.desc())
    )
    done = obj.dod or {}
    return LifecycleOut(
        status=obj.lifecycle_status,
        dod=[
            DodState(
                key=k, done=k in done, by=done.get(k, {}).get("by"), at=done.get(k, {}).get("at")
            )
            for k in lifecycle.DOD_KEYS
        ],
        dod_complete=not lifecycle.dod_missing(obj),
        allowed=lifecycle.allowed_targets(obj.lifecycle_status),
        events=[event_out(db, e, obj) for e in events],
    )


@router.get("/lifecycle/meta", response_model=MetaOut)
def meta(_: Reader) -> MetaOut:
    return MetaOut(
        dod_items=[DodItemOut(key=k, label=lbl, hint=h) for k, lbl, h in lifecycle.DOD_ITEMS],
        drivers={
            t: [DriverOut(key=k, label=lbl) for k, lbl in items]
            for t, items in lifecycle.DRIVERS.items()
        },
    )


@router.get("/changes", response_model=list[EventOut])
def change_log(
    _: Reader,
    db: DB,
    limit: int = Query(50, ge=1, le=500),
    driver_type: str | None = None,
) -> list[EventOut]:
    q = select(LifecycleEvent).order_by(LifecycleEvent.at.desc(), LifecycleEvent.id.desc())
    if driver_type:
        q = q.where(LifecycleEvent.driver_type == driver_type)
    return [event_out(db, e) for e in db.scalars(q.limit(limit))]


def apply_change(db: Session, level: str, obj, body: ChangeIn, user) -> None:
    """Change the lifecycle status of one use case or rule (no commit). Raises HTTPException when
    the change is not allowed; also used by the bulk edit (issue #73)."""
    code = obj.code
    if body.to_status == obj.lifecycle_status:
        raise HTTPException(422, f"{code} is already {body.to_status.value}")
    if body.driver_type not in lifecycle.DRIVER_TYPES or not lifecycle.valid_driver(
        body.driver_type, body.driver
    ):
        raise HTTPException(422, "Unknown change driver")
    problem = lifecycle.transition_error(obj.lifecycle_status, body.to_status)
    if problem:
        raise HTTPException(422, problem)
    missing = lifecycle.dod_missing(obj) if body.to_status == Lifecycle.operational else []
    if missing and not body.override:
        raise HTTPException(
            422,
            "Definition of done is not complete: "
            + ", ".join(lbl for k, lbl, _ in lifecycle.DOD_ITEMS if k in missing),
        )
    if missing and user.role != Role.admin:
        raise HTTPException(403, "Only admins can skip the definition of done")
    old = obj.lifecycle_status
    lifecycle.apply_status(obj, body.to_status)
    if body.to_status == Lifecycle.operational and obj.onboarded_at is None:
        obj.onboarded_at = date.today()
    lifecycle.record_change(
        db,
        obj,
        old,
        body.to_status,
        user.username,
        body.driver_type,
        body.driver,
        body.note,
        override=bool(missing),
    )
    audit.record(
        db,
        user,
        "lifecycle",
        level,
        code,
        {
            "lifecycle_status": [old, body.to_status],
            "driver": f"{body.driver_type}/{body.driver}".rstrip("/"),
        }
        | ({"dod_override": missing} if missing else {}),
    )


for _level in ("l2", "l3"):

    def _make(level: str) -> None:
        base = f"/{level}/{{code}}"

        @router.get(f"{base}/lifecycle", response_model=LifecycleOut)
        def get_lifecycle(code: str, _: Reader, db: DB) -> LifecycleOut:
            return _state(db, level, _owner(db, level, code))

        @router.post(f"{base}/lifecycle", response_model=LifecycleOut, status_code=201)
        def change_status(code: str, body: ChangeIn, user: Editor, db: DB) -> LifecycleOut:
            obj = _owner(db, level, code)
            apply_change(db, level, obj, body, user)
            db.commit()
            return _state(db, level, obj)

        @router.put(f"{base}/dod", response_model=LifecycleOut)
        def set_dod(code: str, body: DodIn, user: Editor, db: DB) -> LifecycleOut:
            obj = _owner(db, level, code)
            unknown = set(body.items) - set(lifecycle.DOD_KEYS)
            if unknown:
                raise HTTPException(422, f"Unknown checklist item: {', '.join(sorted(unknown))}")
            done = dict(obj.dod or {})
            for k, v in body.items.items():
                if v and k not in done:
                    done[k] = {"by": user.username, "at": datetime.now(UTC).date().isoformat()}
                elif not v:
                    done.pop(k, None)
            obj.dod = done
            audit.record(db, user, "dod", level, code, {"items": body.items})
            db.commit()
            return _state(db, level, obj)

    _make(_level)
