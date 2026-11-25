"""Bulk edit of L2 use cases from the use case tree (issue #73).

Each endpoint takes a list of L2 identifiers and applies the same change to each of them. Every
use case is changed in its own savepoint: one that cannot be changed (unknown identifier, a
lifecycle step that is not allowed, an incomplete definition of done) is reported and skipped,
the others are saved. Each change writes the same audit entries as the single edit.
"""

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, drivers
from app.api.deps import DB
from app.api.lifecycle import ChangeIn, apply_change
from app.api.scores import VerifyIn, record_verification
from app.api.usecases import _business_drivers, _compliance_drivers, _refs
from app.models import L2UseCase, RefKind
from app.schemas import Metric
from app.security import Editor

router = APIRouter(prefix="/l2-bulk", tags=["use cases"])

MAX_CODES = 500
Codes = Annotated[list[str], Field(min_length=1, max_length=MAX_CODES)]


class BulkResult(BaseModel):
    code: str
    ok: bool
    error: str | None = None


class BulkOut(BaseModel):
    changed: int
    results: list[BulkResult]


class ListChange(BaseModel):
    """Entries to add to and remove from a list; entries not named stay as they are."""

    add: list[str] = []
    remove: list[str] = []


class IdListChange(BaseModel):
    add: list[int] = []
    remove: list[int] = []


class BulkUpdateIn(BaseModel):
    codes: Codes
    # set: a field left out is unchanged; null clears it (risk level and target are optional)
    risk_level: Annotated[int, Field(ge=1, le=5)] | None = None
    target_implementation: Metric | None = None
    actors: ListChange | None = None
    business_drivers: ListChange | None = None
    compliance_driver_ids: IdListChange | None = None

    @model_validator(mode="after")
    def _something(self):
        if not (self.model_fields_set - {"codes"}):
            raise ValueError("nothing to change")
        return self


class BulkLifecycleIn(ChangeIn):
    codes: Codes

    # skipping the definition of done stays a decision per use case
    @model_validator(mode="after")
    def _no_override(self):
        if self.override:
            raise ValueError("the definition of done cannot be skipped in a bulk change")
        return self


class BulkVerifyIn(VerifyIn):
    codes: Codes


def _each(db: Session, codes: list[str], change) -> BulkOut:
    results: list[BulkResult] = []
    for code in dict.fromkeys(codes):
        l2 = db.scalar(select(L2UseCase).where(L2UseCase.code == code))
        if l2 is None:
            results.append(BulkResult(code=code, ok=False, error="L2 use case not found"))
            continue
        sp = db.begin_nested()
        try:
            change(l2)
            db.flush()
            sp.commit()
            results.append(BulkResult(code=code, ok=True))
        except HTTPException as e:
            sp.rollback()
            results.append(BulkResult(code=code, ok=False, error=str(e.detail)))
    db.commit()
    return BulkOut(changed=sum(r.ok for r in results), results=results)


@router.post("/update", response_model=BulkOut)
def bulk_update(body: BulkUpdateIn, user: Editor, db: DB) -> BulkOut:
    fields = body.model_fields_set
    # look the entries up once, so an unknown name fails the whole request (422), not each L2
    add_actors = _refs(db, RefKind.threat_actor, body.actors.add) if body.actors else []
    add_bd = _business_drivers(db, body.business_drivers.add) if body.business_drivers else []
    add_cd = (
        _compliance_drivers(db, body.compliance_driver_ids.add)
        if body.compliance_driver_ids
        else []
    )

    def change(l2: L2UseCase) -> None:
        changes: dict[str, Any] = {}
        for f in ("risk_level", "target_implementation"):
            if f in fields and getattr(l2, f) != getattr(body, f):
                changes[f] = [getattr(l2, f), getattr(body, f)]
                setattr(l2, f, getattr(body, f))
        if body.actors:
            old = sorted(a.name for a in l2.actors)
            gone = set(body.actors.remove)
            l2.actors = [a for a in l2.actors if a.name not in gone] + [
                a for a in add_actors if a not in l2.actors
            ]
            changes["actors"] = [old, sorted(a.name for a in l2.actors)]
        if body.business_drivers:
            old = sorted(b.code for b in l2.business_drivers)
            gone = set(body.business_drivers.remove)
            l2.business_drivers = [b for b in l2.business_drivers if b.code not in gone] + [
                b for b in add_bd if b not in l2.business_drivers
            ]
            changes["business_drivers"] = [old, sorted(b.code for b in l2.business_drivers)]
        if body.compliance_driver_ids:
            old = sorted(drivers.compliance_label(c) for c in l2.compliance_drivers)
            gone = set(body.compliance_driver_ids.remove)
            l2.compliance_drivers = [c for c in l2.compliance_drivers if c.id not in gone] + [
                c for c in add_cd if c not in l2.compliance_drivers
            ]
            changes["compliance_drivers"] = [
                old,
                sorted(drivers.compliance_label(c) for c in l2.compliance_drivers),
            ]
        changes = {k: v for k, v in changes.items() if v[0] != v[1]}
        if changes:
            audit.record(db, user, "update", "l2", l2.code, changes | {"bulk": True})
            l2.updated_at = datetime.now(UTC)

    return _each(db, body.codes, change)


@router.post("/lifecycle", response_model=BulkOut)
def bulk_lifecycle(body: BulkLifecycleIn, user: Editor, db: DB) -> BulkOut:
    change = ChangeIn(**body.model_dump(exclude={"codes"}))
    return _each(db, body.codes, lambda l2: apply_change(db, "l2", l2, change, user))


@router.post("/verify", response_model=BulkOut)
def bulk_verify(body: BulkVerifyIn, user: Editor, db: DB) -> BulkOut:
    check = VerifyIn(**body.model_dump(exclude={"codes"}))
    return _each(db, body.codes, lambda l2: record_verification(db, "l2", l2, check, user))
