"""L1 / L2 / L3 use cases. Parents are derived from the identifier prefix, as in the Excel tool."""

from collections.abc import Callable
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app import audit, drivers, lifecycle, priorities, rulename
from app.api.deps import DB, SettingsDep
from app.db import lock_row
from app.interviews import SystemRisks, system_risks
from app.models import (
    BusinessDriver,
    ComplianceDriver,
    ComplianceSource,
    L1UseCase,
    L2UseCase,
    L3UseCase,
    Lifecycle,
    ReferenceItem,
    RefKind,
    Role,
    System,
    SystemLink,
    User,
)
from app.schemas import (
    CatalogueSummary,
    L1Create,
    L1Out,
    L1Update,
    L2Create,
    L2Out,
    L2Update,
    L3Create,
    L3Out,
    L3Update,
    LinkedSystem,
)
from app.score_queries import open_issues
from app.scoring import RuleInput, score_rule
from app.security import Admin, Editor, Reader, as_utc

router = APIRouter(tags=["use cases"])

L3_REF_FIELDS = {
    "log_sources": RefKind.log_source,
    "detection_technologies": RefKind.detection_technology,
    "scopes": RefKind.scope,
}


def _pairs(result) -> dict:
    return {k: v for k, v in result.all()}


def _404(what: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")


def _by_code(db: Session, model, code: str, what: str):
    obj = db.scalar(select(model).where(model.code == code))
    if obj is None:
        raise _404(what)
    return obj


def _ensure_unique(db: Session, model, code: str) -> None:
    if db.scalar(select(model.id).where(model.code == code)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Identifier {code} already exists")


def _refs(db: Session, kind: RefKind, names: list[str]) -> list[ReferenceItem]:
    names = list(dict.fromkeys(names))
    items = list(
        db.scalars(
            select(ReferenceItem).where(ReferenceItem.kind == kind, ReferenceItem.name.in_(names))
        )
    )
    missing = set(names) - {i.name for i in items}
    if missing:
        raise HTTPException(
            422,
            f"Unknown {kind.value.replace('_', ' ')}: {', '.join(sorted(missing))}",
        )
    return items


def _business_drivers(db: Session, codes: list[str]) -> list[BusinessDriver]:
    codes = list(dict.fromkeys(codes))
    items = list(db.scalars(select(BusinessDriver).where(BusinessDriver.code.in_(codes))))
    missing = set(codes) - {i.code for i in items}
    if missing:
        raise HTTPException(422, f"Unknown business driver: {', '.join(sorted(missing))}")
    return items


def _compliance_drivers(db: Session, ids: list[int]) -> list[ComplianceDriver]:
    ids = list(dict.fromkeys(ids))
    items = list(db.scalars(select(ComplianceDriver).where(ComplianceDriver.id.in_(ids))))
    missing = set(ids) - {i.id for i in items}
    if missing:
        raise HTTPException(422, f"Unknown compliance driver id: {sorted(missing)}")
    return items


def _check_unchanged(db: Session, obj, data: dict[str, Any]) -> None:
    """Refuse an edit that started from an older version, so two people working on the same use
    case do not silently overwrite each other (the form sends every field)."""
    expected = data.pop("expected_updated_at", None)
    if expected is None or obj.updated_at is None:
        return
    lock_row(db, obj)  # concurrent saves are checked one after the other (audit L6)
    if abs((as_utc(obj.updated_at) - as_utc(expected)).total_seconds()) > 0.001:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{obj.code} was changed by someone else after you opened it. Reload the page and "
            "apply your changes again.",
        )


def _apply(obj, data: dict[str, Any], user: User) -> dict[str, Any]:
    """Set plain fields, return the audit diff. Verification date also records who verified."""
    before = {k: getattr(obj, k) for k in data}
    new_status = data.pop("lifecycle_status", None)
    if new_status is not None and new_status != obj.lifecycle_status:
        problem = lifecycle.transition_error(obj.lifecycle_status if obj.id else None, new_status)
        if problem:
            raise HTTPException(422, problem)
        lifecycle.apply_status(obj, new_status)
        data = data | {"lifecycle_status": new_status}
    elif new_status is not None:
        data = data | {"lifecycle_status": new_status}
    for k, v in data.items():
        if k != "lifecycle_status":
            setattr(obj, k, v)
    # also when only links changed (log sources, drivers): the next stale save must be noticed
    obj.updated_at = datetime.now(UTC)
    if "last_verified_at" in data and data["last_verified_at"] != before["last_verified_at"]:
        obj.last_verified_by = user.username if data["last_verified_at"] else None
    return audit.diff(before, data)


def _status_change(db: Session, obj, old: Lifecycle | None, user: User) -> None:
    """Log a status change made by a plain edit; Operational still needs the definition of done."""
    if obj.id is None:
        db.flush()
    new = obj.lifecycle_status
    if new == old:
        return
    missing = lifecycle.dod_missing(obj) if new == Lifecycle.operational else []
    if missing and user.role != Role.admin:
        raise HTTPException(
            422,
            "Definition of done is not complete; tick the checklist or ask an admin",
        )
    if new == Lifecycle.operational and obj.onboarded_at is None:
        obj.onboarded_at = date.today()
    lifecycle.record_change(db, obj, old, new, user.username, override=bool(missing))


# ---------------------------------------------------------------- serializers


def l2_out(l2: L2UseCase, l3_count: int | None = None) -> L2Out:
    return L2Out(
        id=l2.id,
        code=l2.code,
        l1_code=l2.parent.code,
        name=l2.name,
        description=l2.description,
        lifecycle_status=l2.lifecycle_status,
        risk_level=l2.risk_level,
        target_implementation=l2.target_implementation,
        onboarded_at=l2.onboarded_at,
        last_verified_at=l2.last_verified_at,
        last_verified_by=l2.last_verified_by,
        updated_at=l2.updated_at,
        actors=sorted(a.name for a in l2.actors),
        business_drivers=sorted(b.code for b in l2.business_drivers),
        compliance_driver_ids=sorted(c.id for c in l2.compliance_drivers),
        compliance_drivers=drivers.compliance_refs(l2.compliance_drivers),
        l3_count=len(l2.children) if l3_count is None else l3_count,
        systems=[
            LinkedSystem(id=x.id, name=x.name, archived=x.archived) for x in l2.linked_systems
        ],
    )


def l3_out(
    l3: L3UseCase,
    default_interval: int = 180,
    targets: dict[int, float] | None = None,
    issues: dict[int, date] | None = None,
    system_risks: SystemRisks | None = None,
    siem_name: Callable[[L3UseCase], str] | None = None,
) -> L3Out:
    score = score_rule(
        RuleInput(
            l3.code,
            l3.parent.code,
            l3.lifecycle_status,
            l3.effectiveness,
            l3.implementation,
            l3.coverage,
            l3.last_verified_at,
            l3.verification_interval_days,
        ),
        date.today(),
        default_interval,
    )
    eff = priorities.effective(
        l3,
        targets or priorities.DEFAULT_RISK_TARGETS,
        score.potential,
        system_risks.for_rule(l3) if system_risks else None,
    )
    by_kind: dict[RefKind, list[str]] = {k: [] for k in RefKind}
    for r in l3.references:
        by_kind[r.kind].append(r.name)
    return L3Out(
        id=l3.id,
        code=l3.code,
        l1_code=l3.code[:2],
        l2_code=l3.parent.code,
        name=l3.name,
        description=l3.description,
        effectiveness=l3.effectiveness,
        implementation=l3.implementation,
        coverage=l3.coverage,
        lifecycle_status=l3.lifecycle_status,
        comments=l3.comments,
        attack_techniques=l3.attack_techniques or [],
        siem_rule_ids=l3.siem_rule_ids or [],
        siem_name=siem_name(l3) if siem_name else None,
        onboarded_at=l3.onboarded_at,
        last_verified_at=l3.last_verified_at,
        last_verified_by=l3.last_verified_by,
        verification_interval_days=l3.verification_interval_days,
        risk_level=l3.risk_level,
        target_implementation=l3.target_implementation,
        effective_risk=eff.risk,
        risk_source=eff.risk_source,
        risk_system=eff.risk_system,
        effective_target=eff.target,
        target_source=eff.target_source,
        implementation_gap=eff.gap,
        priority=eff.priority,
        log_sources=sorted(by_kind[RefKind.log_source]),
        detection_technologies=sorted(by_kind[RefKind.detection_technology]),
        scopes=sorted(by_kind[RefKind.scope]),
        updated_at=l3.updated_at,
        business_drivers=sorted(b.code for b in l3.parent.business_drivers),
        compliance_drivers=drivers.compliance_refs(l3.parent.compliance_drivers),
        weight=score.weight,
        potential=score.potential,
        assessed=score.assessed,
        scored=score.scored,
        verification_due=score.verification_due,
        verification_overdue=score.verification_overdue,
        issues_at=(issues or {}).get(l3.id),
    )


# ---------------------------------------------------------------- summary


@router.get("/catalogue/summary", response_model=CatalogueSummary)
def summary(_: Reader, db: DB) -> CatalogueSummary:
    def count(model) -> int:
        return db.scalar(select(func.count()).select_from(model))

    refs = _pairs(db.execute(select(ReferenceItem.kind, func.count()).group_by(ReferenceItem.kind)))
    return CatalogueSummary(
        l1=count(L1UseCase),
        l2=count(L2UseCase),
        l3=count(L3UseCase),
        business_drivers=count(BusinessDriver),
        compliance_drivers=count(ComplianceDriver),
        references={k.value: refs.get(k, 0) for k in RefKind},
    )


# ---------------------------------------------------------------- L1


def _l1_out(db: Session, l1s: list[L1UseCase]) -> list[L1Out]:
    l2c = _pairs(db.execute(select(L2UseCase.l1_id, func.count()).group_by(L2UseCase.l1_id)))
    l3c = _pairs(
        db.execute(
            select(L2UseCase.l1_id, func.count(L3UseCase.id))
            .join(L3UseCase, L3UseCase.l2_id == L2UseCase.id)
            .group_by(L2UseCase.l1_id)
        )
    )
    # L1 inherits the drivers of its L2 use cases (read-only)
    bd: dict[int, set[str]] = {}
    cd: dict[int, list[ComplianceDriver]] = {}
    for l2 in db.scalars(
        select(L2UseCase).options(
            selectinload(L2UseCase.business_drivers),
            selectinload(L2UseCase.compliance_drivers).selectinload(ComplianceDriver.source),
        )
    ):
        bd.setdefault(l2.l1_id, set()).update(b.code for b in l2.business_drivers)
        cd.setdefault(l2.l1_id, []).extend(l2.compliance_drivers)
    return [
        L1Out.model_validate(l1).model_copy(
            update={
                "l2_count": l2c.get(l1.id, 0),
                "l3_count": l3c.get(l1.id, 0),
                "business_drivers": sorted(bd.get(l1.id, set())),
                "compliance_drivers": drivers.compliance_refs(cd.get(l1.id, [])),
            }
        )
        for l1 in l1s
    ]


@router.get("/l1", response_model=list[L1Out])
def list_l1(_: Reader, db: DB) -> list[L1Out]:
    return _l1_out(db, list(db.scalars(select(L1UseCase).order_by(L1UseCase.sort_order))))


@router.get("/l1/{code}", response_model=L1Out)
def get_l1(code: str, _: Reader, db: DB) -> L1Out:
    return _l1_out(db, [_by_code(db, L1UseCase, code, "L1 use case")])[0]


@router.post("/l1", response_model=L1Out, status_code=201)
def create_l1(body: L1Create, user: Editor, db: DB) -> L1Out:
    _ensure_unique(db, L1UseCase, body.code)
    l1 = L1UseCase(**body.model_dump())
    db.add(l1)
    audit.record(db, user, "create", "l1", body.code, body.model_dump())
    db.commit()
    return _l1_out(db, [l1])[0]


@router.patch("/l1/{code}", response_model=L1Out)
def update_l1(code: str, body: L1Update, user: Editor, db: DB) -> L1Out:
    l1 = _by_code(db, L1UseCase, code, "L1 use case")
    changes = _apply(l1, body.model_dump(exclude_unset=True), user)
    audit.record(db, user, "update", "l1", code, changes)
    db.commit()
    return _l1_out(db, [l1])[0]


@router.delete("/l1/{code}", status_code=204)
def delete_l1(code: str, user: Admin, db: DB) -> None:
    l1 = _by_code(db, L1UseCase, code, "L1 use case")
    if l1.children:
        raise HTTPException(status.HTTP_409_CONFLICT, "Delete or move its L2 use cases first")
    audit.record(db, user, "delete", "l1", code)
    db.delete(l1)
    db.commit()


# ---------------------------------------------------------------- L2


def _l2_query():
    return select(L2UseCase).options(
        selectinload(L2UseCase.parent),
        selectinload(L2UseCase.actors),
        selectinload(L2UseCase.business_drivers),
        selectinload(L2UseCase.compliance_drivers).selectinload(ComplianceDriver.source),
        selectinload(L2UseCase.linked_systems),
    )


def _set_l2_relations(db: Session, l2: L2UseCase, data: dict[str, Any]) -> dict[str, Any]:
    changes = {}
    if (names := data.pop("actors", None)) is not None:
        changes["actors"] = [sorted(a.name for a in l2.actors), sorted(set(names))]
        l2.actors = _refs(db, RefKind.threat_actor, names)
    if (codes := data.pop("business_drivers", None)) is not None:
        changes["business_drivers"] = [sorted(b.code for b in l2.business_drivers), sorted(codes)]
        l2.business_drivers = _business_drivers(db, codes)
    if (ids := data.pop("compliance_driver_ids", None)) is not None:
        old = sorted(drivers.compliance_label(c) for c in l2.compliance_drivers)
        l2.compliance_drivers = _compliance_drivers(db, ids)
        changes["compliance_drivers"] = [
            old,
            sorted(drivers.compliance_label(c) for c in l2.compliance_drivers),
        ]
    return {k: v for k, v in changes.items() if v[0] != v[1]}


@router.get("/l2", response_model=list[L2Out])
def list_l2(
    _: Reader,
    db: DB,
    l1: str | None = None,
    business_driver: str | None = Query(None, description="Business driver code"),
    compliance_driver: int | None = Query(None, description="Compliance driver id"),
    compliance_source: int | None = Query(None, description="Compliance source id"),
    system: int | None = Query(None, description="System id (L2 linked by its last interview)"),
) -> list[L2Out]:
    q = _l2_query().order_by(L2UseCase.code)
    if l1:
        q = q.join(L2UseCase.parent).where(L1UseCase.code == l1)
    if business_driver:
        q = q.where(L2UseCase.business_drivers.any(BusinessDriver.code == business_driver))
    if compliance_driver is not None:
        q = q.where(L2UseCase.compliance_drivers.any(ComplianceDriver.id == compliance_driver))
    if compliance_source is not None:
        q = q.where(
            L2UseCase.compliance_drivers.any(
                ComplianceDriver.source.has(ComplianceSource.id == compliance_source)
            )
        )
    if system is not None:
        q = q.where(L2UseCase.linked_systems.any(System.id == system))
    counts = _pairs(db.execute(select(L3UseCase.l2_id, func.count()).group_by(L3UseCase.l2_id)))
    return [l2_out(x, counts.get(x.id, 0)) for x in db.scalars(q)]


@router.get("/l2/{code}", response_model=L2Out)
def get_l2(code: str, _: Reader, db: DB) -> L2Out:
    return l2_out(_by_code(db, L2UseCase, code, "L2 use case"))


@router.post("/l2", response_model=L2Out, status_code=201)
def create_l2(body: L2Create, user: Editor, db: DB) -> L2Out:
    _ensure_unique(db, L2UseCase, body.code)
    parent = db.scalar(select(L1UseCase).where(L1UseCase.code == body.code[:2]))
    if parent is None:
        raise HTTPException(422, f"No L1 use case with identifier {body.code[:2]}")
    data = body.model_dump(exclude_unset=True)
    l2 = L2UseCase(parent=parent, code=data.pop("code"), name=data.pop("name"))
    db.add(l2)
    rel = _set_l2_relations(db, l2, data)
    _apply(l2, data, user)
    _status_change(db, l2, None, user)
    audit.record(db, user, "create", "l2", l2.code, body.model_dump() | rel)
    db.commit()
    return l2_out(l2)


@router.patch("/l2/{code}", response_model=L2Out)
def update_l2(code: str, body: L2Update, user: Editor, db: DB) -> L2Out:
    l2 = _by_code(db, L2UseCase, code, "L2 use case")
    data = body.model_dump(exclude_unset=True)
    _check_unchanged(db, l2, data)
    old = l2.lifecycle_status
    changes = _set_l2_relations(db, l2, data) | _apply(l2, data, user)
    _status_change(db, l2, old, user)
    audit.record(db, user, "update", "l2", code, changes)
    db.commit()
    return l2_out(l2)


@router.delete("/l2/{code}", status_code=204, response_model=None)
def delete_l2(
    code: str,
    user: Admin,
    db: DB,
    confirm: bool = Query(False, description="Also remove the links of systems to this L2"),
) -> JSONResponse | None:
    l2 = _by_code(db, L2UseCase, code, "L2 use case")
    if l2.children:
        raise HTTPException(status.HTTP_409_CONFLICT, "Delete or move its L3 rules first")
    # issue #48: systems linked through an interview lose the link, so say so first
    systems = sorted(s.name for s in l2.linked_systems)
    if systems and not confirm:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "detail": f"{code} is linked to {len(systems)} systems; "
                "repeat with confirm=true to remove the links",
                "systems": systems,
            },
        )
    audit.record(db, user, "delete", "l2", code, {"unlinked_systems": systems} if systems else None)
    for name in systems:
        audit.record(db, user, "unlink", "system", name, {"l2": code, "reason": "L2 deleted"})
    db.delete(l2)
    db.commit()
    return None


# ---------------------------------------------------------------- L3


def _set_l3_refs(db: Session, l3: L3UseCase, data: dict[str, Any]) -> dict[str, Any]:
    changes = {}
    current = {
        k: sorted(r.name for r in l3.references if r.kind == kind)
        for k, kind in L3_REF_FIELDS.items()
    }
    new_items = {
        k: [r for r in l3.references if r.kind == kind] for k, kind in L3_REF_FIELDS.items()
    }
    touched = False
    for field, kind in L3_REF_FIELDS.items():
        names = data.pop(field, None)
        if names is None:
            continue
        touched = True
        new_items[field] = _refs(db, kind, names)
        if sorted(set(names)) != current[field]:
            changes[field] = [current[field], sorted(set(names))]
    if touched:
        l3.references = [r for items in new_items.values() for r in items]
    return changes


def _l3_response(db: Session, settings, l3: L3UseCase) -> L3Out:
    """One rule as the API shows it; the context is read for this rule only."""
    return l3_out(
        l3,
        settings.default_verification_days,
        settings.risk_target_map,
        open_issues(db, ids=[l3.id]),
        system_risks(db, l3),
        rulename.formatter(db),
    )


@router.get("/l3", response_model=list[L3Out])
def list_l3(
    _: Reader,
    db: DB,
    settings: SettingsDep,
    l2: str | None = None,
    l1: str | None = None,
    status_: Lifecycle | None = Query(None, alias="status"),
) -> list[L3Out]:
    q = (
        select(L3UseCase)
        .options(*drivers.l3_parent_options(), selectinload(L3UseCase.references))
        .order_by(L3UseCase.code)
    )
    if l2:
        q = q.where(L3UseCase.code.startswith(l2 + "-"))
    if l1:
        q = q.where(L3UseCase.code.startswith(l1 + "-"))
    if status_:
        q = q.where(L3UseCase.lifecycle_status == status_)
    targets = settings.risk_target_map
    issues = open_issues(db)
    risks = system_risks(db)
    name = rulename.formatter(db)
    return [
        l3_out(x, settings.default_verification_days, targets, issues, risks, name)
        for x in db.scalars(q)
    ]


@router.get("/l3/{code}", response_model=L3Out)
def get_l3(code: str, _: Reader, db: DB, settings: SettingsDep) -> L3Out:
    return _l3_response(db, settings, _by_code(db, L3UseCase, code, "L3 rule"))


@router.post("/l3", response_model=L3Out, status_code=201)
def create_l3(body: L3Create, user: Editor, db: DB, settings: SettingsDep) -> L3Out:
    _ensure_unique(db, L3UseCase, body.code)
    l2_code = body.code[:6]  # XX-YYY; extra identifiers may follow
    parent = db.scalar(select(L2UseCase).where(L2UseCase.code == l2_code))
    if parent is None:
        raise HTTPException(422, f"No L2 use case with identifier {l2_code}")
    data = body.model_dump(exclude_unset=True)
    # A new rule is onboarded from the day it is created unless a date is given (issue #27);
    # an explicit null leaves it empty.
    data.setdefault("onboarded_at", date.today())
    l3 = L3UseCase(parent=parent, code=data.pop("code"), name=data.pop("name"), references=[])
    db.add(l3)
    _set_l3_refs(db, l3, data)
    _apply(l3, data, user)
    _status_change(db, l3, None, user)
    audit.record(db, user, "create", "l3", l3.code, body.model_dump())
    db.commit()
    return _l3_response(db, settings, l3)


@router.patch("/l3/{code}", response_model=L3Out)
def update_l3(code: str, body: L3Update, user: Editor, db: DB, settings: SettingsDep) -> L3Out:
    l3 = _by_code(db, L3UseCase, code, "L3 rule")
    data = body.model_dump(exclude_unset=True)
    _check_unchanged(db, l3, data)
    old = l3.lifecycle_status
    changes = _set_l3_refs(db, l3, data) | _apply(l3, data, user)
    _status_change(db, l3, old, user)
    audit.record(db, user, "update", "l3", code, changes)
    db.commit()
    return _l3_response(db, settings, l3)


@router.delete("/l3/{code}", status_code=204, response_model=None)
def delete_l3(
    code: str,
    user: Admin,
    db: DB,
    confirm: bool = Query(False, description="Also remove the links of systems to this rule"),
) -> JSONResponse | None:
    l3 = _by_code(db, L3UseCase, code, "L3 rule")
    # same as for an L2 (#48): systems linked to this very rule lose the link, so say so first
    systems = sorted(
        db.scalars(
            select(System.name)
            .join(SystemLink, SystemLink.system_id == System.id)
            .where(SystemLink.l3_id == l3.id)
            .distinct()
        )
    )
    if systems and not confirm:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "detail": f"{code} is linked to {len(systems)} systems; "
                "repeat with confirm=true to remove the links",
                "systems": systems,
            },
        )
    audit.record(db, user, "delete", "l3", code, {"unlinked_systems": systems} if systems else None)
    for name in systems:
        audit.record(db, user, "unlink", "system", name, {"l3": code, "reason": "L3 deleted"})
    db.delete(l3)
    db.commit()
    return None


@router.get("/l3/next-code/{l2_code}")
def next_l3_code(l2_code: str, _: Reader, db: DB) -> dict[str, str]:
    """Suggest the next free sequence number for a new rule under an L2 use case."""
    _by_code(db, L2UseCase, l2_code, "L2 use case")
    codes = db.scalars(select(L3UseCase.code).where(L3UseCase.code.startswith(l2_code + "-")))
    nums = [int(c.rsplit("-", 1)[1]) for c in codes if c.rsplit("-", 1)[1].isdigit()]
    return {"code": f"{l2_code}-{(max(nums, default=0) + 1):02d}"}
