"""Business layer (drivers, compliance) and reference lists."""

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app import audit, drivers, interviews
from app.api.deps import DB, SettingsDep
from app.models import (
    BusinessDriver,
    ComplianceDriver,
    ComplianceSource,
    L2UseCase,
    L3UseCase,
    ReferenceItem,
    RefKind,
    RoundDetection,
    l2_actors,
    l3_references,
)
from app.schemas import (
    BusinessDriverIn,
    BusinessDriverOut,
    ComplianceDriverIn,
    ComplianceDriverOut,
    ComplianceSourceIn,
    ComplianceSourceOut,
    DriverCoverageOut,
    RefItemIn,
    RefItemOut,
    RefItemUsageOut,
)
from app.security import Editor, Reader

router = APIRouter(tags=["business layer"])


def _commit(db, what: str) -> None:
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, f"{what} already exists or is in use") from e


def _get(db, model, id_: int):
    obj = db.get(model, id_)
    if not obj:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return obj


# ---------------------------------------------------------------- reference lists


@router.get("/references/{kind}", response_model=list[RefItemUsageOut])
def list_refs(kind: RefKind, _: Reader, db: DB) -> list[RefItemUsageOut]:
    """Entries of one list, each with the codes of what uses it: L2 use cases for threat actors
    (they are assigned to L2), L3 rules for the other kinds."""
    items = list(
        db.scalars(
            select(ReferenceItem).where(ReferenceItem.kind == kind).order_by(ReferenceItem.name)
        )
    )
    if kind == RefKind.threat_actor:
        links = select(l2_actors.c.item_id, L2UseCase.code).join(
            L2UseCase, L2UseCase.id == l2_actors.c.l2_id
        )
    else:
        links = select(l3_references.c.item_id, L3UseCase.code).join(
            L3UseCase, L3UseCase.id == l3_references.c.l3_id
        )
    systems = interviews.log_source_users(db) if kind == RefKind.log_source else {}
    used: dict[int, list[str]] = {}
    for item_id, code in db.execute(
        links.where(links.selected_columns[0].in_([i.id for i in items]))
    ):
        used.setdefault(item_id, []).append(code)
    return [
        RefItemUsageOut(
            id=i.id,
            kind=i.kind,
            name=i.name,
            description=i.description,
            used_by=sorted(used.get(i.id, [])),
            used_by_systems=systems.get(i.id, []),
        )
        for i in items
    ]


@router.post("/references/{kind}", response_model=RefItemOut, status_code=201)
def create_ref(kind: RefKind, body: RefItemIn, user: Editor, db: DB) -> ReferenceItem:
    item = ReferenceItem(kind=kind, **body.model_dump())
    db.add(item)
    audit.record(db, user, "create", kind.value, body.name, body.model_dump())
    _commit(db, "Entry")
    return item


@router.patch("/references/{kind}/{item_id}", response_model=RefItemOut)
def update_ref(kind: RefKind, item_id: int, body: RefItemIn, user: Editor, db: DB) -> ReferenceItem:
    item = _get(db, ReferenceItem, item_id)
    if item.kind != kind:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    data = body.model_dump()
    changes = audit.diff({k: getattr(item, k) for k in data}, data)
    for k, v in data.items():
        setattr(item, k, v)
    audit.record(db, user, "update", kind.value, item.name, changes)
    _commit(db, "Entry")
    return item


def _ref_users(db, item: ReferenceItem) -> list[str]:
    """Codes of the use cases and rules that use a reference list entry."""
    l2 = db.scalars(select(L2UseCase.code).where(L2UseCase.actors.any(ReferenceItem.id == item.id)))
    l3 = db.scalars(
        select(L3UseCase.code).where(L3UseCase.references.any(ReferenceItem.id == item.id))
    )
    return sorted([*l2, *l3])


@router.delete("/references/{kind}/{item_id}", status_code=204, response_model=None)
def delete_ref(
    kind: RefKind,
    item_id: int,
    user: Editor,
    db: DB,
    confirm: bool = Query(False, description="Also remove the entry from the use cases using it"),
) -> JSONResponse | None:
    item = _get(db, ReferenceItem, item_id)
    if item.kind != kind:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    used = _ref_users(db, item)
    systems = interviews.log_source_users(db).get(item.id, []) if kind == RefKind.log_source else []
    detections = (
        db.scalar(
            select(func.count())
            .select_from(RoundDetection)
            .where(RoundDetection.item_id == item.id)
        )
        if kind == RefKind.detection_technology
        else 0
    )
    if (used or systems or detections) and not confirm:
        parts = []
        if detections:
            parts.append(f"{detections} test results (the name stays there as text)")
        if used:
            parts.append(f"{len(used)} use cases or rules")
        if systems:
            parts.append(f"the interviews of {len(systems)} systems")
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "detail": f"{item.name} is used by {' and '.join(parts)}; "
                "repeat with confirm=true to remove it from them",
                "used_by": used,
                "used_by_systems": systems,
            },
        )
    changes = {"unlinked": used} if used else {}
    if systems:
        changes["systems"] = systems
    audit.record(db, user, "delete", kind.value, item.name, changes or None)
    db.delete(item)
    _commit(db, "Entry")
    return None


# ---------------------------------------------------------------- links and coverage


class LinkedUseCaseOut(BaseModel):
    code: str
    name: str
    l3_count: int


Confirm = Query(False, description="Also remove the links to use cases")


def _guard_links(linked: list, confirm: bool, what: str) -> JSONResponse | None:
    """Deleting a driver that is still linked needs confirm=true; the 409 lists the use cases."""
    if linked and not confirm:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "detail": f"{what} is linked to {len(linked)} L2 use cases; "
                "repeat with confirm=true to remove the links",
                "use_cases": drivers.linked_use_cases(linked),
            },
        )
    return None


@router.get("/drivers/coverage", response_model=DriverCoverageOut)
def driver_coverage(_: Reader, db: DB, settings: SettingsDep) -> DriverCoverageOut:
    """Per business driver, compliance driver and compliance source: linked use cases and
    their average weight. Drivers without links are gaps."""
    return drivers.coverage(db, settings.default_verification_days, settings.driver_low_coverage)


@router.get("/business-drivers/{bd_id}/use-cases", response_model=list[LinkedUseCaseOut])
def bd_use_cases(bd_id: int, _: Reader, db: DB) -> list[dict]:
    bd = _get(db, BusinessDriver, bd_id)
    return drivers.linked_use_cases(drivers.l2s_linked_to_business(db, bd))


@router.get("/compliance/drivers/{cd_id}/use-cases", response_model=list[LinkedUseCaseOut])
def cd_use_cases(cd_id: int, _: Reader, db: DB) -> list[dict]:
    cd = _get(db, ComplianceDriver, cd_id)
    return drivers.linked_use_cases(drivers.l2s_linked_to_compliance(db, [cd.id]))


@router.get("/compliance/{source_id}/use-cases", response_model=list[LinkedUseCaseOut])
def source_use_cases(source_id: int, _: Reader, db: DB) -> list[dict]:
    src = _get(db, ComplianceSource, source_id)
    return drivers.linked_use_cases(
        drivers.l2s_linked_to_compliance(db, [c.id for c in src.drivers])
    )


# ---------------------------------------------------------------- business drivers


@router.get("/business-drivers", response_model=list[BusinessDriverOut])
def list_bd(_: Reader, db: DB) -> list[BusinessDriver]:
    return list(db.scalars(select(BusinessDriver).order_by(BusinessDriver.code)))


@router.post("/business-drivers", response_model=BusinessDriverOut, status_code=201)
def create_bd(body: BusinessDriverIn, user: Editor, db: DB) -> BusinessDriver:
    bd = BusinessDriver(**body.model_dump())
    db.add(bd)
    audit.record(db, user, "create", "business_driver", body.code, body.model_dump())
    _commit(db, "Business driver")
    return bd


@router.patch("/business-drivers/{bd_id}", response_model=BusinessDriverOut)
def update_bd(bd_id: int, body: BusinessDriverIn, user: Editor, db: DB) -> BusinessDriver:
    bd = _get(db, BusinessDriver, bd_id)
    data = body.model_dump()
    changes = audit.diff({k: getattr(bd, k) for k in data}, data)
    for k, v in data.items():
        setattr(bd, k, v)
    audit.record(db, user, "update", "business_driver", bd.code, changes)
    _commit(db, "Business driver")
    return bd


@router.delete("/business-drivers/{bd_id}", status_code=204, response_model=None)
def delete_bd(bd_id: int, user: Editor, db: DB, confirm: bool = Confirm) -> JSONResponse | None:
    bd = _get(db, BusinessDriver, bd_id)
    linked = drivers.l2s_linked_to_business(db, bd)
    if blocked := _guard_links(linked, confirm, f"Business driver {bd.code}"):
        return blocked
    for l2 in linked:
        l2.business_drivers.remove(bd)
    audit.record(
        db, user, "delete", "business_driver", bd.code, {"unlinked": [x.code for x in linked]}
    )
    db.delete(bd)
    _commit(db, "Business driver")
    return None


# ---------------------------------------------------------------- compliance


@router.get("/compliance", response_model=list[ComplianceSourceOut])
def list_compliance(_: Reader, db: DB) -> list[ComplianceSource]:
    return list(db.scalars(select(ComplianceSource).order_by(ComplianceSource.id)))


@router.post("/compliance", response_model=ComplianceSourceOut, status_code=201)
def create_source(body: ComplianceSourceIn, user: Editor, db: DB) -> ComplianceSource:
    src = ComplianceSource(name=body.name)
    db.add(src)
    audit.record(db, user, "create", "compliance_source", body.name)
    _commit(db, "Compliance source")
    return src


@router.patch("/compliance/{source_id}", response_model=ComplianceSourceOut)
def rename_source(
    source_id: int, body: ComplianceSourceIn, user: Editor, db: DB
) -> ComplianceSource:
    src = _get(db, ComplianceSource, source_id)
    changes = audit.diff({"name": src.name}, {"name": body.name})
    src.name = body.name
    audit.record(db, user, "update", "compliance_source", body.name, changes)
    _commit(db, "Compliance source")
    return src


@router.delete("/compliance/{source_id}", status_code=204, response_model=None)
def delete_source(
    source_id: int, user: Editor, db: DB, confirm: bool = Confirm
) -> JSONResponse | None:
    src = _get(db, ComplianceSource, source_id)
    ids = {c.id for c in src.drivers}
    linked = drivers.l2s_linked_to_compliance(db, list(ids))
    if blocked := _guard_links(linked, confirm, f"Compliance source {src.name}"):
        return blocked
    for l2 in linked:
        l2.compliance_drivers = [c for c in l2.compliance_drivers if c.id not in ids]
    audit.record(
        db, user, "delete", "compliance_source", src.name, {"unlinked": [x.code for x in linked]}
    )
    db.delete(src)
    _commit(db, "Compliance source")
    return None


@router.post("/compliance/{source_id}/drivers", response_model=ComplianceDriverOut, status_code=201)
def create_cd(source_id: int, body: ComplianceDriverIn, user: Editor, db: DB) -> ComplianceDriver:
    src = _get(db, ComplianceSource, source_id)
    cd = ComplianceDriver(source=src, **body.model_dump())
    db.add(cd)
    audit.record(db, user, "create", "compliance_driver", f"{src.name}/{body.ref}")
    _commit(db, "Compliance driver")
    return cd


@router.patch("/compliance/drivers/{cd_id}", response_model=ComplianceDriverOut)
def update_cd(cd_id: int, body: ComplianceDriverIn, user: Editor, db: DB) -> ComplianceDriver:
    cd = _get(db, ComplianceDriver, cd_id)
    data = body.model_dump()
    changes = audit.diff({k: getattr(cd, k) for k in data}, data)
    for k, v in data.items():
        setattr(cd, k, v)
    audit.record(db, user, "update", "compliance_driver", cd.ref, changes)
    _commit(db, "Compliance driver")
    return cd


@router.delete("/compliance/drivers/{cd_id}", status_code=204, response_model=None)
def delete_cd(cd_id: int, user: Editor, db: DB, confirm: bool = Confirm) -> JSONResponse | None:
    cd = _get(db, ComplianceDriver, cd_id)
    label = drivers.compliance_label(cd)
    linked = drivers.l2s_linked_to_compliance(db, [cd.id])
    if blocked := _guard_links(linked, confirm, f"Compliance driver {label}"):
        return blocked
    for l2 in linked:
        l2.compliance_drivers.remove(cd)
    audit.record(
        db, user, "delete", "compliance_driver", label, {"unlinked": [x.code for x in linked]}
    )
    db.delete(cd)
    _commit(db, "Compliance driver")
    return None
