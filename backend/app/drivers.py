"""Business and compliance drivers linked to L2 use cases: coverage, gaps and priority boost.

A link is a plain link without a weight. Drivers are set on L2; its L3 rules and its L1 inherit
them (read-only).

Coverage of a driver = average weight (effectiveness x implementation x coverage, app/scoring.py)
of the L2 use cases linked to it. An L2 without scored rules is a detection gap and counts as 0,
so linking a driver to an empty use case does not make the driver look better. A driver without
any linked use case has no coverage and is flagged as a gap.
"""

from collections.abc import Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import (
    BusinessDriver,
    ComplianceDriver,
    ComplianceSource,
    L2UseCase,
    L3UseCase,
)
from app.schemas import ComplianceRef, DriverCoverage, DriverCoverageOut, SourceCoverage
from app.score_queries import compute_scores

# Each linked driver raises the priority of the L2's rules by 10 %, at most by 50 %.
BOOST_PER_DRIVER = 0.1
MAX_BOOSTED_DRIVERS = 5


def driver_boost(link_count: int) -> float:
    return round(1 + BOOST_PER_DRIVER * min(link_count, MAX_BOOSTED_DRIVERS), 4)


def link_count(l2: L2UseCase) -> int:
    return len(l2.business_drivers) + len(l2.compliance_drivers)


def compliance_label(c: ComplianceDriver) -> str:
    return f"{c.source.name} {c.ref}"


def compliance_refs(items: Iterable[ComplianceDriver]) -> list[ComplianceRef]:
    uniq = {c.id: c for c in items}.values()
    return [
        ComplianceRef(id=c.id, source_id=c.source_id, source=c.source.name, ref=c.ref, name=c.name)
        for c in sorted(uniq, key=lambda c: (c.source_id, c.ref))
    ]


def _avg(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 4) if values else None


def coverage(db: Session, default_interval: int, low_threshold: float) -> DriverCoverageOut:
    res, _l1s, _l2s, _l3s = compute_scores(db, default_interval)
    l2s = list(
        db.scalars(
            select(L2UseCase).options(
                selectinload(L2UseCase.business_drivers),
                selectinload(L2UseCase.compliance_drivers),
            )
        )
    )
    l3_count = dict(
        db.execute(select(L3UseCase.l2_id, func.count()).group_by(L3UseCase.l2_id)).all()
    )
    weight = {x.code: (res.l2[x.code].weight if x.code in res.l2 else None) for x in l2s}
    scored = {x.code for x in l2s if weight[x.code] is not None}

    by_bd: dict[int, list[L2UseCase]] = {}
    by_cd: dict[int, list[L2UseCase]] = {}
    for x in l2s:
        for b in x.business_drivers:
            by_bd.setdefault(b.id, []).append(x)
        for c in x.compliance_drivers:
            by_cd.setdefault(c.id, []).append(x)

    def row(obj_id: int, code: str, name: str, linked: list[L2UseCase], **extra) -> DriverCoverage:
        cov = _avg([weight[x.code] or 0.0 for x in linked])
        return DriverCoverage(
            id=obj_id,
            code=code,
            name=name,
            l2_count=len(linked),
            l3_count=sum(l3_count.get(x.id, 0) for x in linked),
            scored_l2=sum(1 for x in linked if x.code in scored),
            coverage=cov,
            gap=not linked,
            low=bool(linked) and (cov or 0.0) < low_threshold,
            l2_codes=sorted(x.code for x in linked),
            **extra,
        )

    business = [
        row(b.id, b.code, b.name, by_bd.get(b.id, []))
        for b in db.scalars(select(BusinessDriver).order_by(BusinessDriver.code))
    ]
    compliance: list[DriverCoverage] = []
    sources: list[SourceCoverage] = []
    for src in db.scalars(
        select(ComplianceSource)
        .options(selectinload(ComplianceSource.drivers))
        .order_by(ComplianceSource.id)
    ):
        rows = [
            row(c.id, c.ref, c.name, by_cd.get(c.id, []), source_id=src.id, source=src.name)
            for c in sorted(src.drivers, key=lambda c: c.ref)
        ]
        compliance += rows
        linked = {x.code: x for c in src.drivers for x in by_cd.get(c.id, [])}
        sources.append(
            SourceCoverage(
                id=src.id,
                name=src.name,
                drivers=len(rows),
                linked_drivers=sum(1 for r in rows if not r.gap),
                l2_count=len(linked),
                l3_count=sum(l3_count.get(x.id, 0) for x in linked.values()),
                coverage=_avg([weight[c] or 0.0 for c in linked]),
                gap_drivers=sum(1 for r in rows if r.gap),
                low_drivers=sum(1 for r in rows if r.low),
            )
        )
    return DriverCoverageOut(
        low_threshold=low_threshold, business=business, compliance=compliance, sources=sources
    )


def linked_use_cases(l2s: Iterable[L2UseCase]) -> list[dict]:
    """The L2 use cases behind a set of links, each with the number of L3 rules that inherit."""
    return [
        {"code": x.code, "name": x.name, "l3_count": len(x.children)}
        for x in sorted({x.id: x for x in l2s}.values(), key=lambda x: x.code)
    ]


def l2s_linked_to_business(db: Session, driver: BusinessDriver) -> list[L2UseCase]:
    return list(
        db.scalars(
            select(L2UseCase)
            .where(L2UseCase.business_drivers.any(BusinessDriver.id == driver.id))
            .order_by(L2UseCase.code)
        )
    )


def l2s_linked_to_compliance(db: Session, driver_ids: list[int]) -> list[L2UseCase]:
    if not driver_ids:
        return []
    return list(
        db.scalars(
            select(L2UseCase)
            .where(L2UseCase.compliance_drivers.any(ComplianceDriver.id.in_(driver_ids)))
            .order_by(L2UseCase.code)
        )
    )


def l3_parent_options() -> tuple:
    """Load an L3's parent L2 with its drivers in a few queries instead of one per rule."""
    parent = selectinload(L3UseCase.parent)
    return (
        parent.selectinload(L2UseCase.business_drivers),
        parent.selectinload(L2UseCase.compliance_drivers).selectinload(ComplianceDriver.source),
    )
