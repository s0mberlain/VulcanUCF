"""Gap to target (risk-based prioritisation)."""

from datetime import date

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import select

from app import drivers, growth
from app.api.deps import DB, SettingsDep
from app.interviews import system_risks
from app.models import L3UseCase, Lifecycle
from app.schemas import DriverCoverage
from app.scoring import RuleInput, score_rule
from app.security import Reader

router = APIRouter(tags=["growth"])

ACTIVE = (Lifecycle.onboarding, Lifecycle.operational, Lifecycle.maintenance)


class GapRow(BaseModel):
    code: str
    name: str
    l2_code: str
    l2_name: str
    lifecycle_status: Lifecycle
    effectiveness: float | None
    implementation: float | None
    coverage: float | None
    weight: float | None
    potential: float | None
    risk: int | None
    risk_source: str | None
    risk_system: str | None = None
    target: float | None
    target_source: str | None
    gap: float | None
    priority: float | None
    business_drivers: list[str] = []
    compliance_drivers: list[str] = []
    driver_boost: float = 1.0


class GapSummary(BaseModel):
    rules: int
    with_target: int
    below_target: int
    no_risk: int
    avg_gap: float | None
    by_risk: dict[int, dict[str, int]]
    risk_targets: dict[int, float]


class GapsOut(BaseModel):
    summary: GapSummary
    rows: list[GapRow]
    # drivers without linked use cases, or whose use cases score below the threshold
    driver_gaps: list[DriverCoverage] = []
    driver_low_threshold: float = 0.3


@router.get("/growth/gaps", response_model=GapsOut)
def gaps(
    _: Reader,
    db: DB,
    settings: SettingsDep,
    l1: str | None = None,
    min_risk: int = Query(1, ge=1, le=5),
    below_target: bool = False,
) -> GapsOut:
    """Active rules with risk, target and the gap to it, most valuable work first."""
    targets = settings.risk_target_map
    q = (
        select(L3UseCase)
        .options(*drivers.l3_parent_options())
        .where(L3UseCase.lifecycle_status.in_(ACTIVE))
        .order_by(L3UseCase.code)
    )
    if l1:
        q = q.where(L3UseCase.code.startswith(l1.upper() + "-"))
    rows, all_rows = [], []
    sys_risk = system_risks(db)
    for r in db.scalars(q):
        s = score_rule(
            RuleInput(
                r.code,
                r.parent.code,
                r.lifecycle_status,
                r.effectiveness,
                r.implementation,
                r.coverage,
            ),
            date.today(),
            settings.default_verification_days,
        )
        # onboarding rules are not scored yet; still show what they would add
        potential = s.potential
        if potential is None and None not in (r.effectiveness, r.implementation, r.coverage):
            potential = r.effectiveness - r.effectiveness * r.implementation * r.coverage
        e = growth.effective(r, targets, potential, sys_risk.for_rule(r))
        row = GapRow(
            code=r.code,
            name=r.name,
            l2_code=r.parent.code,
            l2_name=r.parent.name,
            lifecycle_status=r.lifecycle_status,
            effectiveness=r.effectiveness,
            implementation=r.implementation,
            coverage=r.coverage,
            weight=s.weight,
            potential=potential,
            risk=e.risk,
            risk_source=e.risk_source,
            risk_system=e.risk_system,
            target=e.target,
            target_source=e.target_source,
            gap=e.gap,
            priority=e.priority,
            business_drivers=sorted(b.code for b in r.parent.business_drivers),
            compliance_drivers=sorted(
                drivers.compliance_label(c) for c in r.parent.compliance_drivers
            ),
            driver_boost=e.boost,
        )
        all_rows.append(row)
        if (row.risk or 0) < min_risk and min_risk > 1:
            continue
        if below_target and not row.gap:
            continue
        rows.append(row)
    rows.sort(
        key=lambda x: (
            -(x.priority or 0),
            -x.driver_boost,  # without a risk level, rules of driver-linked L2s still rank first
            -(x.gap or 0),
            x.code,
        )
    )
    with_target = [x for x in all_rows if x.target is not None]
    below = [x for x in with_target if x.gap]
    by_risk: dict[int, dict[str, int]] = {}
    for lvl in range(1, 6):
        at = [x for x in all_rows if x.risk == lvl]
        by_risk[lvl] = {"rules": len(at), "below_target": sum(1 for x in at if x.gap)}
    return GapsOut(
        summary=GapSummary(
            rules=len(all_rows),
            with_target=len(with_target),
            below_target=len(below),
            no_risk=sum(1 for x in all_rows if x.risk is None),
            avg_gap=round(sum(x.gap for x in below) / len(below), 4) if below else None,
            by_risk=by_risk,
            risk_targets=targets,
        ),
        rows=rows,
        driver_gaps=driver_gaps(db, settings),
        driver_low_threshold=settings.driver_low_coverage,
    )


def driver_gaps(db, settings) -> list[DriverCoverage]:
    """Uncovered drivers first, then low coverage, lowest first."""
    cov = drivers.coverage(db, settings.default_verification_days, settings.driver_low_coverage)
    items = [d for d in cov.business + cov.compliance if d.gap or d.low]
    items.sort(key=lambda d: (not d.gap, d.coverage or 0.0, d.source or "", d.code))
    return items
