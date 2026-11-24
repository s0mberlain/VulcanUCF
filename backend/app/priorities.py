"""Risk-based prioritisation: risk level and target implementation per rule (PLAN 2.11)."""

from dataclasses import dataclass

from app.drivers import driver_boost, link_count
from app.models import L3UseCase

DEFAULT_RISK_TARGETS = {1: 0.4, 2: 0.5, 3: 0.6, 4: 0.75, 5: 0.9}


def parse_risk_targets(raw: str) -> dict[int, float]:
    """ "1=0.4,2=0.5,..." -> {1: 0.4, ...}; levels that are missing or invalid keep the default."""
    out = dict(DEFAULT_RISK_TARGETS)
    for part in raw.split(","):
        k, _, v = part.partition("=")
        try:
            level, target = int(k.strip()), float(v.strip())
        except ValueError:
            continue
        if 1 <= level <= 5 and 0 <= target <= 1:
            out[level] = target
    return out


@dataclass
class Effective:
    risk: int | None
    risk_source: str | None  # rule | l2 | system
    target: float | None
    target_source: str | None  # rule | l2 | risk
    gap: float | None  # target - implementation, never below 0
    # gap to target x risk / 5 x driver boost: a rule at or above its target has priority 0, a
    # rule without an implementation score counts its whole target as gap (not assessed yet)
    priority: float | None
    drivers: int = 0  # business + compliance drivers linked to the rule's L2
    boost: float = 1.0
    risk_system: str | None = None  # the system that raised the risk (risk_source "system")


def effective(
    rule: L3UseCase,
    targets: dict[int, float],
    potential: float | None,
    system_risk: tuple[int, str] | None = None,
) -> Effective:
    """`system_risk`: (level, system name) when the rule or its L2 is linked to a non-archived
    system (app/interviews.py SystemRisks); the higher of it and the own risk level is used."""
    l2 = rule.parent
    if rule.risk_level is not None:
        risk, rsrc = rule.risk_level, "rule"
    elif l2.risk_level is not None:
        risk, rsrc = l2.risk_level, "l2"
    else:
        risk, rsrc = None, None
    risk_system = None
    if system_risk is not None and system_risk[0] > (risk or 0):
        risk, rsrc, risk_system = system_risk[0], "system", system_risk[1]
    if rule.target_implementation is not None:
        target, tsrc = rule.target_implementation, "rule"
    elif l2.target_implementation is not None:
        target, tsrc = l2.target_implementation, "l2"
    elif risk is not None:
        target, tsrc = targets[risk], "risk"
    else:
        target, tsrc = None, None
    gap = None
    if target is not None and rule.implementation is not None:
        gap = round(max(0.0, target - rule.implementation), 4)
    elif target is not None:
        gap = target
    links = link_count(l2)
    boost = driver_boost(links)
    priority = None
    if risk is not None and gap is not None:
        priority = round(gap * risk / 5 * boost, 4)
    return Effective(risk, rsrc, target, tsrc, gap, priority, links, boost, risk_system)
