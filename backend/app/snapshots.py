"""Snapshots of the computed scores, scheduled snapshots and trend series (PLAN 2.6)."""

import logging
import threading
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.db import try_job_lock
from app.models import (
    ConfigCommit,
    L1UseCase,
    L3UseCase,
    Lifecycle,
    LifecycleEvent,
    ReferenceItem,
    RefKind,
    Snapshot,
    l3_references,
)
from app.score_queries import compute_scores
from app.scoring import SCORED_STATES

log = logging.getLogger(__name__)

SCHEDULES = {"daily": timedelta(days=1), "weekly": timedelta(days=7), "monthly": timedelta(days=30)}

# Control metrics shown on the trends page; all are stored in each snapshot under "kpis".
METRICS = [
    ("soc_detection_score", "SOC detection score", "pct"),
    ("catalogue_coverage", "Catalogue coverage", "pct"),
    ("growth_potential", "Growth potential", "pct"),
    ("framework_completeness", "Framework completeness", "pct"),
    ("assessment_coverage", "Assessment coverage", "pct"),
    ("verification_health", "Verification health", "pct"),
    ("l2_with_rules", "L2 use cases with rules", "count"),
    ("rules", "L3 rules", "count"),
    ("operational_rules", "Operational rules", "count"),
    ("log_sources_used", "Log sources in use", "count"),
    ("scopes_used", "Scopes in use", "count"),
]


def _r(v: float | None) -> float | None:
    return None if v is None else round(v, 4)


def capture(db: Session, default_interval: int, today: date | None = None) -> dict:
    """All numbers a snapshot keeps: KPIs, per-L1 and per-L2 scores and per-rule state."""
    res, l1s, l2s, l3s = compute_scores(db, default_interval, today)
    k = res.kpis
    used = dict(
        db.execute(
            select(ReferenceItem.kind, func.count(func.distinct(ReferenceItem.id)))
            .join(l3_references, l3_references.c.item_id == ReferenceItem.id)
            .join(L3UseCase, L3UseCase.id == l3_references.c.l3_id)
            .where(L3UseCase.lifecycle_status.in_(list(SCORED_STATES)))
            .group_by(ReferenceItem.kind)
        ).all()
    )
    l2_with_rules = len({x.l2_id for x in l3s})
    kpis = {key: _r(v) if isinstance(v, float) else v for key, v in vars(k).items()}
    kpis |= {
        "l2_total": len(l2s),
        "l2_with_rules": l2_with_rules,
        "rules": len(l3s),
        "operational_rules": sum(1 for x in l3s if x.lifecycle_status in SCORED_STATES),
        "log_sources_used": used.get(RefKind.log_source, 0),
        "scopes_used": used.get(RefKind.scope, 0),
    }
    return {
        "kpis": kpis,
        "status_counts": {
            s.value: sum(1 for x in l3s if x.lifecycle_status == s) for s in Lifecycle
        },
        "l1": {
            x.code: {
                "name": x.name,
                "weight": _r(res.l1[x.code].weight),
                "rules": res.l1[x.code].rules,
            }
            for x in l1s
        },
        "l2": {
            x.code: {
                "name": x.name,
                "weight": _r(res.l2[x.code].weight),
                "rules": res.l2[x.code].rules,
            }
            for x in l2s
        },
        "rules": {
            x.code: {
                "name": x.name,
                "status": x.lifecycle_status.value,
                "e": x.effectiveness,
                "i": x.implementation,
                "c": x.coverage,
                "weight": _r(res.rules[x.code].weight),
            }
            for x in l3s
        },
    }


def take(
    db: Session,
    default_interval: int,
    label: str = "",
    kind: str = "manual",
    by: str = "system",
    at: datetime | None = None,
) -> Snapshot:
    snap = Snapshot(
        label=label,
        kind=kind,
        taken_by=by,
        taken_at=at or datetime.now(UTC),
        data=capture(db, default_interval),
    )
    db.add(snap)
    db.flush()
    return snap


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def compare(a: dict, b: dict) -> dict:
    """What changed between two snapshot data dicts (a = older, b = newer)."""
    kpis = {
        k: {"a": a["kpis"].get(k), "b": b["kpis"].get(k)}
        for k in dict.fromkeys([*a["kpis"], *b["kpis"]])
    }

    def groups(level: str) -> list[dict]:
        out = []
        for code in sorted(set(a.get(level, {})) | set(b.get(level, {}))):
            x, y = a.get(level, {}).get(code), b.get(level, {}).get(code)
            if x == y:
                continue
            out.append(
                {
                    "code": code,
                    "name": (y or x)["name"],
                    "change": "added" if x is None else "removed" if y is None else "changed",
                    "a": x,
                    "b": y,
                }
            )
        return out

    return {"kpis": kpis, "l1": groups("l1"), "l2": groups("l2"), "rules": groups("rules")}


def framework_changes(db: Session, since: datetime, until: datetime) -> dict:
    """Lifecycle events and config commits in a period ("framework changes" control metric)."""
    ev = db.scalar(
        select(func.count())
        .select_from(LifecycleEvent)
        .where(LifecycleEvent.at > since, LifecycleEvent.at <= until)
    )
    cc = db.scalar(
        select(func.count())
        .select_from(ConfigCommit)
        .where(ConfigCommit.created_at > since, ConfigCommit.created_at <= until)
    )
    return {"lifecycle_changes": ev or 0, "config_commits": cc or 0}


def due(db: Session, schedule: str, now: datetime | None = None) -> bool:
    step = SCHEDULES.get(schedule)
    if step is None:
        return False
    last = db.scalar(
        select(func.max(Snapshot.taken_at)).where(Snapshot.kind.in_(["scheduled", "demo"]))
    )
    now = now or datetime.now(UTC)
    if schedule == "monthly":
        return last is None or (_aware(last).year, _aware(last).month) != (now.year, now.month)
    return last is None or now - _aware(last) >= step


def run_scheduled(factory: sessionmaker, schedule: str, default_interval: int) -> bool:
    with factory() as db:
        if not try_job_lock(db, "snapshots"):
            return False  # another replica is taking it
        if not db.scalar(select(func.count()).select_from(L1UseCase)) or not due(db, schedule):
            return False
        take(
            db,
            default_interval,
            label=f"{schedule.capitalize()} {date.today().isoformat()}",
            kind="scheduled",
        )
        db.commit()
        log.info("Took %s snapshot", schedule)
        return True


class Scheduler:
    """Background thread that takes a scheduled snapshot when one is due (checked hourly)."""

    def __init__(self, factory: sessionmaker, schedule: str, default_interval: int):
        self.factory, self.schedule, self.interval = factory, schedule, default_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.schedule not in SCHEDULES:
            return
        self._thread = threading.Thread(target=self._loop, name="snapshots", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                run_scheduled(self.factory, self.schedule, self.interval)
            except Exception:
                log.exception("Scheduled snapshot failed")
            self._stop.wait(3600)

    def stop(self) -> None:
        self._stop.set()
