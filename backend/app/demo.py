"""Reproducible random demo data on top of the MaGMa catalogue (docs/PLAN.md section 7a).

Usage:
    python -m app.demo --seed 42          (uses DATABASE_URL)
    DEMO_DATA=true on first start         (applied once after seeding the catalogue)
    POST /api/admin/demo-data             (admin, overwrites the use case fields)

Only use case fields are overwritten; the catalogue itself (IDs, names) is kept.
"""

import argparse
import json
import logging
import random
from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import configs, lifecycle, snapshots
from app.dates import months_back
from app.models import (
    BusinessDriver,
    ComplianceDriver,
    ComplianceSource,
    ConfigCommit,
    L2UseCase,
    L3UseCase,
    Lifecycle,
    LifecycleEvent,
    OutputMetric,
    ReferenceItem,
    RefKind,
    Snapshot,
    Verification,
    VerificationResult,
)

log = logging.getLogger("magma.demo")

# Typical strength of a detection technology: (effectiveness, implementation, coverage) means.
TECH_PROFILE = {
    "SIEM": (0.70, 0.60, 0.60),
    "Big data analytics": (0.60, 0.45, 0.50),
    "NIDS/NIPS": (0.65, 0.65, 0.55),
    "HIPS": (0.75, 0.60, 0.65),
    "Anti-malware": (0.70, 0.80, 0.80),
    "Network anomaly detection": (0.55, 0.45, 0.50),
    "Email protection": (0.75, 0.75, 0.85),
}
DEFAULT_PROFILE = (0.6, 0.55, 0.55)

COMPLIANCE_REFS = {
    "Internal Security Policy": [
        ("ISP-4.1", "Logging"),
        ("ISP-7.2", "Access control"),
        ("ISP-9.3", "Security monitoring"),
    ],
    "External Regulator #1": [
        ("DORA-10", "DORA Art. 10 Detection"),
        ("DORA-17", "DORA Art. 17 ICT incident management"),
    ],
    "External Regulator #2": [("NIS2-21", "NIS2 Art. 21 Risk management measures")],
}

DEMO_MARK = "[demo rule]"
DEMO_RULE_KINDS = [
    "correlation rule",
    "threshold alert",
    "signature match",
    "anomaly baseline",
    "threat intel match",
]

NOTES_OK = [
    "Atomic Red Team test detected as expected",
    "Purple team exercise: alert fired within SLA",
    "Quarterly check, rule logic and data feed OK",
    "Replayed sample logs, alert raised",
]
NOTES_ISSUES = [
    "Missed one test variant, rule tuned afterwards",
    "Data source gap found on two hosts, ticket opened",
    "Too many false positives, threshold adjusted",
]


def _metric(rnd: random.Random, mean: float) -> float:
    return round(min(1.0, max(0.05, rnd.gauss(mean, 0.15))), 2)


def _pick(rnd: random.Random, items: list, lo: int, hi: int) -> list:
    return rnd.sample(items, min(len(items), rnd.randint(lo, hi))) if items else []


SEVERITIES = ["low", "medium", "high", "critical"]
QUERY_FIELDS = ["process.name", "event.code", "user.name", "destination.port", "file.path"]
CONFIG_CHANGES = [
    ("threshold", "Lower threshold after purple team test"),
    ("severity", "Raise severity"),
    ("window", "Widen correlation window"),
    ("exclusions", "Exclude known admin hosts"),
    ("owner", "Hand over to detection engineering"),
]


def _config_json(rule, cfg: dict) -> str:
    doc = {
        "rule": rule.code,
        "title": rule.name,
        "owner": cfg["owner"],
        "severity": cfg["severity"],
        "schedule": {"interval": cfg["interval"], "window": cfg["window"]},
        "detection": {
            "query": f'{cfg["field"]} == "{cfg["value"]}"',
            "threshold": cfg["threshold"],
        },
    }
    if rule.attack_techniques:
        doc["attack"] = list(rule.attack_techniques)
    if cfg["exclusions"]:
        doc["exclusions"] = [{"host": h} for h in cfg["exclusions"]]
    doc["response"] = {"playbook": f"PB-{cfg['playbook']:03d}", "notify": "soc-l1"}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _demo_configs(db: Session, rnd: random.Random, rules, users, today: date) -> int:
    """A JSON config with 1-4 commits for about 40 % of the operational rules."""
    n = 0
    for rule in rules:
        if rule.lifecycle_status not in (Lifecycle.operational, Lifecycle.maintenance):
            continue
        if rnd.random() > 0.4:
            continue
        cfg = {
            "owner": rnd.choice(["soc-l2", "detection-engineering", "threat-hunting"]),
            "severity": rnd.choice(SEVERITIES[:3]),
            "interval": rnd.choice(["5m", "15m", "1h"]),
            "window": rnd.choice(["10m", "30m", "1h"]),
            "field": rnd.choice(QUERY_FIELDS),
            "value": rnd.choice(["lsass.exe", "4625", "svc_backup", "445", "/tmp/*"]),
            "threshold": rnd.randint(3, 20),
            "exclusions": [],
            "playbook": rnd.randint(1, 40),
        }
        start = rule.onboarded_at or today - timedelta(days=300)
        span = max(1, (today - start).days)
        days = sorted(rnd.sample(range(span), min(span, rnd.randint(1, 4))))
        made = []
        for i, d in enumerate(days):
            if i == 0:
                msg = "Initial configuration"
            else:
                key, msg = rnd.choice(CONFIG_CHANGES)
                if key == "threshold":
                    cfg["threshold"] = max(1, cfg["threshold"] - rnd.randint(1, 3))
                elif key == "severity":
                    idx = SEVERITIES.index(cfg["severity"])
                    cfg["severity"] = SEVERITIES[min(3, idx + 1)]
                elif key == "window":
                    cfg["window"] = "2h"
                elif key == "exclusions":
                    cfg["exclusions"] = cfg["exclusions"] + [f"adm-{rnd.randint(1, 99):02d}"]
                else:
                    cfg["owner"] = "detection-engineering"
            at = datetime.combine(
                start + timedelta(days=d), time(rnd.randint(8, 17), rnd.randint(0, 59)), UTC
            )
            made.append(
                configs.make_commit(
                    db, rule, _config_json(rule, cfg), msg, rnd.choice(users), at=at
                )
            )
            n += 1
        # tag the version that was live when the rule was last verified
        if rule.last_verified_at:
            live = [c for c in made if c.created_at.date() <= rule.last_verified_at]
            if live:
                name = f"verified-{rule.last_verified_at.isoformat()}"
                configs.add_tag(db, rule, live[-1], name, rule.last_verified_by or "demo")
    return n


def _at(d: date, rnd: random.Random) -> datetime:
    return datetime.combine(d, time(rnd.randint(8, 17), rnd.randint(0, 59)), UTC)


def _driver(rnd: random.Random, kinds: list[str]) -> tuple[str, str]:
    t = rnd.choice(kinds)
    return t, rnd.choice(lifecycle.DRIVERS[t])[0]


def _demo_lifecycle(db: Session, rnd: random.Random, l2s, rules, users, today: date) -> int:
    """Change log that fits the current state: created -> onboarding -> operational -> ..."""
    n = 0
    done_all = {k: None for k in lifecycle.DOD_KEYS}

    def add(obj, old, new, when: date, kinds=("environmental", "operational"), note=""):
        nonlocal n
        t, d = _driver(rnd, list(kinds))
        lifecycle.record_change(
            db, obj, old, new, rnd.choice(users), t, d, note, at=_at(min(when, today), rnd)
        )
        n += 1

    for obj in [*l2s, *rules]:
        start = obj.onboarded_at or today - timedelta(days=rnd.randint(10, 300))
        created = start - timedelta(days=rnd.randint(14, 90))
        add(obj, None, Lifecycle.onboarding, created, note="New use case")
        status = obj.lifecycle_status
        if status == Lifecycle.onboarding:
            obj.dod = {
                k: {"by": rnd.choice(users), "at": created.isoformat()}
                for k in lifecycle.DOD_KEYS
                if rnd.random() < 0.5
            }
            continue
        obj.dod = {
            k: {
                "by": rnd.choice(users),
                "at": (start - timedelta(days=rnd.randint(0, 10))).isoformat(),
            }
            for k in done_all
        }
        add(obj, Lifecycle.onboarding, Lifecycle.operational, start, note="Definition of done met")
        if status in (Lifecycle.maintenance, Lifecycle.offloading):
            when = start + timedelta(days=rnd.randint(30, max(31, (today - start).days)))
            note = "Tuning after false positives" if status == Lifecycle.maintenance else ""
            add(obj, Lifecycle.operational, status, when, ("operational", "environmental"), note)
    return n


def _demo_output(db: Session, rnd: random.Random, rules, today: date) -> int:
    """Monthly alert counts for live rules. Less effective rules raise more false positives;
    a few noisy rules stand out so the summary has something to show."""
    from app.scoring import SCORED_STATES

    n = 0
    for rule in rules:
        if rule.lifecycle_status not in SCORED_STATES:
            continue
        noisy = rnd.random() < 0.12
        base = rnd.uniform(20, 160) if noisy else rnd.uniform(0.5, 25)
        fp_share = min(0.95, (1.05 - (rule.effectiveness or 0.5)) * rnd.uniform(0.4, 0.9))
        if noisy:
            fp_share = max(fp_share, rnd.uniform(0.7, 0.92))
        start = rule.onboarded_at.replace(day=1) if rule.onboarded_at else None
        trend = rnd.uniform(-0.04, 0.03)  # tuning tends to reduce noise over time
        for i, period in enumerate(months_back(12, today)):
            if start and period < start:
                continue
            alerts = max(0, round(rnd.gauss(base * (1 + trend * i), base * 0.3)))
            fp = min(alerts, round(alerts * fp_share * rnd.uniform(0.8, 1.2)))
            incidents = sum(1 for _ in range(alerts - fp) if rnd.random() < 0.18)
            db.add(
                OutputMetric(
                    l3_id=rule.id,
                    period=period,
                    alerts=alerts,
                    incidents=incidents,
                    false_positives=fp,
                    false_negatives=1
                    if rnd.random() < 0.04
                    else (0 if rnd.random() < 0.5 else None),
                    note="",
                    source="demo",
                    updated_by=rnd.choice(["jana", "tom"]),
                )
            )
            n += 1
    return n


def _status_at(db: Session, rule: L3UseCase, when: datetime) -> Lifecycle | None:
    ev = db.scalar(
        select(LifecycleEvent)
        .where(LifecycleEvent.l3_id == rule.id, LifecycleEvent.at <= when)
        .order_by(LifecycleEvent.at.desc())
        .limit(1)
    )
    return ev.to_status if ev else None


def _demo_snapshots(db: Session, rules, today: date, default_interval: int) -> int:
    """Twelve monthly snapshots that replay the history: rules appear and go live on their
    dates, verifications count from their date, and implementation and coverage grow."""
    n = 0
    first = today.replace(day=1)
    months = []
    for k in range(12, 0, -1):
        y, m = divmod(first.year * 12 + first.month - 1 - k, 12)
        months.append(date(y, m + 1, 1))
    for i, d in enumerate(months):
        when = datetime.combine(d, time(2, 0), UTC)
        ramp = 0.72 + 0.28 * (i + 1) / (len(months) + 1)
        sp = db.begin_nested()
        for rule in rules:
            status = _status_at(db, rule, when)
            if status is None:
                db.delete(rule)
                continue
            rule.lifecycle_status = status
            for f in ("implementation", "coverage"):
                v = getattr(rule, f)
                if v is not None:
                    setattr(rule, f, round(v * ramp, 2))
            past = db.scalar(
                select(Verification.verified_at)
                .where(Verification.l3_id == rule.id, Verification.verified_at <= d)
                .order_by(Verification.verified_at.desc())
                .limit(1)
            )
            rule.last_verified_at = past
        db.flush()
        data = snapshots.capture(db, default_interval, today=d)
        sp.rollback()
        db.add(Snapshot(label=f"Monthly {d:%Y-%m}", kind="demo", taken_at=when, data=data))
        n += 1
    db.expire_all()
    return n


def apply_demo_data(
    db: Session, seed: int = 42, today: date | None = None, default_interval: int = 180
) -> dict[str, int]:
    rnd = random.Random(seed)
    today = today or date.today()

    refs = {
        k: list(db.scalars(select(ReferenceItem).where(ReferenceItem.kind == k))) for k in RefKind
    }
    drivers = list(db.scalars(select(BusinessDriver)))

    compliance: list[ComplianceDriver] = []
    sources = list(db.scalars(select(ComplianceSource).order_by(ComplianceSource.id)))
    for src in sources:
        existing = {d.ref for d in src.drivers}
        for code, name in COMPLIANCE_REFS.get(src.name, []):
            if code not in existing:
                src.drivers.append(ComplianceDriver(ref=code, name=name))
        compliance.extend(src.drivers)
    db.flush()

    db.execute(delete(Verification))
    db.execute(delete(ConfigCommit))
    db.execute(delete(LifecycleEvent))
    db.execute(delete(OutputMetric).where(OutputMetric.source == "demo"))
    db.execute(delete(Snapshot).where(Snapshot.kind == "demo"))

    # Earlier demo rules are replaced, so re-running with the same seed gives the same result.
    db.execute(delete(L3UseCase).where(L3UseCase.description == DEMO_MARK))
    db.flush()
    db.expire_all()

    # Most catalogue L3 rules sit under CC, AO, EX and PV. Give about three quarters of the
    # empty L2 use cases 1-3 generated rules so the dashboard shows every L1; the rest stay
    # empty and show up as detection gaps.
    added = 0
    for l2 in db.scalars(select(L2UseCase).order_by(L2UseCase.code)):
        if l2.children or rnd.random() > 0.75:
            continue
        for n in range(1, rnd.randint(1, 3) + 1):
            db.add(
                L3UseCase(
                    parent=l2,
                    code=f"{l2.code}-{n:02d}",
                    name=f"{l2.name}: {rnd.choice(DEMO_RULE_KINDS)}",
                    description=DEMO_MARK,
                )
            )
            added += 1
    db.flush()

    # Leave the last business driver and the last requirement of each compliance source unlinked,
    # so the driver pages and the Priorities page show what a coverage gap looks like.
    linkable_bd = sorted(drivers, key=lambda d: d.code)[:-1] or drivers
    spare = {max(src.drivers, key=lambda d: d.ref).id for src in sources if len(src.drivers) > 1}
    linkable_cd = [c for c in compliance if c.id not in spare] or compliance

    l2s = list(db.scalars(select(L2UseCase).order_by(L2UseCase.code)))
    for l2 in l2s:
        has_rules = bool(l2.children)
        l2.lifecycle_status = Lifecycle.operational if has_rules else Lifecycle.onboarding
        l2.actors = _pick(rnd, refs[RefKind.threat_actor], 1, 2)
        l2.business_drivers = _pick(rnd, linkable_bd, 1, 3)
        l2.compliance_drivers = _pick(rnd, linkable_cd, 1, 2)
        l2.risk_level = rnd.randint(1, 5)
        l2.target_implementation = rnd.choice([0.5, 0.6, 0.7, 0.8])
        l2.onboarded_at = today - timedelta(days=rnd.randint(200, 1100)) if has_rules else None
        l2.last_verified_at = None
        l2.last_verified_by = None

    users = ["jana", "tom", "admin"]
    rules = list(db.scalars(select(L3UseCase).order_by(L3UseCase.code)))
    counts = {"rules": len(rules), "demo_rules_added": added, "l2": len(l2s), "verifications": 0}
    for rule in rules:
        status = rnd.choices(
            [
                Lifecycle.operational,
                Lifecycle.maintenance,
                Lifecycle.onboarding,
                Lifecycle.offloading,
            ],
            weights=[70, 10, 15, 5],
        )[0]
        rule.lifecycle_status = status

        techs = _pick(rnd, refs[RefKind.detection_technology], 1, 2)
        rule.references = (
            techs
            + _pick(rnd, refs[RefKind.log_source], 1, 3)
            + _pick(rnd, refs[RefKind.scope], 1, 2)
        )

        if rnd.random() < 0.10:
            rule.effectiveness = rule.implementation = rule.coverage = None
        else:
            prof = TECH_PROFILE.get(techs[0].name, DEFAULT_PROFILE) if techs else DEFAULT_PROFILE
            impl_mean = prof[1] * (0.5 if status == Lifecycle.onboarding else 1.0)
            rule.effectiveness = _metric(rnd, prof[0])
            rule.implementation = _metric(rnd, impl_mean)
            rule.coverage = _metric(rnd, prof[2])

        rule.onboarded_at = today - timedelta(days=rnd.randint(30, 1095))
        rule.verification_interval_days = rnd.choice([None] * 8 + [30, 90])
        rule.comments = ""
        # most rules follow their L2; some have their own risk or target
        rule.risk_level = rnd.randint(1, 5) if rnd.random() < 0.15 else None
        rule.target_implementation = rnd.choice([0.5, 0.7, 0.9]) if rnd.random() < 0.1 else None
        rule.last_verified_at = None
        rule.last_verified_by = None

        if status in (Lifecycle.operational, Lifecycle.maintenance) and rnd.random() > 0.12:
            # 1-4 verifications, the latest between 0 and 230 days ago (some become overdue)
            when = today - timedelta(days=rnd.randint(0, 230))
            history = []
            for _ in range(rnd.randint(1, 4)):
                if when < rule.onboarded_at:
                    break
                history.append(when)
                when -= timedelta(days=rnd.randint(60, 120))
            for i, d in enumerate(history):
                issues = rnd.random() < 0.15
                who = rnd.choice(users)
                db.add(
                    Verification(
                        l3_id=rule.id,
                        verified_at=d,
                        username=who,
                        result=VerificationResult.issues if issues else VerificationResult.ok,
                        note=rnd.choice(NOTES_ISSUES if issues else NOTES_OK),
                    )
                )
                counts["verifications"] += 1
                if i == 0:
                    rule.last_verified_at = d
                    rule.last_verified_by = who

    # L2 verification date = the oldest verification among its scored rules
    for l2 in l2s:
        dates = [r.last_verified_at for r in l2.children if r.last_verified_at]
        if dates:
            l2.last_verified_at = min(dates)
            l2.last_verified_by = "demo"

    counts["config_commits"] = _demo_configs(db, rnd, rules, users, today)
    counts["lifecycle_events"] = _demo_lifecycle(db, rnd, l2s, rules, users, today)
    counts["output_metrics"] = _demo_output(db, rnd, rules, today)
    db.flush()
    counts["snapshots"] = _demo_snapshots(db, rules, today, default_interval)

    db.commit()
    log.info("Applied demo data (seed %d): %s", seed, counts)
    return counts


def main() -> None:
    from app.config import get_settings
    from app.db import make_engine
    from app.startup import initialize

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    settings = get_settings()
    engine = make_engine(settings.database_url)
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    initialize(engine, factory, settings)
    with factory() as db:
        print(apply_demo_data(db, args.seed))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
