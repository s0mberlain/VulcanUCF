"""Tests against detection rules (PROJ-3): scope coverage, verification and gaps.

A test links to L3 rules, per rule with the scopes it covered. A successful result (Blocked or
Alerted) covers those scopes of the rule for the rule's verification interval; a rule counts as
verified when every scope is covered. Logged and Not detected are problems and gaps.
"""

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, selectinload

from app.models import (
    Campaign,
    CampaignStatus,
    GapAcceptance,
    L3UseCase,
    RefKind,
    Role,
    TestCase,
    TestEvent,
    TestOutcome,
    TestRound,
    TestRule,
    TestStatus,
    User,
    Verification,
    VerificationResult,
    utcnow,
)
from app.security import as_utc

# A field named `date` hides the type inside its own class body, so annotations use this alias.
Day = date

SUCCESS = (TestOutcome.blocked, TestOutcome.alerted)
FAILURE = (TestOutcome.logged, TestOutcome.not_detected)


def day(dt: datetime) -> date:
    return as_utc(dt).date()


def rule_scopes(rule: L3UseCase) -> list[str]:
    return sorted(r.name for r in rule.references if r.kind == RefKind.scope)


def interval_days(rule: L3UseCase, default_days: int) -> int:
    return rule.verification_interval_days or default_days


@dataclass
class ScopeState:
    scope: str  # "" = the rule has no scopes (the whole rule)
    status: str  # covered | expired | problem | open
    test_id: int | None = None
    test_title: str | None = None
    outcome: str | None = None
    date: Day | None = None
    until: Day | None = None


@dataclass
class RuleState:
    state: str  # verified | partial | issues | due | none
    scopes: list[ScopeState] = field(default_factory=list)
    verified_date: date | None = None
    verified_test_id: int | None = None
    covered: int = 0
    total: int = 0


def _result_links(db: Session, rule_ids: list[int]) -> dict[int, list[tuple[TestRule, TestCase]]]:
    """Rule id -> its links to tests that have a result."""
    out: dict[int, list[tuple[TestRule, TestCase]]] = {i: [] for i in rule_ids}
    if not rule_ids:
        return out
    q = (
        select(TestRule, TestCase)
        .join(TestCase, TestCase.id == TestRule.test_id)
        .where(
            TestRule.l3_id.in_(rule_ids),
            TestCase.exec_status == TestStatus.executed,
            TestCase.outcome.is_not(None),
            TestCase.executed_at.is_not(None),
        )
    )
    for link, test in db.execute(q):
        out[link.l3_id].append((link, test))
    return out


def rule_state(
    db: Session, rule: L3UseCase, default_days: int, today: date | None = None
) -> RuleState:
    """How far the tests of this rule cover its scopes right now."""
    return _state(rule, _result_links(db, [rule.id])[rule.id], default_days, today)


def rule_states(
    db: Session, rules: list[L3UseCase], default_days: int, today: date | None = None
) -> dict[int, RuleState]:
    """rule_state for many rules with one query (load the rules with their references)."""
    links = _result_links(db, [r.id for r in rules])
    return {r.id: _state(r, links[r.id], default_days, today) for r in rules}


def _state(
    rule: L3UseCase,
    links: list[tuple[TestRule, TestCase]],
    default_days: int,
    today: date | None = None,
) -> RuleState:
    today = today or date.today()
    scopes = rule_scopes(rule) or [""]
    days = interval_days(rule, default_days)
    out: list[ScopeState] = []
    for sc in scopes:
        best: tuple[TestRule, TestCase] | None = None
        for link, test in links:
            if sc and sc not in (link.scopes or []):
                continue
            if sc == "" and (link.scopes or []):
                # a rule without scopes today: older links may still carry scope names; they
                # count as the whole rule
                pass
            if best is None or (as_utc(test.executed_at), test.id) > (
                as_utc(best[1].executed_at),
                best[1].id,
            ):
                best = (link, test)
        if best is None:
            out.append(ScopeState(sc, "open"))
            continue
        test = best[1]
        d = day(test.executed_at)
        until = d + timedelta(days=days)
        if test.outcome in FAILURE:
            st = "problem"
        elif until < today:
            st = "expired"
        else:
            st = "covered"
        out.append(ScopeState(sc, st, test.id, test.title, test.outcome.value, d, until))
    covered = sum(1 for s in out if s.status == "covered")
    if any(s.status == "problem" for s in out):
        state = "issues"
    elif covered == len(out):
        state = "verified"
    elif covered:
        state = "partial"
    elif any(s.status == "expired" for s in out):
        state = "due"
    else:
        state = "none"
    res = RuleState(state, out, covered=covered, total=len(out))
    if state == "verified":
        oldest = min(out, key=lambda s: (s.date, s.test_id or 0))
        res.verified_date = oldest.date
        res.verified_test_id = oldest.test_id
    return res


def recompute_rule(db: Session, rule: L3UseCase, default_days: int) -> RuleState:
    """Rewrite the verification entries that come from tests and the rule's verified date."""
    st = rule_state(db, rule, default_days)
    old = list(
        db.scalars(
            select(Verification).where(
                Verification.l3_id == rule.id, Verification.test_id.is_not(None)
            )
        )
    )
    old_ok = max((v.verified_at for v in old if v.result == VerificationResult.ok), default=None)
    db.execute(
        delete(Verification).where(Verification.l3_id == rule.id, Verification.test_id.is_not(None))
    )
    db.flush()
    tests = {
        t.id: t
        for t in db.scalars(
            select(TestCase).where(TestCase.id.in_({s.test_id for s in st.scopes if s.test_id}))
        )
    }
    if st.state == "verified" and st.verified_date:
        t = tests[st.verified_test_id]
        names = ", ".join(s.scope or "–" for s in st.scopes)
        db.add(
            Verification(
                l3_id=rule.id,
                verified_at=st.verified_date,
                username=t.blue_by or t.created_by,
                result=VerificationResult.ok,
                note=f"Test: {t.title}" + (f" (scopes: {names})" if st.scopes[0].scope else ""),
                test_id=t.id,
            )
        )
        if rule.last_verified_at is None or st.verified_date >= rule.last_verified_at:
            rule.last_verified_at = st.verified_date
            rule.last_verified_by = t.blue_by or t.created_by
    else:
        if old_ok and rule.last_verified_at == old_ok:
            manual = db.scalar(
                select(Verification.verified_at)
                .where(
                    Verification.l3_id == rule.id,
                    Verification.test_id.is_(None),
                    Verification.result == VerificationResult.ok,
                )
                .order_by(Verification.verified_at.desc())
            )
            rule.last_verified_at = manual
            if manual is None:
                rule.last_verified_by = None
    seen: set[int] = set()
    for s in st.scopes:
        if s.status == "problem" and s.test_id and s.test_id not in seen:
            seen.add(s.test_id)
            t = tests[s.test_id]
            where = ", ".join(x.scope for x in st.scopes if x.test_id == s.test_id and x.scope)
            db.add(
                Verification(
                    l3_id=rule.id,
                    verified_at=day(t.executed_at),
                    username=t.blue_by or t.created_by,
                    result=VerificationResult.issues,
                    note=f"Test: {t.title} ({t.outcome.value})"
                    + (f" (scopes: {where})" if where else ""),
                    test_id=t.id,
                )
            )
    return st


def recompute_rules(db: Session, rule_ids: set[int], default_days: int) -> None:
    for rid in rule_ids:
        rule = db.get(L3UseCase, rid)
        if rule is not None:
            recompute_rule(db, rule, default_days)


# ---------------------------------------------------------------- gaps


@dataclass
class Gap:
    l3_id: int | None
    rule_code: str | None
    rule_name: str | None
    technique: str
    scope: str
    outcome: str
    test_id: int
    test_title: str
    executed_at: datetime
    campaign_id: int | None
    campaign_name: str | None
    accepted: bool = False
    accepted_reason: str | None = None
    accepted_by: str | None = None
    accepted_at: datetime | None = None


def gaps(db: Session, technique: str | None = None) -> list[Gap]:
    """Gaps from tests: per rule, scope and technique, the latest executed test decides.

    With `technique` only the gaps of that technique are worked out. A gap is keyed by its
    technique, so that is exact for every test of the technique (used for one test's badge).
    """
    q = (
        select(TestCase)
        .where(
            TestCase.exec_status == TestStatus.executed,
            TestCase.outcome.is_not(None),
            TestCase.executed_at.is_not(None),
        )
        .options(selectinload(TestCase.rules))
    )
    if technique is not None:
        q = q.where(TestCase.technique == technique)
    tests = list(db.scalars(q))
    camp = {i: n for i, n in db.execute(select(Campaign.id, Campaign.name))}
    rules = {r.id: r for r in db.execute(select(L3UseCase.id, L3UseCase.code, L3UseCase.name))}
    latest: dict[tuple[int | None, str, str], TestCase] = {}

    def offer(key: tuple[int | None, str, str], t: TestCase) -> None:
        cur = latest.get(key)
        if cur is None or (as_utc(t.executed_at), t.id) > (as_utc(cur.executed_at), cur.id):
            latest[key] = t

    for t in tests:
        linked = [r for r in t.rules if r.l3_id in rules]
        if not linked:
            if not t.rules:  # a test without any rule: a gap of the technique itself
                offer((None, t.technique, ""), t)
            continue
        for link in linked:
            scopes = [s for s in (link.scopes or []) if s] or [""]
            for sc in scopes:
                offer((link.l3_id, t.technique, sc), t)
    acc = {}
    aq = select(GapAcceptance).order_by(GapAcceptance.id)
    if technique is not None:
        aq = aq.where(GapAcceptance.technique == technique)
    for a in db.scalars(aq):
        acc[(a.l3_id, a.technique, a.scope, a.test_id)] = a
    # an acceptance covers one result: a later result of the same test starts the question again
    last_result = {}
    eq = (
        select(TestEvent.test_id, TestEvent.at)
        .where(TestEvent.kind.in_(("result", "result_changed")))
        .order_by(TestEvent.id)
    )
    if technique is not None:
        eq = eq.where(TestEvent.test_id.in_([t.id for t in tests]))
    for e in db.execute(eq):
        last_result[e[0]] = e[1]
    out = []
    for (rid, tech, sc), t in latest.items():
        if t.outcome not in FAILURE:
            continue
        rule = rules.get(rid) if rid else None
        g = Gap(
            rid,
            rule.code if rule else None,
            rule.name if rule else None,
            tech,
            sc,
            t.outcome.value,
            t.id,
            t.title,
            t.executed_at,
            t.campaign_id,
            camp.get(t.campaign_id) if t.campaign_id else None,
        )
        a = acc.get((rid, tech, sc, t.id))
        if a and (t.id not in last_result or as_utc(a.accepted_at) >= as_utc(last_result[t.id])):
            g.accepted = True
            g.accepted_reason, g.accepted_by, g.accepted_at = a.reason, a.accepted_by, a.accepted_at
        out.append(g)
    out.sort(key=lambda g: (g.accepted, as_utc(g.executed_at)), reverse=False)
    return out


# ---------------------------------------------------------------- accounts


def account_expiry(user: User, db: Session) -> datetime | None:
    """When a red team account ends: the end of its latest campaign, or the date set by hand."""
    if user.role != Role.red_team:
        return None
    if user.expiry_follows_campaign:
        ends = [c.planned_end for c in user_campaigns(db, user)]
        if ends:
            return datetime.combine(max(ends), time(23, 59, 59), tzinfo=UTC)
        return as_utc(user.expires_at) if user.expires_at else None
    return as_utc(user.expires_at) if user.expires_at else None


def user_campaigns(db: Session, user: User) -> list[Campaign]:
    return list(db.scalars(select(Campaign).where(Campaign.accounts.any(User.id == user.id))))


def account_expired(user: User, db: Session) -> bool:
    exp = account_expiry(user, db)
    return exp is not None and exp < datetime.now(UTC)


def new_round(number: int, opened_by: str, what: str = "") -> TestRound:
    """A round with every value set, so it can be read before it is saved."""
    return TestRound(
        number=number,
        opened_by=opened_by,
        opened_at=utcnow(),
        exec_status=TestStatus.not_run,
        executed_what=what,
        red_notes="",
        blue_notes="",
        red_version=1,
        blue_version=1,
    )


def latest_round(t: TestCase) -> TestRound | None:
    return max(t.rounds, key=lambda r: r.number, default=None)


def round_done(r: TestRound) -> bool:
    """A round is finished once it has a result, or its execution is not possible."""
    return r.outcome is not None or r.exec_status == TestStatus.not_executable


def test_status(t: TestCase) -> str:
    """open: not executed yet; waiting: executed, the blue team has no result; done."""
    r = latest_round(t)
    if r is None:
        return "open"
    if round_done(r):
        return "done"
    return "waiting" if r.exec_status == TestStatus.executed else "open"


def sync_test(t: TestCase) -> None:
    """Copy the current state of the rounds into the test's own columns.

    The current result is the one of the latest round that has a result. Verification, scope
    coverage and gaps read these columns, so they follow the rounds without further changes.
    """
    latest = latest_round(t)
    if latest is None:
        return
    with_result = [r for r in t.rounds if r.outcome is not None]
    cur = max(with_result, key=lambda r: r.number, default=None)
    src = cur or latest
    t.exec_status = src.exec_status
    t.executed_at = src.started_at if src.exec_status == TestStatus.executed else None
    t.red_notes, t.red_by, t.red_at = src.red_notes, src.red_by, src.red_at
    t.outcome = cur.outcome if cur else None
    t.detected_at = cur.detected_at if cur else None
    t.blue_notes = cur.blue_notes if cur else ""
    t.blue_by = cur.blue_by if cur else None
    t.blue_at = cur.blue_at if cur else None
    t.red_version = latest.red_version
    t.blue_version = latest.blue_version


def add_event(
    db: Session,
    t: TestCase,
    kind: str,
    side: str,
    author: str,
    round_number: int | None,
    text: str = "",
    data: dict | None = None,
) -> TestEvent:
    e = TestEvent(
        test_id=t.id,
        round_number=round_number,
        kind=kind,
        side=side,
        author=author,
        text=text,
        data=data or {},
        at=utcnow(),
    )
    t.events.append(e)
    db.flush()
    return e


def can_close(campaign: Campaign) -> list[str]:
    """The tests that stop a campaign from being closed: their latest round is not finished."""
    bad = []
    for t in campaign.tests:
        r = latest_round(t)
        if r is None:
            if t.exec_status == TestStatus.not_run or (
                t.exec_status == TestStatus.executed and t.outcome is None
            ):
                bad.append(t.title)
        elif not round_done(r):
            bad.append(f"{t.title} (round {r.number})")
    return bad


__all__ = ["CampaignStatus"]
