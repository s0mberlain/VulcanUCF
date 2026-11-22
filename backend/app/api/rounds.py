"""Rounds, comments and the history of a test (PROJ-4).

A test is a series of rounds. Each round holds the red team's execution and the blue team's
result. The test's own execution and result columns follow the latest round with a result (see
purple.sync_test), so verification and gaps keep using them.

The campaign setting "collaboration" decides what a red team account sees of the blue team: with
"hidden" (the default) the result, notes, files and comments of the blue side appear after the
campaign is closed, with "open" at once.
"""

from datetime import date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, StringConstraints
from sqlalchemy import select

from app import attack, audit, purple
from app.api.deps import DB, SettingsDep
from app.api.purple import (
    AttachmentOut,
    QuickIn,
    TestOut,
    _att,
    _blue_visible,
    _campaign,
    _conflict,
    _defaults,
    _editor,
    _links,
    _new_test,
    _open_gap_tests,
    _red,
    _refresh,
    _resolve_links,
    _rule_ids,
    _test,
    out_test,
)
from app.models import (
    Campaign,
    CampaignStatus,
    ReferenceItem,
    RefKind,
    Role,
    RoundDetection,
    TestCase,
    TestEvent,
    TestOutcome,
    TestRound,
    TestStatus,
    User,
)
from app.security import Editor, Reader, as_utc

router = APIRouter(tags=["tests"])

MAX_ROUNDS = 20
EVENT_PAGE = 200
Comment = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=10000)]
Notes = Annotated[str, StringConstraints(max_length=10000)]

# ------------------------------------------------------------------ schemas


class DetectionOut(BaseModel):
    name: str
    item_id: int | None


class RoundOut(BaseModel):
    number: int
    state: Literal["open", "waiting", "done"]
    opened_by: str
    opened_at: datetime
    exec_status: TestStatus
    started_at: datetime | None
    ended_at: datetime | None
    executed_what: str
    red_notes: str
    red_by: str | None
    red_at: datetime | None
    blue_hidden: bool
    outcome: TestOutcome | None
    detected_at: datetime | None
    detected_by: list[DetectionOut]
    blue_notes: str | None
    blue_by: str | None
    blue_at: datetime | None
    time_to_detect_seconds: int | None
    attachments: list[AttachmentOut]
    red_version: int
    blue_version: int
    can_record_red: bool
    can_record_blue: bool
    can_delete: bool


class EventOut(BaseModel):
    id: int
    round_number: int | None
    kind: str
    side: str
    author: str
    at: datetime
    text: str
    data: dict
    removed: bool
    removed_by: str | None
    removed_at: datetime | None
    can_remove: bool = False


class TestDetail(TestOut):
    rounds: list[RoundOut]
    events: list[EventOut]
    events_more: bool
    collaboration: Literal["hidden", "open"] | None
    can_comment: bool
    can_open_round: bool
    max_rounds: int = MAX_ROUNDS


class RoundRedIn(BaseModel):
    exec_status: TestStatus
    started_at: datetime | None = None
    ended_at: datetime | None = None
    executed_what: Notes = ""
    red_notes: Notes = ""
    expected_version: int | None = None


class RoundBlueIn(BaseModel):
    outcome: TestOutcome | None = None
    detected_at: datetime | None = None
    detected_by: list[
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
    ] = []
    blue_notes: Notes = ""
    expected_version: int | None = None


class CommentIn(BaseModel):
    text: Comment
    round_number: int | None = None


class CollabIn(BaseModel):
    collaboration: Literal["hidden", "open"]


# ------------------------------------------------------------------ helpers


def _side(user: User) -> str:
    return "red" if _red(user) else "blue"


def _round(t: TestCase, number: int) -> TestRound:
    for r in t.rounds:
        if r.number == number:
            return r
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Round not found")


def _running(t: TestCase) -> bool:
    return t.campaign is None or t.campaign.status == CampaignStatus.running


def _may_write(user: User, t: TestCase, *, blue_only: bool = False) -> None:
    """Who may change rounds: the blue team and the assigned red team while the campaign runs."""
    if user.role == Role.auditor or (blue_only and not _editor(user)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this action")
    if t.campaign is not None and t.campaign.status != CampaignStatus.running:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This can only be changed while the campaign is running"
        )


def _event_visible(user: User, t: TestCase, e: TestEvent) -> bool:
    if not _red(user) or _blue_visible(user, t):
        return True
    return e.side != "blue" and e.kind not in ("result", "result_changed")


def _round_state(r: TestRound) -> str:
    if purple.round_done(r):
        return "done"
    return "waiting" if r.exec_status == TestStatus.executed else "open"


def _ttd(r: TestRound) -> int | None:
    if r.outcome in purple.SUCCESS and r.started_at and r.detected_at:
        return int((as_utc(r.detected_at) - as_utc(r.started_at)).total_seconds())
    return None


def _detections(r: TestRound) -> list[DetectionOut]:
    return [
        DetectionOut(name=d.item.name if d.item else d.name, item_id=d.item.id if d.item else None)
        for d in r.detections
    ]


def out_round(user: User, t: TestCase, r: TestRound) -> RoundOut:
    blue_ok = _blue_visible(user, t)
    running = _running(t)
    latest = purple.latest_round(t)
    empty = (
        r.exec_status == TestStatus.not_run
        and r.outcome is None
        and not r.red_notes
        and not r.blue_notes
        and not any(a.round_id == r.id for a in t.attachments)
        and not any(e.round_number == r.number and e.kind == "comment" for e in t.events)
    )
    return RoundOut(
        number=r.number,
        state=_round_state(r),  # type: ignore[arg-type]
        opened_by=r.opened_by,
        opened_at=r.opened_at,
        exec_status=r.exec_status,
        started_at=r.started_at,
        ended_at=r.ended_at,
        executed_what=r.executed_what,
        red_notes=r.red_notes,
        red_by=r.red_by,
        red_at=r.red_at,
        blue_hidden=not blue_ok,
        outcome=r.outcome if blue_ok else None,
        detected_at=r.detected_at if blue_ok else None,
        detected_by=_detections(r) if blue_ok else [],
        blue_notes=r.blue_notes if blue_ok else None,
        blue_by=r.blue_by if blue_ok else None,
        blue_at=r.blue_at if blue_ok else None,
        time_to_detect_seconds=_ttd(r) if blue_ok else None,
        attachments=[
            _att(a, t) for a in t.attachments if a.round_id == r.id and (a.side == "red" or blue_ok)
        ],
        red_version=r.red_version,
        blue_version=r.blue_version,
        can_record_red=running and user.role != Role.auditor,
        can_record_blue=running and _editor(user),
        can_delete=running
        and empty
        and r.number > 1
        and r is latest
        and r.opened_by == user.username
        and user.role != Role.auditor,
    )


def _events(db, user: User, t: TestCase, before: int | None = None) -> tuple[list[TestEvent], bool]:
    rows = [e for e in t.events if _event_visible(user, t, e) and (before is None or e.id < before)]
    more = len(rows) > EVENT_PAGE
    return rows[-EVENT_PAGE:], more


def out_event(user: User, e: TestEvent) -> EventOut:
    removed = e.removed_by is not None
    return EventOut(
        id=e.id,
        round_number=e.round_number,
        kind=e.kind,
        side=e.side,
        author=e.author,
        at=e.at,
        text="" if removed else e.text,
        data=e.data or {},
        removed=removed,
        removed_by=e.removed_by,
        removed_at=e.removed_at,
        can_remove=user.role == Role.admin and e.kind == "comment" and not removed,
    )


def out_detail(db, user: User, t: TestCase, gap_tests: set[int] | None = None) -> TestDetail:
    base = out_test(db, user, t, gap_tests)
    events, more = _events(db, user, t)
    latest = purple.latest_round(t)
    commenting = user.role != Role.auditor and (_editor(user) or _red(user)) and _running(t)
    return TestDetail(
        **base.model_dump(),
        rounds=[out_round(user, t, r) for r in t.rounds],
        events=[out_event(user, e) for e in events],
        events_more=more,
        collaboration=(t.campaign.collaboration if t.campaign else None),  # type: ignore[arg-type]
        can_comment=commenting,
        can_open_round=commenting
        and latest is not None
        and purple.round_done(latest)
        and len(t.rounds) < MAX_ROUNDS,
    )


# ------------------------------------------------------------------ rules for a round


def apply_red(
    db,
    t: TestCase,
    r: TestRound,
    user: User,
    *,
    exec_status: TestStatus,
    started_at: datetime | None,
    ended_at: datetime | None,
    what: str,
    notes: str,
    expected_version: int | None,
) -> None:
    if expected_version is not None and expected_version != r.red_version:
        raise _conflict("execution", r.red_by)
    if exec_status == TestStatus.executed and started_at is None:
        raise HTTPException(422, "Enter when the execution started")
    if exec_status != TestStatus.executed:
        if r.outcome is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "A round with a result stays executed")
        started_at = ended_at = None
    if started_at and ended_at and as_utc(ended_at) < as_utc(started_at):
        raise HTTPException(422, "The end cannot be before the start")
    earlier = [x.started_at for x in t.rounds if x.number < r.number and x.started_at]
    if started_at and earlier and as_utc(started_at) < max(as_utc(x) for x in earlier):
        raise HTTPException(422, "The round cannot start before the previous round")
    if started_at and r.detected_at and as_utc(r.detected_at) < as_utc(started_at):
        raise HTTPException(422, "The detection time cannot be before the start")
    first = r.exec_status == TestStatus.not_run
    r.exec_status, r.started_at, r.ended_at = exec_status, started_at, ended_at
    r.executed_what, r.red_notes = what, notes
    r.red_by, r.red_at = user.username, purple.utcnow()
    r.red_version += 1
    purple.add_event(
        db,
        t,
        "execution",
        "red",
        user.username,
        r.number,
        data={"status": exec_status.value, "first": first},
    )


def apply_blue(
    db,
    t: TestCase,
    r: TestRound,
    user: User,
    *,
    outcome: TestOutcome | None,
    detected_at: datetime | None,
    detected_by: list[str],
    notes: str,
    expected_version: int | None,
) -> None:
    if expected_version is not None and expected_version != r.blue_version:
        raise _conflict("result", r.blue_by)
    if outcome is not None and r.exec_status != TestStatus.executed:
        raise HTTPException(422, "A result needs an executed round")
    if outcome is None:
        detected_at = None
    if detected_at and r.started_at and as_utc(detected_at) < as_utc(r.started_at):
        raise HTTPException(422, "The detection time cannot be before the start of the round")
    names = list(dict.fromkeys(detected_by))
    items = {
        i.name: i
        for i in db.scalars(
            select(ReferenceItem).where(
                ReferenceItem.kind == RefKind.detection_technology, ReferenceItem.name.in_(names)
            )
        )
    }
    unknown = [n for n in names if n not in items]
    if unknown:
        raise HTTPException(
            422,
            "Unknown detection technology: " + ", ".join(unknown) + ". Add it to the list first.",
        )
    old = r.outcome
    r.detections.clear()
    db.flush()
    for n in names:
        r.detections.append(RoundDetection(item_id=items[n].id, name=n))
    r.outcome, r.detected_at, r.blue_notes = outcome, detected_at, notes
    r.blue_by, r.blue_at = user.username, purple.utcnow()
    r.blue_version += 1
    if outcome != old and outcome is not None:
        purple.add_event(
            db,
            t,
            "result" if old is None else "result_changed",
            "blue",
            user.username,
            r.number,
            data={"old": old.value if old else None, "new": outcome.value},
        )


def _after(db, settings, t: TestCase, before_rules: set[int]) -> None:
    purple.sync_test(t)
    _refresh(db, settings, before_rules | _rule_ids(t))


# ------------------------------------------------------------------ detail and rounds


@router.get("/tests/{tid}", response_model=TestDetail)
def get_test(tid: int, user: Reader, db: DB) -> TestDetail:
    t = _test(db, user, tid)
    return out_detail(db, user, t, _open_gap_tests(db) if not _red(user) else None)


@router.get("/tests/{tid}/events", response_model=list[EventOut])
def older_events(tid: int, user: Reader, db: DB, before: int = Query(...)) -> list[EventOut]:
    t = _test(db, user, tid)
    rows, _ = _events(db, user, t, before)
    return [out_event(user, e) for e in rows]


@router.post("/tests/{tid}/rounds", response_model=TestDetail, status_code=201)
def open_round(tid: int, user: Reader, db: DB) -> TestDetail:
    t = _test(db, user, tid)
    _may_write(user, t)
    latest = purple.latest_round(t)
    if latest is not None and not purple.round_done(latest):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Round {latest.number} is still open")
    if len(t.rounds) >= MAX_ROUNDS:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"A test can have at most {MAX_ROUNDS} rounds"
        )
    n = (latest.number if latest else 0) + 1
    t.rounds.append(purple.new_round(n, user.username, latest.executed_what if latest else ""))
    purple.add_event(db, t, "round_opened", _side(user), user.username, n)
    audit.record(db, user, "round_open", "test", f"{t.id}: {t.title}", {"round": n})
    db.commit()
    return out_detail(db, user, t, _open_gap_tests(db) if not _red(user) else None)


@router.delete("/tests/{tid}/rounds/{number}", response_model=TestDetail)
def delete_round(tid: int, number: int, user: Reader, db: DB) -> TestDetail:
    t = _test(db, user, tid)
    _may_write(user, t)
    r = _round(t, number)
    view = out_round(user, t, r)
    if not view.can_delete:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Only the person who opened an empty latest round can delete it",
        )
    t.rounds.remove(r)
    purple.add_event(db, t, "round_deleted", _side(user), user.username, number)
    audit.record(db, user, "round_delete", "test", f"{t.id}: {t.title}", {"round": number})
    db.commit()
    return out_detail(db, user, t, _open_gap_tests(db) if not _red(user) else None)


@router.put("/tests/{tid}/rounds/{number}/red", response_model=TestDetail)
def record_round_red(
    tid: int, number: int, body: RoundRedIn, user: Reader, db: DB, settings: SettingsDep
) -> TestDetail:
    t = _test(db, user, tid)
    _may_write(user, t)
    r = _round(t, number)
    before = _rule_ids(t)
    apply_red(
        db,
        t,
        r,
        user,
        exec_status=body.exec_status,
        started_at=body.started_at,
        ended_at=body.ended_at,
        what=body.executed_what,
        notes=body.red_notes,
        expected_version=body.expected_version,
    )
    audit.record(
        db,
        user,
        "execute",
        "test",
        f"{t.id}: {t.title}",
        {"round": number, "status": body.exec_status.value, "started_at": body.started_at},
    )
    _after(db, settings, t, before)
    db.commit()
    return out_detail(db, user, t, _open_gap_tests(db) if not _red(user) else None)


@router.put("/tests/{tid}/rounds/{number}/blue", response_model=TestDetail)
def record_round_blue(
    tid: int, number: int, body: RoundBlueIn, user: Editor, db: DB, settings: SettingsDep
) -> TestDetail:
    t = _test(db, user, tid)
    _may_write(user, t, blue_only=True)
    r = _round(t, number)
    before = _rule_ids(t)
    apply_blue(
        db,
        t,
        r,
        user,
        outcome=body.outcome,
        detected_at=body.detected_at,
        detected_by=body.detected_by,
        notes=body.blue_notes,
        expected_version=body.expected_version,
    )
    audit.record(
        db,
        user,
        "result",
        "test",
        f"{t.id}: {t.title}",
        {"round": number, "outcome": body.outcome.value if body.outcome else None},
    )
    _after(db, settings, t, before)
    db.commit()
    return out_detail(db, user, t, _open_gap_tests(db))


# Earlier endpoints of PROJ-3: they act on the latest round


class LegacyRedIn(BaseModel):
    exec_status: TestStatus
    executed_at: datetime | None = None
    red_notes: Notes = ""
    expected_version: int | None = None


class LegacyBlueIn(BaseModel):
    outcome: TestOutcome | None = None
    detected_at: datetime | None = None
    blue_notes: Notes = ""
    expected_version: int | None = None


@router.put("/tests/{tid}/red", response_model=TestOut)
def record_red(tid: int, body: LegacyRedIn, user: Reader, db: DB, settings: SettingsDep) -> TestOut:
    t = _test(db, user, tid)
    r = purple.latest_round(t)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Round not found")
    record_round_red(
        tid,
        r.number,
        RoundRedIn(
            exec_status=body.exec_status,
            started_at=body.executed_at,
            red_notes=body.red_notes,
            executed_what=r.executed_what,
            ended_at=r.ended_at,
            expected_version=body.expected_version,
        ),
        user,
        db,
        settings,
    )
    return out_test(db, user, t, _open_gap_tests(db) if not _red(user) else None)


@router.put("/tests/{tid}/blue", response_model=TestOut)
def record_blue(
    tid: int, body: LegacyBlueIn, user: Editor, db: DB, settings: SettingsDep
) -> TestOut:
    t = _test(db, user, tid)
    r = purple.latest_round(t)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Round not found")
    record_round_blue(
        tid,
        r.number,
        RoundBlueIn(
            outcome=body.outcome,
            detected_at=body.detected_at,
            detected_by=[d.name for d in r.detections],
            blue_notes=body.blue_notes,
            expected_version=body.expected_version,
        ),
        user,
        db,
        settings,
    )
    return out_test(db, user, t, _open_gap_tests(db))


# ------------------------------------------------------------------ comments


@router.post("/tests/{tid}/comments", response_model=TestDetail, status_code=201)
def add_comment(tid: int, body: CommentIn, user: Reader, db: DB) -> TestDetail:
    t = _test(db, user, tid)
    if user.role == Role.auditor:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this action")
    _may_write(user, t)
    if body.round_number is not None:
        _round(t, body.round_number)
    purple.add_event(
        db, t, "comment", _side(user), user.username, body.round_number, text=body.text
    )
    audit.record(db, user, "comment", "test", f"{t.id}: {t.title}", {"round": body.round_number})
    db.commit()
    return out_detail(db, user, t, _open_gap_tests(db) if not _red(user) else None)


@router.delete("/tests/{tid}/comments/{eid}", response_model=TestDetail)
def remove_comment(tid: int, eid: int, user: Reader, db: DB) -> TestDetail:
    t = _test(db, user, tid)
    if user.role != Role.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an admin can remove a comment")
    e = next((x for x in t.events if x.id == eid and x.kind == "comment"), None)
    if e is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Comment not found")
    e.removed_by, e.removed_at, e.text = user.username, purple.utcnow(), ""
    audit.record(db, user, "comment_remove", "test", f"{t.id}: {t.title}", {"by": e.author})
    db.commit()
    return out_detail(db, user, t, _open_gap_tests(db))


# ------------------------------------------------------------------ quick tests and collaboration


@router.post("/quick-tests", response_model=TestOut, status_code=201)
def create_quick_test(body: QuickIn, user: Editor, db: DB, settings: SettingsDep) -> TestOut:
    if body.exec_status == TestStatus.executed and body.executed_at is None:
        raise HTTPException(422, "Enter when the test was executed")
    links = _resolve_links(db, body.links)
    t = _new_test(db, user, body, None, links)
    r = t.rounds[0]
    apply_red(
        db,
        t,
        r,
        user,
        exec_status=body.exec_status,
        started_at=body.executed_at,
        ended_at=None,
        what="",
        notes=body.red_notes,
        expected_version=None,
    )
    apply_blue(
        db,
        t,
        r,
        user,
        outcome=body.outcome,
        detected_at=body.detected_at,
        detected_by=[],
        notes=body.blue_notes,
        expected_version=None,
    )
    purple.sync_test(t)
    audit.record(
        db,
        user,
        "create",
        "quick_test",
        f"{t.id}: {t.title}",
        {"technique": t.technique, "outcome": body.outcome},
    )
    _refresh(db, settings, _rule_ids(t))
    db.commit()
    return out_test(db, user, t, _open_gap_tests(db))


@router.post("/campaigns/{cid}/collaboration")
def set_collaboration(cid: int, body: CollabIn, user: Editor, db: DB) -> dict[str, str]:
    c: Campaign = _campaign(db, user, cid)
    if c.status == CampaignStatus.closed:
        raise HTTPException(status.HTTP_409_CONFLICT, "A closed campaign cannot be changed")
    old = c.collaboration
    if old != body.collaboration:
        c.collaboration = body.collaboration
        for t in c.tests:
            purple.add_event(
                db,
                t,
                "collaboration",
                "system",
                user.username,
                None,
                data={"to": body.collaboration},
            )
        audit.record(
            db,
            user,
            "collaboration",
            "campaign",
            c.name,
            {"collaboration": [old, body.collaboration]},
        )
    db.commit()
    return {"collaboration": c.collaboration}


__all__ = ["attack", "date", "_links", "_defaults"]
