"""Tests against detection rules (PROJ-3): campaigns, quick tests, test library and gaps.

Rules of access (enforced here, not only in the UI):
- Admin and analyst (blue team) create and run everything.
- Auditors read everything.
- Red team accounts see only the campaigns they are assigned to. They create tests there and
  record the execution; the blue team's result, notes and files stay hidden until the campaign
  is closed. They never see rules, use cases or other pages (see security._gate).
"""

import re
from datetime import date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from pydantic import BaseModel, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app import attack, audit, files, purple
from app.api.deps import DB, SettingsDep
from app.db import lock_row
from app.models import (
    Campaign,
    CampaignStatus,
    GapAcceptance,
    L2UseCase,
    L3UseCase,
    Lifecycle,
    Role,
    TestAttachment,
    TestCase,
    TestOutcome,
    TestRule,
    TestStatus,
    TestTemplate,
    User,
)
from app.security import Admin, Editor, Reader, as_utc

# A field named `date` hides the type inside its own class body, so annotations use this alias.
Day = date

router = APIRouter(tags=["tests"])

TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
Title = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
Technique = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^T\d{4}(\.\d{3})?$")]
Text = Annotated[str, StringConstraints(max_length=10000)]
Tools = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]
Notes = Annotated[str, StringConstraints(max_length=10000)]
MAX_TEST_FILES = 50

# ------------------------------------------------------------------ small helpers


def _editor(user: User) -> bool:
    return user.role in (Role.admin, Role.analyst)


def _red(user: User) -> bool:
    return user.role == Role.red_team


def _campaign(db, user: User, cid: int) -> Campaign:
    c = db.get(Campaign, cid)
    if c is None or (_red(user) and not any(a.id == user.id for a in c.accounts)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Campaign not found")
    return c


def _test(db, user: User, tid: int) -> TestCase:
    t = db.get(TestCase, tid)
    if t is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Test not found")
    if _red(user):
        if t.campaign is None or not any(a.id == user.id for a in t.campaign.accounts):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Test not found")
    return t


def _blue_visible(user: User, t: TestCase) -> bool:
    """What a red team account sees of the blue team: everything once the campaign is closed or
    when the campaign is open (purple team); otherwise nothing."""
    if not _red(user):
        return True
    c = t.campaign
    return c is not None and (c.status == CampaignStatus.closed or c.collaboration == "open")


def _red_owns_open(user: User, t: TestCase) -> bool:
    """A red team account may change and delete its own test definition until the blue team has a
    result; while the blue side is hidden (blind campaign) until the test is executed, because
    the red team must not learn whether a result exists (audit L8)."""
    if not (_red(user) and t.created_by == user.username and t.created_by_red_team):
        return False
    if _blue_visible(user, t):
        return t.outcome is None
    return t.exec_status != TestStatus.executed and t.outcome is None


def _shown_status(user: User, t: TestCase) -> str:
    """The test status; while the blue side is hidden, "done" because of a result shows as
    "waiting" (audit L8)."""
    s = purple.test_status(t)
    if s == "done" and not _blue_visible(user, t):
        r = purple.latest_round(t)
        if r is not None and r.exec_status == TestStatus.executed:
            return "waiting"
    return s


def _defaults(settings: SettingsDep) -> int:
    return settings.default_verification_days


def _conflict(what: str, who: str | None) -> HTTPException:
    return HTTPException(
        status.HTTP_409_CONFLICT,
        f"This test was changed by {who or 'someone else'} ({what}); reload to see the changes",
    )


# ------------------------------------------------------------------ schemas


class LinkIn(BaseModel):
    l3_code: str
    scopes: list[str] = []


class LinkOut(BaseModel):
    l3_code: str
    rule_name: str
    scopes: list[str]
    deleted: bool
    rule_scopes: list[str]


class AttachmentOut(BaseModel):
    id: int
    side: str
    round: int | None = None
    filename: str
    size: int
    uploaded_by: str
    uploaded_at: datetime
    viewable: bool


class TestOut(BaseModel):
    __test__ = False
    id: int
    campaign_id: int | None
    campaign_name: str | None
    title: str
    technique: str
    technique_name: str | None
    description: str
    procedure: str
    tools: str
    prerequisites: str
    expected_detection: str
    created_by: str
    created_by_red_team: bool
    links: list[LinkOut]
    needs_rules: bool
    exec_status: TestStatus
    executed_at: datetime | None
    red_notes: str
    red_by: str | None
    red_at: datetime | None
    outcome: TestOutcome | None
    detected_at: datetime | None
    blue_notes: str | None
    blue_by: str | None
    blue_at: datetime | None
    time_to_detect_seconds: int | None
    attachments: list[AttachmentOut]
    version: int
    red_version: int
    blue_version: int
    status: str = "open"
    round_count: int = 1
    open_gaps: int = 0
    can_edit_definition: bool = False
    can_record_red: bool = False
    can_record_blue: bool = False
    can_delete: bool = False


class TestIn(BaseModel):
    __test__ = False
    title: Title
    technique: Technique
    description: Text = ""
    procedure: Text = ""
    tools: Tools = ""
    prerequisites: Text = ""
    expected_detection: Text = ""
    template_id: int | None = None
    links: list[LinkIn] = []
    expected_version: int | None = None


class QuickIn(TestIn):
    exec_status: TestStatus = TestStatus.executed
    executed_at: datetime | None = None
    red_notes: Notes = ""
    outcome: TestOutcome | None = None
    detected_at: datetime | None = None
    blue_notes: Notes = ""


class TemplateIn(BaseModel):
    title: Title
    technique: Technique
    description: Text = ""
    procedure: Text = ""
    tools: Tools = ""
    prerequisites: Text = ""
    expected_detection: Text = ""


class TemplateOut(TemplateIn):
    id: int
    uses: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    technique_name: str | None = None


class CampaignIn(BaseModel):
    collaboration: Literal["hidden", "open"] | None = None
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
    description: Text = ""
    planned_start: date
    planned_end: date
    account_ids: list[int] = []


class AccountOut(BaseModel):
    id: int
    username: str
    display_name: str


class CampaignOut(BaseModel):
    id: int
    name: str
    description: str
    planned_start: date
    planned_end: date
    status: CampaignStatus
    collaboration: str = "hidden"
    tests: int
    outcomes: dict[str, int] | None
    open_points: int
    accounts: list[AccountOut]
    can_delete: bool = False


class CampaignDetail(CampaignOut):
    test_cases: list[TestOut]


class StatusIn(BaseModel):
    status: CampaignStatus


class ProposalRule(BaseModel):
    code: str
    name: str
    scopes: list[str]


class Proposal(BaseModel):
    technique: str
    technique_name: str | None
    rules: list[ProposalRule]
    templates: list[TemplateOut]
    existing_tests: int


class ProposalsIn(BaseModel):
    l2_codes: list[str] = []
    l3_codes: list[str] = []


class ProposalsOut(BaseModel):
    proposals: list[Proposal]
    no_technique: list[ProposalRule]
    notes: list[str]


class GapOut(BaseModel):
    l3_code: str | None
    rule_name: str | None
    technique: str
    technique_name: str | None
    scope: str
    outcome: str
    test_id: int
    test_title: str
    executed_at: datetime
    campaign_id: int | None
    campaign_name: str | None
    accepted: bool
    accepted_reason: str | None
    accepted_by: str | None
    accepted_at: datetime | None


class AcceptIn(BaseModel):
    l3_code: str | None = None
    technique: Technique
    scope: str = ""
    test_id: int
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


# ------------------------------------------------------------------ serialisation


# what out_test reads of a test; load lists of tests with these to avoid a query per test
TEST_LOAD = (
    selectinload(TestCase.campaign),
    selectinload(TestCase.rules),
    selectinload(TestCase.attachments),
    selectinload(TestCase.rounds),
)


def linked_rules(db, tests: list[TestCase]) -> dict[int, L3UseCase]:
    """The rules the tests link to, with their scopes, in one query."""
    ids = {r.l3_id for t in tests for r in t.rules if r.l3_id}
    if not ids:
        return {}
    q = select(L3UseCase).where(L3UseCase.id.in_(ids)).options(selectinload(L3UseCase.references))
    return {r.id: r for r in db.scalars(q)}


def _links(db, t: TestCase, rules: dict[int, L3UseCase] | None = None) -> list[LinkOut]:
    if rules is None:
        rules = linked_rules(db, [t])
    out = []
    for r in t.rules:
        rule = rules.get(r.l3_id) if r.l3_id else None
        out.append(
            LinkOut(
                l3_code=rule.code if rule else r.rule_code,
                rule_name=rule.name if rule else r.rule_name,
                scopes=list(r.scopes or []),
                deleted=rule is None,
                rule_scopes=purple.rule_scopes(rule) if rule else [],
            )
        )
    return out


def _att(a: TestAttachment, t: TestCase | None = None) -> AttachmentOut:
    number = None
    if t is not None and a.round_id is not None:
        number = next((r.number for r in t.rounds if r.id == a.round_id), None)
    return AttachmentOut(
        id=a.id,
        side=a.side,
        round=number,
        filename=a.filename,
        size=a.size,
        uploaded_by=a.uploaded_by,
        uploaded_at=a.uploaded_at,
        viewable=files.viewable(a.filename),
    )


def _ttd(t: TestCase) -> int | None:
    if t.outcome in purple.SUCCESS and t.executed_at and t.detected_at:
        return int((as_utc(t.detected_at) - as_utc(t.executed_at)).total_seconds())
    return None


def _open_gap_tests(db, technique: str | None = None) -> set[int]:
    """Tests with an open gap; with a technique only (and exactly) those of that technique."""
    return {g.test_id for g in purple.gaps(db, technique) if not g.accepted}


def out_tests(db, user: User, tests: list[TestCase], gap_tests: set[int] | None) -> list[TestOut]:
    rules = {} if _red(user) else linked_rules(db, tests)
    return [out_test(db, user, t, gap_tests, rules) for t in tests]


def out_test(
    db,
    user: User,
    t: TestCase,
    gap_tests: set[int] | None = None,
    rules: dict[int, L3UseCase] | None = None,
) -> TestOut:
    red = _red(user)
    blue_ok = _blue_visible(user, t)
    running = t.campaign is None or t.campaign.status == CampaignStatus.running
    editable = t.campaign is None or t.campaign.status != CampaignStatus.closed
    own = _red_owns_open(user, t)
    return TestOut(
        id=t.id,
        campaign_id=t.campaign_id,
        campaign_name=t.campaign.name if t.campaign else None,
        title=t.title,
        technique=t.technique,
        technique_name=attack.name(t.technique),
        description=t.description,
        procedure=t.procedure,
        tools=t.tools,
        prerequisites=t.prerequisites,
        expected_detection=t.expected_detection,
        created_by=t.created_by,
        created_by_red_team=t.created_by_red_team,
        links=[] if red else _links(db, t, rules),
        needs_rules=t.created_by_red_team and not t.rules,
        exec_status=t.exec_status,
        executed_at=t.executed_at,
        red_notes=t.red_notes,
        red_by=t.red_by,
        red_at=t.red_at,
        outcome=t.outcome if blue_ok else None,
        detected_at=t.detected_at if blue_ok else None,
        blue_notes=t.blue_notes if blue_ok else None,
        blue_by=t.blue_by if blue_ok else None,
        blue_at=t.blue_at if blue_ok else None,
        time_to_detect_seconds=_ttd(t) if blue_ok else None,
        attachments=[_att(a, t) for a in t.attachments if a.side == "red" or blue_ok],
        version=t.version,
        red_version=t.red_version,
        blue_version=t.blue_version,
        status=_shown_status(user, t),
        round_count=len(t.rounds),
        open_gaps=1 if gap_tests is not None and t.id in gap_tests and blue_ok else 0,
        can_edit_definition=editable and (_editor(user) or own),
        can_record_red=running and (_editor(user) or red) and not user.role == Role.auditor,
        can_record_blue=running and _editor(user),
        can_delete=editable and t.outcome is None and (_editor(user) or own),
    )


def _counts(c: Campaign) -> dict[str, int]:
    n = {o.value: 0 for o in TestOutcome}
    for t in c.tests:
        if t.outcome:
            n[t.outcome.value] += 1
    return n


def out_campaign(user: User, c: Campaign) -> CampaignOut:
    show = not _red(user) or c.status == CampaignStatus.closed or c.collaboration == "open"
    return CampaignOut(
        id=c.id,
        name=c.name,
        description=c.description,
        planned_start=c.planned_start,
        planned_end=c.planned_end,
        status=c.status,
        collaboration=c.collaboration,
        tests=len(c.tests),
        outcomes=_counts(c) if show else None,
        open_points=sum(1 for t in c.tests if t.created_by_red_team and not t.rules)
        if _editor(user) or user.role == Role.auditor
        else 0,
        accounts=[
            AccountOut(id=a.id, username=a.username, display_name=a.display_name)
            for a in c.accounts
        ],
        can_delete=user.role == Role.admin
        and (c.status == CampaignStatus.planned or not any(t.outcome for t in c.tests)),
    )


# ------------------------------------------------------------------ links and verification


def _resolve_links(db, links: list[LinkIn]) -> list[tuple[L3UseCase, list[str]]]:
    out: list[tuple[L3UseCase, list[str]]] = []
    seen: set[str] = set()
    for ln in links:
        rule = db.scalar(select(L3UseCase).where(L3UseCase.code == ln.l3_code))
        if rule is None:
            raise HTTPException(422, f"Rule {ln.l3_code} not found")
        if rule.code in seen:
            raise HTTPException(422, f"Rule {rule.code} is linked twice")
        seen.add(rule.code)
        have = purple.rule_scopes(rule)
        scopes = list(dict.fromkeys(ln.scopes))
        if have:
            if not scopes:
                raise HTTPException(422, f"Choose the scopes this test covers for {rule.code}")
            bad = [s for s in scopes if s not in have]
            if bad:
                raise HTTPException(
                    422,
                    f"{rule.code} has no scope {', '.join(bad)} (its scopes: {', '.join(have)})",
                )
        else:
            scopes = []
        out.append((rule, scopes))
    return out


def _set_links(db, t: TestCase, links: list[tuple[L3UseCase, list[str]]]) -> set[int]:
    """Replace the links; returns the ids of every rule whose verification may change."""
    touched = {r.l3_id for r in t.rules if r.l3_id}
    t.rules.clear()
    db.flush()
    for rule, scopes in links:
        t.rules.append(
            TestRule(l3_id=rule.id, rule_code=rule.code, rule_name=rule.name, scopes=scopes)
        )
        touched.add(rule.id)
    return touched


def _refresh(db, settings, rule_ids: set[int]) -> None:
    db.flush()
    purple.recompute_rules(db, rule_ids, _defaults(settings))


def _rule_ids(t: TestCase) -> set[int]:
    return {r.l3_id for r in t.rules if r.l3_id}


def _new_test(
    db,
    user: User,
    body: TestIn,
    campaign: Campaign | None,
    links: list[tuple[L3UseCase, list[str]]],
) -> TestCase:
    t = TestCase(
        campaign=campaign,
        title=body.title,
        technique=body.technique,
        description=body.description,
        procedure=body.procedure,
        tools=body.tools,
        prerequisites=body.prerequisites,
        expected_detection=body.expected_detection,
        template_id=body.template_id,
        created_by=user.username,
        created_by_red_team=_red(user),
    )
    if body.template_id:
        tpl = db.get(TestTemplate, body.template_id)
        if tpl:
            tpl.uses += 1
    db.add(t)
    db.flush()
    t.rounds.append(purple.new_round(1, user.username))
    purple.sync_test(t)
    db.flush()
    purple.add_event(db, t, "round_opened", "red" if _red(user) else "blue", user.username, 1)
    _set_links(db, t, links)
    return t


# ------------------------------------------------------------------ test library


def _tpl_out(t: TestTemplate) -> TemplateOut:
    return TemplateOut(
        id=t.id,
        title=t.title,
        technique=t.technique,
        description=t.description,
        procedure=t.procedure,
        tools=t.tools,
        prerequisites=t.prerequisites,
        expected_detection=t.expected_detection,
        uses=t.uses,
        created_by=t.created_by,
        created_at=t.created_at,
        updated_at=t.updated_at,
        technique_name=attack.name(t.technique),
    )


@router.get("/library", response_model=list[TemplateOut])
def list_templates(
    _: Reader, db: DB, technique: str | None = None, q: str | None = None
) -> list[TemplateOut]:
    rows = db.scalars(select(TestTemplate).order_by(TestTemplate.technique, TestTemplate.title))
    out = []
    for t in rows:
        if technique and t.technique != technique:
            continue
        if q and q.lower() not in f"{t.title}\n{t.description}\n{t.procedure}".lower():
            continue
        out.append(_tpl_out(t))
    return out


@router.post("/library", response_model=TemplateOut, status_code=201)
def create_template(body: TemplateIn, user: Editor, db: DB) -> TemplateOut:
    t = TestTemplate(**body.model_dump(), created_by=user.username)
    db.add(t)
    db.flush()
    audit.record(db, user, "create", "test_template", str(t.id), {"title": t.title})
    db.commit()
    return _tpl_out(t)


@router.put("/library/{tid}", response_model=TemplateOut)
def update_template(tid: int, body: TemplateIn, user: Editor, db: DB) -> TemplateOut:
    t = db.get(TestTemplate, tid)
    if t is None:
        raise HTTPException(404, "Template not found")
    for k, v in body.model_dump().items():
        setattr(t, k, v)
    audit.record(db, user, "update", "test_template", str(t.id), {"title": t.title})
    db.commit()
    return _tpl_out(t)


@router.delete("/library/{tid}", status_code=204)
def delete_template(tid: int, user: Editor, db: DB) -> None:
    t = db.get(TestTemplate, tid)
    if t is None:
        raise HTTPException(404, "Template not found")
    audit.record(db, user, "delete", "test_template", str(t.id), {"title": t.title})
    db.delete(t)
    db.commit()


@router.post("/tests/{tid}/library", response_model=TemplateOut, status_code=201)
def save_to_library(tid: int, user: Editor, db: DB) -> TemplateOut:
    t = _test(db, user, tid)
    tpl = TestTemplate(
        title=t.title,
        technique=t.technique,
        description=t.description,
        procedure=t.procedure,
        tools=t.tools,
        prerequisites=t.prerequisites,
        expected_detection=t.expected_detection,
        created_by=user.username,
    )
    db.add(tpl)
    db.flush()
    audit.record(
        db, user, "create", "test_template", str(tpl.id), {"title": tpl.title, "from_test": t.id}
    )
    db.commit()
    return _tpl_out(tpl)


# ------------------------------------------------------------------ campaigns


@router.get("/campaigns", response_model=list[CampaignOut])
def list_campaigns(user: Reader, db: DB) -> list[CampaignOut]:
    rows = db.scalars(
        select(Campaign)
        .options(
            selectinload(Campaign.accounts),
            selectinload(Campaign.tests).selectinload(TestCase.rules),
        )
        .order_by(Campaign.planned_start.desc(), Campaign.id.desc())
    )
    return [
        out_campaign(user, c)
        for c in rows
        if not _red(user) or any(a.id == user.id for a in c.accounts)
    ]


def _accounts(db, ids: list[int]) -> list[User]:
    users = list(db.scalars(select(User).where(User.id.in_(ids)))) if ids else []
    if len(users) != len(set(ids)) or any(u.role != Role.red_team for u in users):
        raise HTTPException(422, "Only red team accounts can be assigned to a campaign")
    return users


def _check_dates(body: CampaignIn) -> None:
    if body.planned_end < body.planned_start:
        raise HTTPException(422, "The planned end cannot be before the planned start")


@router.post("/campaigns", response_model=CampaignOut, status_code=201)
def create_campaign(body: CampaignIn, user: Editor, db: DB) -> CampaignOut:
    _check_dates(body)
    if db.scalar(select(Campaign).where(func.lower(Campaign.name) == body.name.lower())):
        raise HTTPException(409, "A campaign with this name exists already")
    c = Campaign(
        name=body.name,
        description=body.description,
        planned_start=body.planned_start,
        planned_end=body.planned_end,
        created_by=user.username,
        collaboration=body.collaboration or "hidden",
        accounts=_accounts(db, body.account_ids),
    )
    db.add(c)
    db.flush()
    audit.record(
        db,
        user,
        "create",
        "campaign",
        c.name,
        {"start": body.planned_start, "end": body.planned_end},
    )
    db.commit()
    return out_campaign(user, c)


@router.get("/campaigns/{cid}", response_model=CampaignDetail)
def get_campaign(cid: int, user: Reader, db: DB) -> CampaignDetail:
    c = _campaign(db, user, cid)
    gap_tests = _open_gap_tests(db) if not _red(user) else None
    tests = list(
        db.scalars(
            select(TestCase)
            .where(TestCase.campaign_id == c.id)
            .options(*TEST_LOAD)
            .order_by(TestCase.id)
        )
    )
    return CampaignDetail(
        **out_campaign(user, c).model_dump(),
        test_cases=out_tests(db, user, tests, gap_tests),
    )


@router.put("/campaigns/{cid}", response_model=CampaignOut)
def update_campaign(cid: int, body: CampaignIn, user: Editor, db: DB) -> CampaignOut:
    c = _campaign(db, user, cid)
    _check_dates(body)
    clash = db.scalar(
        select(Campaign).where(func.lower(Campaign.name) == body.name.lower(), Campaign.id != c.id)
    )
    if clash:
        raise HTTPException(409, "A campaign with this name exists already")
    c.name, c.description = body.name, body.description
    c.planned_start, c.planned_end = body.planned_start, body.planned_end
    c.accounts = _accounts(db, body.account_ids)
    audit.record(
        db, user, "update", "campaign", c.name, {"accounts": [a.username for a in c.accounts]}
    )
    db.commit()
    return out_campaign(user, c)


@router.delete("/campaigns/{cid}", status_code=204)
def delete_campaign(cid: int, user: Admin, db: DB, settings: SettingsDep) -> None:
    c = _campaign(db, user, cid)
    if not out_campaign(user, c).can_delete:
        raise HTTPException(409, "A campaign with results cannot be deleted")
    rules = {rid for t in c.tests for rid in _rule_ids(t)}
    audit.record(db, user, "delete", "campaign", c.name)
    db.delete(c)
    _refresh(db, settings, rules)
    db.commit()


@router.post("/campaigns/{cid}/status", response_model=CampaignOut)
def set_status(cid: int, body: StatusIn, user: Editor, db: DB) -> CampaignOut:
    c = _campaign(db, user, cid)
    allowed = {
        CampaignStatus.planned: {CampaignStatus.running},
        CampaignStatus.running: {CampaignStatus.closed},
        CampaignStatus.closed: {CampaignStatus.running},
    }
    if body.status not in allowed[c.status]:
        raise HTTPException(409, f"A {c.status.value} campaign cannot become {body.status.value}")
    if body.status == CampaignStatus.closed:
        open_ = purple.can_close(c)
        if open_:
            raise HTTPException(409, "These tests are not finished: " + ", ".join(open_[:10]))
    old = c.status
    c.status = body.status
    for t in c.tests:
        purple.add_event(
            db, t, "campaign_status", "system", user.username, None, data={"to": body.status.value}
        )
    audit.record(db, user, "status", "campaign", c.name, {"status": [old.value, body.status.value]})
    db.commit()
    return out_campaign(user, c)


@router.post("/campaigns/{cid}/proposals", response_model=ProposalsOut)
def proposals(cid: int, body: ProposalsIn, user: Editor, db: DB) -> ProposalsOut:
    c = _campaign(db, user, cid)
    rules: dict[int, L3UseCase] = {}
    for code in body.l2_codes:
        l2 = db.scalar(select(L2UseCase).where(L2UseCase.code == code))
        if l2 is None:
            raise HTTPException(422, f"Use case {code} not found")
        for r in l2.children:
            if r.lifecycle_status != Lifecycle.retired:
                rules[r.id] = r
    for code in body.l3_codes:
        r = db.scalar(select(L3UseCase).where(L3UseCase.code == code))
        if r is None:
            raise HTTPException(422, f"Rule {code} not found")
        rules[r.id] = r
    by_tech: dict[str, list[L3UseCase]] = {}
    none: list[ProposalRule] = []
    notes: list[str] = []
    for r in sorted(rules.values(), key=lambda x: x.code):
        shown = ProposalRule(code=r.code, name=r.name, scopes=purple.rule_scopes(r))
        techs = []
        for tid in r.attack_techniques or []:
            st, new = attack.status(tid)
            if st in ("current", "revoked") and new:
                techs.append(new)
            else:
                notes.append(f"{r.code}: technique {tid} is {st} and is not proposed")
        techs = list(dict.fromkeys(techs))
        if not techs:
            none.append(shown)
        for tid in techs:
            by_tech.setdefault(tid, []).append(r)
    existing: dict[str, int] = {}
    for t in c.tests:
        existing[t.technique] = existing.get(t.technique, 0) + 1
    out = []
    for tid, rs in sorted(by_tech.items()):
        tpls = list(
            db.scalars(
                select(TestTemplate).where(TestTemplate.technique == tid).order_by(TestTemplate.id)
            )
        )
        out.append(
            Proposal(
                technique=tid,
                technique_name=attack.name(tid),
                rules=[
                    ProposalRule(code=r.code, name=r.name, scopes=purple.rule_scopes(r)) for r in rs
                ],
                templates=[_tpl_out(x) for x in tpls],
                existing_tests=existing.get(tid, 0),
            )
        )
    return ProposalsOut(proposals=out, no_technique=none, notes=notes)


# ------------------------------------------------------------------ tests in campaigns


@router.post("/campaigns/{cid}/tests", response_model=TestOut, status_code=201)
def add_test(cid: int, body: TestIn, user: Reader, db: DB, settings: SettingsDep) -> TestOut:
    c = _campaign(db, user, cid)
    if user.role == Role.auditor:
        raise HTTPException(403, "Your role does not allow this action")
    if c.status == CampaignStatus.closed:
        raise HTTPException(409, "A closed campaign cannot be changed; reopen it first")
    if _red(user) and body.links:
        raise HTTPException(403, "Linking rules is done by the blue team")
    links = _resolve_links(db, body.links)
    t = _new_test(db, user, body, c, links)
    audit.record(db, user, "create", "test", f"{c.name}: {t.title}", {"technique": t.technique})
    _refresh(db, settings, _rule_ids(t))
    db.commit()
    return out_test(db, user, t)


def _must_edit_definition(db, user: User, t: TestCase) -> None:
    if user.role == Role.auditor:
        raise HTTPException(403, "Your role does not allow this action")
    if t.campaign is not None and t.campaign.status == CampaignStatus.closed:
        raise HTTPException(409, "A closed campaign cannot be changed; reopen it first")
    if _red(user) and not _red_owns_open(user, t):
        if not _blue_visible(user, t):
            raise HTTPException(403, "You can only change tests you created, until they are run")
        raise HTTPException(
            403, "You can only change tests you created, until the blue team has a result"
        )


@router.put("/tests/{tid}", response_model=TestOut)
def update_test(tid: int, body: TestIn, user: Reader, db: DB, settings: SettingsDep) -> TestOut:
    t = _test(db, user, tid)
    _must_edit_definition(db, user, t)
    if body.expected_version is not None:
        lock_row(db, t)
    if body.expected_version is not None and body.expected_version != t.version:
        raise _conflict("definition", t.created_by)
    if _red(user) and body.links:
        raise HTTPException(403, "Linking rules is done by the blue team")
    touched = set()
    t.title, t.technique = body.title, body.technique
    t.description = body.description
    t.procedure, t.tools = body.procedure, body.tools
    t.prerequisites, t.expected_detection = body.prerequisites, body.expected_detection
    if not _red(user):
        touched = _set_links(db, t, _resolve_links(db, body.links))
    t.version += 1
    audit.record(db, user, "update", "test", f"{t.id}: {t.title}", {"technique": t.technique})
    _refresh(db, settings, touched | _rule_ids(t))
    db.commit()
    return out_test(db, user, t)


@router.delete("/tests/{tid}", status_code=204)
def delete_test(tid: int, user: Reader, db: DB, settings: SettingsDep) -> None:
    t = _test(db, user, tid)
    _must_edit_definition(db, user, t)
    if t.outcome is not None:  # a red team account was refused above already (no hint)
        raise HTTPException(409, "A test with a result cannot be deleted")
    rules = _rule_ids(t)
    audit.record(db, user, "delete", "test", f"{t.id}: {t.title}")
    db.delete(t)
    _refresh(db, settings, rules)
    db.commit()


# ------------------------------------------------------------------ quick tests


@router.get("/quick-tests", response_model=list[TestOut])
def list_quick_tests(
    user: Reader,
    db: DB,
    outcome: TestOutcome | None = None,
    technique: str | None = None,
    open_gaps: bool = False,
) -> list[TestOut]:
    gap_tests = _open_gap_tests(db)
    q = (
        select(TestCase)
        .where(TestCase.campaign_id.is_(None))
        .options(*TEST_LOAD)
        .order_by(TestCase.id.desc())
    )
    if outcome:
        q = q.where(TestCase.outcome == outcome)
    if technique:
        q = q.where(TestCase.technique == technique)
    if open_gaps:
        q = q.where(TestCase.id.in_(gap_tests))
    return out_tests(db, user, list(db.scalars(q)), gap_tests)


# ------------------------------------------------------------------ attachments


def _may_attach(user: User, t: TestCase) -> str:
    if user.role == Role.auditor:
        raise HTTPException(403, "Your role does not allow this action")
    if t.campaign is not None and t.campaign.status != CampaignStatus.running:
        raise HTTPException(409, "Files can only be added while the campaign is running")
    return "red" if _red(user) else "blue"


@router.post("/tests/{tid}/attachments", response_model=AttachmentOut, status_code=201)
async def upload(
    tid: int,
    user: Reader,
    db: DB,
    settings: SettingsDep,
    file: UploadFile = File(...),
    round: int | None = Query(None, description="Round number; default the latest round"),
) -> AttachmentOut:
    t = _test(db, user, tid)
    side = _may_attach(user, t)
    target = (
        next((r for r in t.rounds if r.number == round), None)
        if round is not None
        else purple.latest_round(t)
    )
    if round is not None and target is None:
        raise HTTPException(404, "Round not found")
    name, kind, data, sha = await files.read_upload(
        file,
        db,
        settings,
        types_message="This file type is not accepted. Allowed: PDF, JPG, PNG and diagram files",
    )
    if len(t.attachments) >= MAX_TEST_FILES:
        raise HTTPException(422, f"A test can have at most {MAX_TEST_FILES} files")
    a = TestAttachment(
        test_id=t.id,
        side=side,
        filename=name,
        content_type=files.TYPES[kind][0],
        size=len(data),
        sha256=sha,
        data=data,
        uploaded_by=user.username,
        round_id=target.id if target else None,
    )
    db.add(a)
    db.flush()
    purple.add_event(
        db,
        t,
        "file_added",
        side,
        user.username,
        target.number if target else None,
        data={"file": name},
    )
    audit.record(
        db,
        user,
        "upload",
        "test_attachment",
        f"{t.id}: {t.title}",
        {"file": name, "size": len(data)},
    )
    db.commit()
    return _att(a, t)


def _attachment(db, user: User, aid: int) -> TestAttachment:
    a = db.get(TestAttachment, aid)
    if a is None:
        raise HTTPException(404, "File not found")
    t = _test(db, user, a.test_id)
    if a.side == "blue" and not _blue_visible(user, t):
        raise HTTPException(404, "File not found")
    return a


@router.get("/test-attachments/{aid}/content")
def attachment_content(aid: int, user: Reader, db: DB, download: bool = False) -> Response:
    a = _attachment(db, user, aid)
    inline = files.viewable(a.filename) and not download
    audit.record_access(
        db,
        user,
        "view" if inline else "download",
        "test_attachment",
        f"{a.test_id}",
        {"file": a.filename},
    )
    return files.file_response(a.data, a.filename, a.content_type, inline)


@router.delete("/test-attachments/{aid}", status_code=204)
def delete_attachment(aid: int, user: Reader, db: DB) -> None:
    a = _attachment(db, user, aid)
    t = a.test
    if user.role == Role.auditor or a.uploaded_by != user.username:
        raise HTTPException(403, "You can only remove your own files")
    if t.campaign is not None and t.campaign.status != CampaignStatus.running:
        raise HTTPException(409, "Files can only be removed while the campaign is running")
    number = next((r.number for r in t.rounds if r.id == a.round_id), None)
    purple.add_event(
        db, t, "file_removed", a.side, user.username, number, data={"file": a.filename}
    )
    audit.record(db, user, "delete", "test_attachment", f"{t.id}: {t.title}", {"file": a.filename})
    db.delete(a)
    db.commit()


# ------------------------------------------------------------------ gaps and rule views


def _gap_out(g: purple.Gap) -> GapOut:
    return GapOut(
        l3_code=g.rule_code,
        rule_name=g.rule_name,
        technique=g.technique,
        technique_name=attack.name(g.technique),
        scope=g.scope,
        outcome=g.outcome,
        test_id=g.test_id,
        test_title=g.test_title,
        executed_at=g.executed_at,
        campaign_id=g.campaign_id,
        campaign_name=g.campaign_name,
        accepted=g.accepted,
        accepted_reason=g.accepted_reason,
        accepted_by=g.accepted_by,
        accepted_at=g.accepted_at,
    )


@router.get("/test-gaps", response_model=list[GapOut])
def list_gaps(_: Reader, db: DB, accepted: bool = Query(False)) -> list[GapOut]:
    return [_gap_out(g) for g in purple.gaps(db) if accepted or not g.accepted]


@router.post("/test-gaps/accept", status_code=204)
def accept_gap(body: AcceptIn, user: Editor, db: DB) -> None:
    rule = None
    if body.l3_code:
        rule = db.scalar(select(L3UseCase).where(L3UseCase.code == body.l3_code))
        if rule is None:
            raise HTTPException(404, "Rule not found")
    match = [
        g
        for g in purple.gaps(db)
        if g.test_id == body.test_id
        and g.technique == body.technique
        and g.scope == body.scope
        and g.l3_id == (rule.id if rule else None)
        and not g.accepted
    ]
    if not match:
        raise HTTPException(404, "This gap is not open")
    db.add(
        GapAcceptance(
            l3_id=rule.id if rule else None,
            technique=body.technique,
            scope=body.scope,
            test_id=body.test_id,
            reason=body.reason,
            accepted_by=user.username,
        )
    )
    audit.record(
        db,
        user,
        "accept",
        "test_gap",
        f"{body.l3_code or '-'} {body.technique} {body.scope}",
        {"reason": body.reason},
    )
    db.commit()


class ScopeOut(BaseModel):
    scope: str
    status: str
    test_id: int | None
    test_title: str | None
    outcome: str | None
    date: Day | None
    until: Day | None


class RuleTests(BaseModel):
    state: str
    covered: int
    total: int
    verified_date: date | None
    scopes: list[ScopeOut]
    tests: list[TestOut]
    gaps: list[GapOut]
    interval_days: int


@router.get("/l3/{code}/tests", response_model=RuleTests)
def rule_tests(code: str, user: Reader, db: DB, settings: SettingsDep) -> RuleTests:
    rule = db.scalar(select(L3UseCase).where(L3UseCase.code == code))
    if rule is None:
        raise HTTPException(404, "Rule not found")
    st = purple.rule_state(db, rule, _defaults(settings))
    tests = list(
        db.scalars(
            select(TestCase)
            .where(TestCase.rules.any(TestRule.l3_id == rule.id))
            .options(*TEST_LOAD)
            .order_by(TestCase.id.desc())
        )
    )
    all_gaps = purple.gaps(db)
    gap_tests = {g.test_id for g in all_gaps if not g.accepted}
    return RuleTests(
        state=st.state,
        covered=st.covered,
        total=st.total,
        verified_date=st.verified_date,
        scopes=[ScopeOut(**vars(s)) for s in st.scopes],
        tests=out_tests(db, user, tests, gap_tests),
        gaps=[_gap_out(g) for g in all_gaps if g.l3_id == rule.id],
        interval_days=purple.interval_days(rule, _defaults(settings)),
    )


class L2Summary(BaseModel):
    tests: int
    last_test: date | None
    open_gaps: int
    states: dict[str, int]


@router.get("/l2/{code}/tests-summary", response_model=L2Summary)
def l2_summary(code: str, _: Reader, db: DB, settings: SettingsDep) -> L2Summary:
    l2 = db.scalar(select(L2UseCase).where(L2UseCase.code == code))
    if l2 is None:
        raise HTTPException(404, "Use case not found")
    rules = list(
        db.scalars(
            select(L3UseCase)
            .where(L3UseCase.l2_id == l2.id)
            .options(selectinload(L3UseCase.references))
        )
    )
    ids = {r.id for r in rules}
    states = {"verified": 0, "partial": 0, "issues": 0, "due": 0, "none": 0}
    for st in purple.rule_states(db, rules, _defaults(settings)).values():
        states[st.state] += 1
    runs = (
        db.execute(
            select(TestCase.id, TestCase.executed_at)
            .join(TestRule, TestRule.test_id == TestCase.id)
            .where(TestRule.l3_id.in_(ids))
            .distinct()
        ).all()
        if ids
        else []
    )
    test_ids = {i for i, _ in runs}
    dates = [purple.day(at) for _, at in runs if at]
    open_gaps = sum(1 for g in purple.gaps(db) if not g.accepted and g.l3_id in ids)
    return L2Summary(
        tests=len(test_ids),
        last_test=max(dates) if dates else None,
        open_gaps=open_gaps,
        states=states,
    )


class GapCount(BaseModel):
    open: int


@router.get("/test-gaps/count", response_model=GapCount)
def gap_count(_: Reader, db: DB) -> GapCount:
    return GapCount(open=sum(1 for g in purple.gaps(db) if not g.accepted))


@router.get("/red-team-accounts", response_model=list[AccountOut])
def red_team_accounts(_: Editor, db: DB) -> list[AccountOut]:
    return [
        AccountOut(id=u.id, username=u.username, display_name=u.display_name)
        for u in db.scalars(select(User).where(User.role == Role.red_team).order_by(User.username))
    ]
