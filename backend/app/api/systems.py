"""Systems, business owner interviews and the STRIDE mapping (issue #17, app/interviews.py)."""

from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import Response
from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app import attack, audit
from app import interviews as iv
from app.api import evidence
from app.api.deps import DB, SettingsDep
from app.models import (
    DetectionRequestState,
    Interview,
    InterviewStatus,
    L2UseCase,
    L3UseCase,
    ReferenceItem,
    RefKind,
    RequestStatus,
    StrideMapping,
    System,
    SystemLink,
    User,
)
from app.score_queries import compute_scores
from app.security import Admin, Editor, Reader

router = APIRouter(tags=["systems & interviews"])

TEXT_MAX = 10_000
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
Short = Annotated[str, StringConstraints(strip_whitespace=True, max_length=255)]
Text = Annotated[str, StringConstraints(max_length=TEXT_MAX)]
Stride = Literal[iv.STRIDE]  # type: ignore[valid-type]
Rating = Annotated[int, Field(ge=1, le=5)]


def _today() -> date:
    return date.today()


def _not_future(v: date) -> date:
    # The server counts in UTC; a browser east of it is up to a day ahead.
    if v > _today() + timedelta(days=1):
        raise ValueError("The date cannot be in the future")
    return v


# ---------------------------------------------------------------- schemas


class SystemIn(BaseModel):
    name: Name
    description: Text = ""
    owner_name: Name
    owner_department: Short = ""
    owner_email: EmailStr | None = None
    criticality: Annotated[int, Field(ge=1, le=5)]
    internet_facing: bool = False
    data_classification: Literal[iv.CLASSIFICATIONS] = "internal"  # type: ignore[valid-type]
    review_interval_months: Annotated[int, Field(ge=1, le=60)] = 12
    archived: bool = False

    @field_validator("owner_email", mode="before")
    @classmethod
    def _blank_email(cls, v):
        return None if isinstance(v, str) and not v.strip() else v


class SystemRow(BaseModel):
    id: int
    name: str
    description: str
    owner_name: str
    owner_department: str
    owner_email: str | None
    criticality: int
    internet_facing: bool
    data_classification: str
    review_interval_months: int
    archived: bool
    updated_at: datetime | None
    linked: int
    coverage: float | None
    gaps: int
    last_interview: date | None
    next_due: date | None
    state: Literal["none", "due", "ok"]
    draft_id: int | None
    can_delete: bool


class LinkOut(BaseModel):
    level: Literal["L2", "L3"] = "L2"
    l2_id: int
    l3_id: int | None = None
    code: str
    name: str
    l2_code: str
    detection: str | None = None
    weight: float | None
    risk_score: int
    risk_level: int | None
    sources: list[dict]


class InterviewRow(BaseModel):
    id: int
    status: InterviewStatus
    interview_date: date
    analyst: str
    completed_at: datetime | None
    confirmed_by: str | None
    confirmed_at: date | None
    previous_id: int | None


class SystemDetail(SystemRow):
    links: list[LinkOut]
    # risk overview of the latest completed interview with the current state of its links
    risks: list[dict]
    threshold: int | None
    # components of that interview, in interview order (rows of the threat matrix)
    components: list[dict]
    gap_no_rules: list[dict]
    gap_log_sources: list[dict]
    gap_requests: list[dict]
    # issue #59: risks above the threshold that no linked use case addresses
    gap_risks: list[dict] = []
    interviews: list[InterviewRow]


class ThreatIn(BaseModel):
    category: Stride
    state: Literal[iv.STATES] = "not_discussed"  # type: ignore[valid-type]
    description: Text = ""
    likelihood: Rating | None = None
    impact: Rating | None = None


Key = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,40}$")]
Technique = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^T\d{4}(\.\d{3})?$")]


class CustomThreatIn(BaseModel):
    """A threat beyond STRIDE, linked to MITRE ATT&CK techniques (#60). It always applies."""

    key: Key
    # a draft may hold a threat that is still being written; completion needs title, at least
    # one technique, likelihood and impact (app/interviews.py)
    title: Short = ""
    description: Text = ""
    techniques: list[Technique] = Field(default_factory=list, max_length=50)
    likelihood: Rating | None = None
    impact: Rating | None = None


class ComponentIn(BaseModel):
    key: Key
    name: Name
    description: Text = ""
    log_source_ids: list[int] = Field(default_factory=list, max_length=200)
    threats: list[ThreatIn] = Field(default_factory=list, max_length=6)
    custom_threats: list[CustomThreatIn] = Field(default_factory=list, max_length=50)


# a STRIDE category or a custom threat (custom:<key>, #60)
ThreatCategory = Stride | Annotated[str, StringConstraints(pattern=r"^custom:[A-Za-z0-9_-]{1,40}$")]


class ThreatRef(BaseModel):
    component: str
    category: ThreatCategory


class AddedIn(BaseModel):
    """A use case chosen by hand: a whole L2 (`l2_id`) or a single L3 rule (`l3_id`)."""

    l2_id: int | None = None
    l3_id: int | None = None
    threats: list[ThreatRef] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def _one_level(self):
        if (self.l2_id is None) == (self.l3_id is None):
            raise ValueError("Choose either an L2 use case or an L3 rule")
        return self


class RemovedIn(BaseModel):
    """A proposed L2 removed by hand: as a whole, or only from the listed threats (#57)."""

    l2_id: int
    reason: Text = ""
    threats: list[ThreatRef] = Field(default_factory=list, max_length=200)


class RequestIn(BaseModel):
    """A detection request of the interview. `text` is the form before PROJ-1 (a single text)."""

    key: Annotated[str, StringConstraints(max_length=40, pattern=r"^[A-Za-z0-9_-]*$")] = ""
    title: Annotated[str, StringConstraints(strip_whitespace=True, max_length=iv.TITLE_MAX)] = ""
    description: Text = ""
    text: Annotated[str, StringConstraints(strip_whitespace=True, max_length=TEXT_MAX)] = ""
    threat: ThreatRef

    @model_validator(mode="after")
    def _title(self):
        if not self.title and self.text:
            self.title, self.description = iv.split_text(self.text)
        if not self.title:
            raise ValueError("A detection request needs a title")
        return self


class RequestStatusIn(BaseModel):
    """Status of one detection request (PROJ-1). The link names what implemented it."""

    status: RequestStatus
    note: Annotated[str, StringConstraints(strip_whitespace=True, max_length=iv.NOTE_MAX)] = ""
    l2_id: int | None = None
    l3_id: int | None = None


class InterviewSave(BaseModel):
    expected_version: int
    interview_date: date
    participants: Text = ""
    notes: Text = ""
    components: list[ComponentIn] = Field(default_factory=list, max_length=100)
    added: list[AddedIn] = Field(default_factory=list, max_length=500)
    removed: list[RemovedIn] = Field(default_factory=list, max_length=500)
    requests: list[RequestIn] = Field(default_factory=list, max_length=500)

    @field_validator("interview_date")
    @classmethod
    def _date(cls, v: date) -> date:
        return _not_future(v)


class VersionIn(BaseModel):
    expected_version: int


class UnconfirmIn(BaseModel):
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class ConfirmIn(BaseModel):
    confirmed_by: Name
    confirmed_at: date

    @field_validator("confirmed_at")
    @classmethod
    def _date(cls, v: date) -> date:
        return _not_future(v)


class InterviewOut(BaseModel):
    id: int
    system_id: int
    system_name: str
    owner_name: str
    archived: bool
    status: InterviewStatus
    interview_date: date
    participants: str
    notes: str
    analyst: str
    version: int
    updated_by: str
    updated_at: datetime | None
    completed_at: datetime | None
    completed_by: str | None
    confirmed_by: str | None
    confirmed_at: date | None
    confirmation_recorded_by: str | None
    previous_id: int | None
    # interview date of the latest completed interview before this one (new date must not be
    # earlier)
    min_date: date | None
    view: dict
    # evidence files (#34)
    attachments: list[evidence.AttachmentOut] = []


class MappingL2(BaseModel):
    l2_id: int
    code: str
    name: str
    l1_applicable: bool


class MappingCategory(BaseModel):
    category: str
    l2s: list[MappingL2]


class MappingOut(BaseModel):
    threshold: int
    log_source_filter: bool
    categories: list[MappingCategory]


class MappingIn(BaseModel):
    l2_ids: list[int] = Field(default_factory=list, max_length=500)


class ThresholdIn(BaseModel):
    proposal_threshold: Annotated[int, Field(ge=1, le=25)]


class LogSourceFilterIn(BaseModel):
    enabled: bool


# ---------------------------------------------------------------- helpers


def _system(db: Session, system_id: int) -> System:
    s = db.get(System, system_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "System not found")
    return s


def _interview(db: Session, interview_id: int) -> Interview:
    i = db.get(Interview, interview_id)
    if i is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Interview not found")
    return i


def _key(i: Interview) -> str:
    return f"{i.system.name} {i.interview_date.isoformat()}"


def _ensure_name_free(db: Session, name: str, own_id: int | None = None) -> None:
    other = db.scalar(select(System).where(System.name_key == name.lower()))
    if other is not None and other.id != own_id:
        raise HTTPException(status.HTTP_409_CONFLICT, f"A system named {other.name} exists already")


def _weights(db: Session, settings) -> dict[str, float | None]:
    res, _l1, l2s, _l3 = compute_scores(db, settings.default_verification_days)
    out = {x.code: (res.l2[x.code].weight if x.code in res.l2 else None) for x in l2s}
    # L3 codes (XX-YYY-NN) never clash with L2 codes (XX-YYY)
    out |= {code: r.weight for code, r in res.rules.items()}
    return out


class _Ctx:
    """Things every system row needs, loaded once per request."""

    def __init__(self, db: Session, settings, system_id: int | None = None):
        self.weights = _weights(db, settings)
        self.links: dict[int, list[SystemLink]] = {}
        q = select(SystemLink).options(
            selectinload(SystemLink.l2)
            .selectinload(L2UseCase.children)
            .selectinload(L3UseCase.references),
            selectinload(SystemLink.l3).selectinload(L3UseCase.references),
        )
        states = select(DetectionRequestState)
        if system_id is not None:  # one system's page
            q = q.where(SystemLink.system_id == system_id)
            states = states.where(DetectionRequestState.system_id == system_id)
        for link in db.scalars(q):
            self.links.setdefault(link.system_id, []).append(link)
        # request status per system and request key (no row: open)
        self.states: dict[int, dict[str, DetectionRequestState]] = {}
        for st in db.scalars(states):
            self.states.setdefault(st.system_id, {})[st.key] = st

    def unresolved(self, system_id: int, requests: list[dict]) -> list[dict]:
        """The requests still to do: open or in progress."""
        known = self.states.get(system_id, {})
        return [
            r
            for r in requests
            if (known[r["key"]].status if r["key"] in known else RequestStatus.open)
            in iv.UNRESOLVED
        ]


def _gaps(system: System, links: list[SystemLink]) -> tuple[list, list, list]:
    """Gaps of a system from its latest completed interview and the current catalogue.

    Log sources are compared by id, so renaming one does not create gaps (issue #39). Only
    active rules count (issue #40). A linked L2 is a log source gap when none of its active rules
    gets any log source it needs ("blind"); rules that get only some are listed as "partial"
    hints but do not count (issue #41)."""
    last = iv.latest_completed(system)
    result = (last.result or {}) if last else {}
    comp_ls = _delivered(result)
    no_rules, ls_gaps = [], []
    for link in sorted(links, key=_link_code):
        l2 = link.l2
        rule = link.l3
        candidates = [rule] if rule is not None else l2.children
        active = [r for r in candidates if iv.is_active(r)]
        if not active:
            uc = rule or l2
            no_rules.append({"code": uc.code, "name": uc.name})
            continue
        comps = sorted({s["component"] for s in link.sources})
        delivered = set().union(*(comp_ls.get(c, set()) for c in comps)) if comps else set()
        state = link_detection(link, delivered)
        rules = []
        for r in active:
            needed = {x.id: x.name for x in r.references if x.kind == RefKind.log_source}
            cov = iv.rule_coverage(set(needed), delivered)
            if cov in ("blind", "partial"):
                rules.append(
                    {
                        "rule_code": r.code,
                        "rule_name": r.name,
                        "missing": sorted(n for i, n in needed.items() if i not in delivered),
                        "partial": cov == "partial",
                    }
                )
        if rules:
            ls_gaps.append(
                {
                    "l2_code": (rule or l2).code,
                    "l2_name": (rule or l2).name,
                    "components": comps,
                    "blind": state == "blind",
                    "rules": rules,
                }
            )
    requests = [
        {
            "key": r["key"],
            "title": r["title"],
            "description": r["description"],
            "component": r["component_name"],
            "category": r["category"],
        }
        for r in iv.upgrade_requests(result.get("requests", []))
    ]
    return no_rules, ls_gaps, requests


def _level(link: SystemLink) -> str:
    return "L3" if link.l3_id else "L2"


def _link_code(link: SystemLink) -> str:
    return link.l3.code if link.l3 is not None else link.l2.code


def link_detection(link: SystemLink, delivered: set[int]) -> str:
    if link.l3 is not None:
        return iv.rule_detection(link.l3, delivered)
    return iv.detection_state(link.l2, delivered)


def _delivered(result: dict) -> dict[str, set[int]]:
    """Component name -> log source ids of a completed interview."""
    return {
        c["name"]: {s["id"] for s in c.get("log_sources", []) if s.get("id") is not None}
        for c in result.get("components", [])
    }


def _link_views(system: System, links: list[SystemLink], ctx: _Ctx) -> list[dict]:
    last = iv.latest_completed(system)
    comp_ls = _delivered((last.result or {}) if last else {})
    out = []
    for x in sorted(links, key=lambda x: (-x.risk_score, _link_code(x))):
        uc = x.l3 if x.l3 is not None else x.l2
        comps = {s["component"] for s in x.sources}
        delivered = set().union(*(comp_ls.get(c, set()) for c in comps)) if comps else set()
        out.append(
            {
                "level": _level(x),
                "l2_id": x.l2_id,
                "l3_id": x.l3_id,
                "code": uc.code,
                "name": uc.name,
                "l2_code": x.l2.code,
                "detection": link_detection(x, delivered),
                "weight": ctx.weights.get(uc.code),
                "risk_score": x.risk_score,
                "risk_level": iv.risk_level(x.risk_score),
                "sources": x.sources,
            }
        )
    return out


def _risks(system: System, link_views: list[dict]) -> tuple[list[dict], int | None]:
    """Risk overview of the latest completed interview, with the links' current state."""
    last = iv.latest_completed(system)
    if last is None:
        return [], None
    result = last.result or {}
    key_of = {c["name"]: c["key"] for c in result.get("components", [])}
    proposals = [
        v
        | {
            "sources": [
                {"component": key_of[s["component"]], "category": s["category"]}
                for s in v["sources"]
                if s["component"] in key_of
            ]
        }
        for v in link_views
    ]
    requests = [
        {
            "key": r["key"],
            "title": r["title"],
            "component": r["component"],
            "category": r["category"],
        }
        for r in iv.upgrade_requests(result.get("requests", []))
    ]
    threshold = int(result.get("threshold") or iv.DEFAULT_THRESHOLD)
    view = {
        "threshold": threshold,
        "components": result.get("components", []),
        "proposals": proposals,
        "requests": requests,
    }
    return iv.risk_overview(view), threshold


def _uncovered(risks: list[dict]) -> list[dict]:
    """Risks with coverage "gap" that no use case addresses (issue #59). Gaps of risks that
    have use cases are already listed by use case (no rules / blind)."""
    return [
        {
            "component": r["component"],
            "component_name": r["component_name"],
            "category": r["category"],
            "score": r["score"],
            "level": r["level"],
        }
        for r in risks
        if r["coverage"] == "gap" and not r["use_cases"]
    ]


def gap_count(no_rules: list, ls_gaps: list, requests: list, uncovered: list) -> int:
    """The number of gaps of a system (list column, detail stat and Gaps section agree)."""
    return len(no_rules) + sum(1 for g in ls_gaps if g["blind"]) + len(requests) + len(uncovered)


def _row(system: System, ctx: _Ctx) -> dict:
    links = ctx.links.get(system.id, [])
    last = iv.latest_completed(system)
    last_date = last.interview_date if last else None
    no_rules, ls_gaps, requests = _gaps(system, links)
    risks, _ = _risks(system, _link_views(system, links, ctx)) if last else ([], None)
    weights = [ctx.weights.get(_link_code(x)) or 0.0 for x in links]
    draft = iv.draft_of(system)
    return {
        "id": system.id,
        "name": system.name,
        "description": system.description,
        "owner_name": system.owner_name,
        "owner_department": system.owner_department,
        "owner_email": system.owner_email,
        "criticality": system.criticality,
        "internet_facing": system.internet_facing,
        "data_classification": system.data_classification,
        "review_interval_months": system.review_interval_months,
        "archived": system.archived,
        "updated_at": system.updated_at,
        "linked": len(links),
        "coverage": round(sum(weights) / len(weights), 4) if weights else None,
        # only the requests still to do count; implemented or declined ones are not gaps
        "gaps": gap_count(
            no_rules, ls_gaps, ctx.unresolved(system.id, requests), _uncovered(risks)
        ),
        "last_interview": last_date,
        "next_due": iv.add_months(last_date, system.review_interval_months) if last_date else None,
        "state": iv.interview_state(system, last_date),
        "draft_id": draft.id if draft else None,
        "can_delete": last is None,
    }


def _system_query():
    return select(System).order_by(System.name)


def _systems(db: Session, q, results: bool = True) -> list[System]:
    """Systems with their interviews, without the JSON of every interview: only the latest
    completed one (the one lists and requests read) is loaded in full, when `results`."""
    systems = list(db.scalars(q.options(iv.light_interviews())))
    if results:
        iv.load_full(db, [x for s in systems if (x := iv.latest_completed(s))])
    return systems


def _apply_system(system: System, body: SystemIn) -> dict:
    data = body.model_dump()
    data["owner_email"] = str(body.owner_email) if body.owner_email else None
    before = {k: getattr(system, k, None) for k in data}
    for k, v in data.items():
        setattr(system, k, v)
    system.name_key = body.name.lower()
    return audit.diff(before, data)


def _interview_out(db: Session, i: Interview) -> InterviewOut:
    if i.status == InterviewStatus.draft:
        view = iv.evaluate(db, i.data or {}, iv.threshold(db))
    else:
        view = iv.mark_deleted(db, dict(i.result or {}))
    iv.attach_status(db, i.system_id, view)
    earlier = [x for x in iv.completed(i.system) if x.id != i.id]
    if i.status != InterviewStatus.draft:
        earlier = [x for x in earlier if (x.interview_date, x.id) < (i.interview_date, i.id)]
    return InterviewOut(
        id=i.id,
        system_id=i.system_id,
        system_name=i.system.name,
        owner_name=i.system.owner_name,
        archived=i.system.archived,
        status=i.status,
        interview_date=i.interview_date,
        participants=i.participants,
        notes=i.notes,
        analyst=i.analyst,
        version=i.version,
        updated_by=i.updated_by,
        updated_at=i.updated_at,
        completed_at=i.completed_at,
        completed_by=i.completed_by,
        confirmed_by=i.confirmed_by,
        confirmed_at=i.confirmed_at,
        confirmation_recorded_by=i.confirmation_recorded_by,
        previous_id=i.previous_id,
        min_date=max((x.interview_date for x in earlier), default=None),
        view=view,
        attachments=[evidence.out(a) for a in i.attachments],
    )


def _check_version(i: Interview, expected: int) -> None:
    if expected != i.version:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"This draft was changed by {i.updated_by}; reload to see the changes",
        )


def _draft(db: Session, interview_id: int) -> Interview:
    i = _interview(db, interview_id)
    if i.status != InterviewStatus.draft:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A completed interview cannot be changed; start a new one"
        )
    return i


def _min_date_check(i: Interview, d: date) -> None:
    last = iv.latest_completed(i.system)
    if last is not None and d < last.interview_date:
        raise HTTPException(
            422,
            "The interview date must be on or after the previous interview "
            f"({last.interview_date.isoformat()})",
        )


def _validate_draft(db: Session, body: InterviewSave) -> dict:
    """Checks that hold for every save (completeness of threats is checked on completion)."""
    names: set[str] = set()
    keys: set[str] = set()
    applies: set[tuple[str, str]] = set()
    for c in body.components:
        if c.name.lower() in names:
            raise HTTPException(422, f"There is already a component named {c.name}")
        if c.key in keys:
            raise HTTPException(422, f"Component key {c.key} is used twice")
        names.add(c.name.lower())
        keys.add(c.key)
        cats = [t.category for t in c.threats]
        if len(cats) != len(set(cats)):
            raise HTTPException(422, f"{c.name}: a STRIDE category is listed twice")
        applies |= {(c.key, t.category) for t in c.threats if t.state == "applies"}
        custom_keys = [x.key for x in c.custom_threats]
        if len(custom_keys) != len(set(custom_keys)):
            raise HTTPException(422, f"{c.name}: a custom threat is listed twice")
        for x in c.custom_threats:
            unknown = [tid for tid in x.techniques if attack.status(tid)[0] == "unknown"]
            if unknown:
                raise HTTPException(
                    422,
                    f"{c.name} / {x.title or x.key}: unknown ATT&CK technique {', '.join(unknown)}",
                )
            x.techniques = list(dict.fromkeys(x.techniques))
        applies |= {(c.key, iv.CUSTOM + k) for k in custom_keys}
    ls_ids = {i for c in body.components for i in c.log_source_ids}
    if ls_ids:
        found = set(
            db.scalars(
                select(ReferenceItem.id).where(
                    ReferenceItem.id.in_(ls_ids), ReferenceItem.kind == RefKind.log_source
                )
            )
        )
        if ls_ids - found:
            raise HTTPException(422, "Unknown log source; reload the page")
    l2_ids = {a.l2_id for a in body.added if a.l2_id is not None} | {r.l2_id for r in body.removed}
    l2_code: dict[int, str] = {}
    if l2_ids:
        l2_code = dict(
            db.execute(select(L2UseCase.id, L2UseCase.code).where(L2UseCase.id.in_(l2_ids))).all()
        )
        if l2_ids - set(l2_code):
            raise HTTPException(422, "Unknown L2 use case; reload the page")
    l3_ids = {a.l3_id for a in body.added if a.l3_id is not None}
    l3_code: dict[int, str] = {}
    if l3_ids:
        l3_code = dict(
            db.execute(select(L3UseCase.id, L3UseCase.code).where(L3UseCase.id.in_(l3_ids))).all()
        )
        if l3_ids - set(l3_code):
            raise HTTPException(422, "Unknown L3 rule; reload the page")
    seen: set[tuple[str, int]] = set()
    for a in body.added:
        ident = ("L3", a.l3_id) if a.l3_id is not None else ("L2", a.l2_id)
        code = l3_code[a.l3_id] if a.l3_id is not None else l2_code[a.l2_id]
        if ident in seen:
            raise HTTPException(422, f"{code} is added twice")
        seen.add(ident)
        if not a.threats:
            raise HTTPException(422, f"{code}: choose at least one threat of the interview")
        for r in a.threats:
            if (r.component, r.category) not in applies:
                raise HTTPException(422, f"{code} is tied to a threat that does not apply")
    request_keys: set[str] = set()
    for r in body.requests:
        if (r.threat.component, r.threat.category) not in applies:
            raise HTTPException(
                422, f"{r.title}: the detection request is tied to a threat that does not apply"
            )
        if r.key in request_keys:
            raise HTTPException(422, f"Detection request key {r.key} is used twice")
        if r.key:
            request_keys.add(r.key)
    data = body.model_dump(include={"components", "added", "removed", "requests"}, mode="json")
    # a request without a key (an older client) gets one; `text` was turned into the title
    data["requests"] = iv.upgrade_requests(
        [{k: v for k, v in r.items() if k != "text"} for r in data["requests"]]
    )
    # an added entry carries either l2_id or l3_id
    data["added"] = [{k: v for k, v in a.items() if v is not None} for a in data["added"]]
    # one removal per use case; a removal from single threats keeps only threats that apply
    # (#57) and is dropped when none is left (it must not turn into a whole removal)
    removed = []
    for r in {r["l2_id"]: r for r in data["removed"]}.values():
        if r["threats"]:
            r["threats"] = [x for x in r["threats"] if (x["component"], x["category"]) in applies]
            if not r["threats"]:
                continue
        else:
            r.pop("threats")
        removed.append(r)
    data["removed"] = removed
    return data


# ---------------------------------------------------------------- systems


@router.get("/systems", response_model=list[SystemRow])
def list_systems(
    _: Reader,
    db: DB,
    settings: SettingsDep,
    archived: bool = Query(False, description="Also list archived systems"),
    due: bool = Query(False, description="Only systems without interview or with one due"),
) -> list[dict]:
    ctx = _Ctx(db, settings)
    rows = [_row(s, ctx) for s in _systems(db, _system_query())]
    if not archived:
        rows = [r for r in rows if not r["archived"]]
    if due:
        rows = [r for r in rows if r["state"] != "ok" and not r["archived"]]
    return rows


class SystemName(BaseModel):
    id: int
    name: str
    archived: bool


@router.get("/systems/names", response_model=list[SystemName])
def system_names(_: Reader, db: DB) -> list[SystemName]:
    """Id and name of every system, also archived ones (filters and pickers)."""
    q = select(System.id, System.name, System.archived).order_by(System.name)
    return [SystemName(id=i, name=n, archived=a) for i, n, a in db.execute(q)]


@router.get("/systems/due-count")
def due_count(_: Reader, db: DB) -> dict[str, int]:
    """Non-archived systems without completed interview or whose review interval has passed."""
    n = 0
    for s in _systems(db, _system_query().where(System.archived.is_(False)), results=False):
        last = iv.latest_completed(s)
        if iv.interview_state(s, last.interview_date if last else None) != "ok":
            n += 1
    return {"due": n}


@router.post("/systems", response_model=SystemDetail, status_code=201)
def create_system(body: SystemIn, user: Editor, db: DB, settings: SettingsDep) -> dict:
    _ensure_name_free(db, body.name)
    s = System(name=body.name, name_key=body.name.lower(), owner_name=body.owner_name)
    _apply_system(s, body)
    db.add(s)
    audit.record(db, user, "create", "system", s.name, body.model_dump(mode="json"))
    db.commit()
    return _detail(db, s, settings)


def _detail(db: Session, s: System, settings) -> dict:
    db.refresh(s)
    ctx = _Ctx(db, settings, s.id)
    row = _row(s, ctx)
    links = ctx.links.get(s.id, [])
    no_rules, ls_gaps, requests = _gaps(s, links)
    link_views = _link_views(s, links, ctx)
    risks, threshold = _risks(s, link_views)
    # the requests of the risk rows carry their status (the chip next to them)
    known = ctx.states.get(s.id, {})
    for risk in risks:
        risk["requests"] = [
            r | {"status": known[r["key"]].status.value if r["key"] in known else "open"}
            for r in risk["requests"]
        ]
    last = iv.latest_completed(s)
    comps = ((last.result or {}) if last else {}).get("components", [])
    link_ok = iv.existing_links(db, known.values())
    return row | {
        "links": link_views,
        "risks": risks,
        "threshold": threshold,
        "components": [
            {
                "key": c["key"],
                "name": c["name"],
                # custom ATT&CK threats (#60): labels for the risk overview
                "custom_threats": [
                    {"category": t["category"], "title": t.get("title") or t["category"]}
                    | {"techniques": t.get("techniques", [])}
                    for t in c.get("threats", [])
                    if t.get("custom")
                ],
            }
            for c in comps
        ],
        "gap_no_rules": no_rules,
        "gap_log_sources": ls_gaps,
        "gap_requests": [
            r | iv.state_view(db, ctx.states.get(s.id, {}).get(r["key"]), link_ok) for r in requests
        ],
        "gap_risks": _uncovered(risks),
        "interviews": [
            InterviewRow.model_validate(i, from_attributes=True)
            for i in sorted(s.interviews, key=lambda i: (i.interview_date, i.id), reverse=True)
        ],
    }


@router.get("/systems/{system_id}", response_model=SystemDetail)
def get_system(system_id: int, _: Reader, db: DB, settings: SettingsDep) -> dict:
    return _detail(db, _system(db, system_id), settings)


@router.patch("/systems/{system_id}", response_model=SystemDetail)
def update_system(
    system_id: int, body: SystemIn, user: Editor, db: DB, settings: SettingsDep
) -> dict:
    s = _system(db, system_id)
    _ensure_name_free(db, body.name, s.id)
    old_name = s.name
    changes = _apply_system(s, body)
    action = "update"
    if set(changes) == {"archived"}:
        action = "archive" if body.archived else "unarchive"
    audit.record(db, user, action, "system", old_name, changes)
    db.commit()
    return _detail(db, s, settings)


@router.delete("/systems/{system_id}", status_code=204)
def delete_system(system_id: int, user: Editor, db: DB) -> None:
    s = _system(db, system_id)
    if iv.latest_completed(s) is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "A system with a completed interview cannot be deleted; archive it instead",
        )
    audit.record(db, user, "delete", "system", s.name)
    db.delete(s)
    db.commit()


# ---------------------------------------------------------------- interviews


@router.post("/systems/{system_id}/interviews", response_model=InterviewOut, status_code=201)
def start_interview(system_id: int, user: Editor, db: DB) -> InterviewOut:
    s = _system(db, system_id)
    if iv.draft_of(s) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "This system already has a draft interview")
    prev = iv.latest_completed(s)
    data: dict = {"components": [], "added": [], "removed": [], "requests": []}
    if prev is not None:
        ls = set(
            db.scalars(select(ReferenceItem.id).where(ReferenceItem.kind == RefKind.log_source))
        )
        data = iv.copy_for_reinterview(prev, ls)
    today = _today()
    i = Interview(
        system=s,
        status=InterviewStatus.draft,
        interview_date=max(today, prev.interview_date) if prev else today,
        participants=s.owner_name,
        notes="",
        data=data,
        previous_id=prev.id if prev else None,
        analyst=user.username,
        updated_by=user.username,
        version=1,
    )
    db.add(i)
    changes = {"copied_from": prev.interview_date.isoformat()} if prev else None
    audit.record(db, user, "create", "interview", f"{s.name} {i.interview_date}", changes)
    try:
        db.commit()
    except IntegrityError as e:  # a second click at the same moment (#45)
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This system already has a draft interview"
        ) from e
    return _interview_out(db, i)


@router.get("/interviews/{interview_id}", response_model=InterviewOut)
def get_interview(interview_id: int, _: Reader, db: DB) -> InterviewOut:
    return _interview_out(db, _interview(db, interview_id))


@router.put("/interviews/{interview_id}", response_model=InterviewOut)
def save_interview(interview_id: int, body: InterviewSave, user: Editor, db: DB) -> InterviewOut:
    i = _draft(db, interview_id)
    _check_version(i, body.expected_version)
    _min_date_check(i, body.interview_date)
    data = _validate_draft(db, body)
    changes = audit.diff(
        {"interview_date": i.interview_date, "participants": i.participants, "notes": i.notes},
        {
            "interview_date": body.interview_date,
            "participants": body.participants,
            "notes": body.notes,
        },
    )
    if data != (i.data or {}):
        changes["content"] = {
            "components": len(data["components"]),
            "added": len(data["added"]),
            "removed": len(data["removed"]),
            "requests": len(data["requests"]),
        }
    i.interview_date = body.interview_date
    i.participants = body.participants
    i.notes = body.notes
    i.data = data
    i.version += 1
    i.updated_by = user.username
    if changes:
        audit.record(db, user, "update", "interview", _key(i), changes)
    db.commit()
    return _interview_out(db, i)


@router.delete("/interviews/{interview_id}", status_code=204)
def delete_interview(interview_id: int, user: Editor, db: DB) -> None:
    i = _interview(db, interview_id)
    if i.status != InterviewStatus.draft:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only a draft interview can be deleted")
    audit.record(db, user, "delete", "interview", _key(i))
    db.delete(i)
    db.commit()


@router.post("/interviews/{interview_id}/complete", response_model=InterviewOut)
def complete_interview(interview_id: int, body: VersionIn, user: Editor, db: DB) -> InterviewOut:
    i = _draft(db, interview_id)
    _check_version(i, body.expected_version)
    _min_date_check(i, i.interview_date)
    if i.interview_date > _today() + timedelta(days=1):
        raise HTTPException(422, "The interview date cannot be in the future")
    data = i.data or {}
    if not data.get("components"):
        raise HTTPException(422, "Add at least one component before completing the interview")
    result = iv.evaluate(db, data, iv.threshold(db))
    if result["incomplete"]:
        names = ", ".join(
            f"{x['component']} / {x.get('title') or x['category']}" for x in result["incomplete"]
        )
        raise HTTPException(
            422, f"Complete description, likelihood and impact of these threats: {names}"
        )
    i.result = result
    i.status = InterviewStatus.completed
    i.completed_at = datetime.now(UTC)
    i.completed_by = user.username
    i.version += 1
    i.updated_by = user.username
    iv.replace_links(db, i.system, i, result)
    audit.record(
        db,
        user,
        "complete",
        "interview",
        _key(i),
        {"system": i.system.name, "linked": [p["code"] for p in result["proposals"]]},
    )
    db.commit()
    return _interview_out(db, i)


@router.put("/interviews/{interview_id}/confirmation", response_model=InterviewOut)
def confirm_interview(interview_id: int, body: ConfirmIn, user: Editor, db: DB) -> InterviewOut:
    i = _interview(db, interview_id)
    if i.status == InterviewStatus.draft:
        raise HTTPException(status.HTTP_409_CONFLICT, "Complete the interview before confirming")
    if i.status == InterviewStatus.confirmed:
        # an existing confirmation is never replaced silently (#42)
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Already confirmed by {i.confirmed_by}; remove that confirmation first",
        )
    if body.confirmed_at < i.interview_date:
        raise HTTPException(422, "The confirmation date cannot be before the interview date")
    i.confirmed_by = body.confirmed_by
    i.confirmed_at = body.confirmed_at
    i.confirmation_recorded_by = user.username
    i.status = InterviewStatus.confirmed
    changes = {"confirmed_by": body.confirmed_by, "confirmed_at": body.confirmed_at}
    signoff = next((a for a in i.attachments if a.signoff), None)
    if signoff is not None:
        changes["signoff"] = signoff.filename
    audit.record(db, user, "confirm", "interview", _key(i), changes)
    db.commit()
    return _interview_out(db, i)


@router.delete("/interviews/{interview_id}/confirmation", response_model=InterviewOut)
def unconfirm_interview(interview_id: int, body: UnconfirmIn, user: Editor, db: DB) -> InterviewOut:
    i = _interview(db, interview_id)
    if i.status != InterviewStatus.confirmed:
        raise HTTPException(status.HTTP_409_CONFLICT, "The interview is not confirmed")
    changes = {
        "confirmed_by": i.confirmed_by,
        "confirmed_at": i.confirmed_at,
        "recorded_by": i.confirmation_recorded_by,
        "reason": body.reason,
    }
    audit.record(db, user, "unconfirm", "interview", _key(i), changes)
    i.status = InterviewStatus.completed
    i.confirmed_by = i.confirmed_at = i.confirmation_recorded_by = None
    db.commit()
    return _interview_out(db, i)


@router.get("/interviews/{interview_id}/compare")
def compare_interview(interview_id: int, _: Reader, db: DB) -> dict:
    """Changes against the completed interview this one started from."""
    i = _interview(db, interview_id)
    prev = db.get(Interview, i.previous_id) if i.previous_id else None
    if prev is None or prev.status == InterviewStatus.draft:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This interview has no predecessor")
    new = (
        i.result
        if i.status != InterviewStatus.draft
        else iv.evaluate(db, i.data or {}, iv.threshold(db))
    )
    return {
        "previous_id": prev.id,
        "previous_date": prev.interview_date,
        **iv.compare(prev.result or {}, new or {}),
    }


@router.get("/interviews/{interview_id}/pdf")
def interview_pdf(
    interview_id: int,
    user: Reader,
    db: DB,
    settings: SettingsDep,
    lang: Literal["en", "de", "nl"] | None = None,
) -> Response:
    from app import interview_report

    out = _interview_out(db, _interview(db, interview_id))
    system = _system(db, out.system_id)
    data = interview_report.build(out, system, lang or _lang(user), settings.app_name)
    audit.record_access(db, user, "export", "interview", _key(_interview(db, interview_id)), {})
    safe = "".join(ch if ch.isalnum() else "-" for ch in out.system_name).strip("-")[:60]
    name = f"interview-{safe or 'system'}-{out.interview_date.isoformat()}.pdf"
    return Response(
        data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


def _lang(user: User) -> str:
    return user.locale if user.locale in ("en", "de", "nl") else "en"


# ---------------------------------------------------------------- detection requests


def _request_titles(system: System) -> dict[str, str]:
    """Key -> title of every detection request in any interview of the system."""
    titles: dict[str, str] = {}
    for i in sorted(system.interviews, key=lambda i: (i.interview_date, i.id)):
        raw = (
            (i.data or {}).get("requests", [])
            if i.status == InterviewStatus.draft
            else (i.result or {}).get("requests", [])
        )
        for r in iv.upgrade_requests(raw):
            titles[r["key"]] = r["title"]
    return titles


@router.put(
    "/systems/{system_id}/detection-requests/{key}/status",
    summary="Set the implementation status of a detection request",
)
def set_request_status(
    system_id: int, key: str, body: RequestStatusIn, user: Editor, db: DB
) -> dict:
    """Works on draft and completed interviews alike; the last write wins (PROJ-1)."""
    system = _system(db, system_id)
    titles = _request_titles(system)
    if key not in titles:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Detection request not found")
    if body.status in iv.NOTE_REQUIRED and not body.note:
        raise HTTPException(422, "Give a reason for a rejected or not feasible request")
    l2_id = l3_id = None
    code = None
    # what implemented the request counts for "implemented" only
    if body.status == RequestStatus.implemented and (body.l3_id or body.l2_id):
        if body.l3_id is not None:
            rule = db.get(L3UseCase, body.l3_id)
            if rule is None:
                raise HTTPException(422, "Unknown L3 rule; reload the page")
            l2_id, l3_id, code = rule.l2_id, rule.id, rule.code
        else:
            l2 = db.get(L2UseCase, body.l2_id)
            if l2 is None:
                raise HTTPException(422, "Unknown L2 use case; reload the page")
            l2_id, code = l2.id, l2.code

    def write() -> DetectionRequestState:
        st = db.scalar(
            select(DetectionRequestState).where(
                DetectionRequestState.system_id == system.id, DetectionRequestState.key == key
            )
        )
        if st is None:
            st = DetectionRequestState(system_id=system.id, key=key)
            db.add(st)
        st.status = body.status
        st.note = body.note
        st.link_l2_id, st.link_l3_id, st.link_code = l2_id, l3_id, code
        st.updated_by = user.username
        st.updated_at = datetime.now(UTC)
        return st

    def record() -> None:
        audit.record(
            db,
            user,
            "update",
            "detection_request",
            f"{system.name} / {titles[key]}",
            {"status": body.status.value, "note": body.note, "link": code},
        )

    st = write()
    record()
    try:
        db.commit()
    except IntegrityError:  # two first writes at the same moment: the second one updates
        db.rollback()
        st = write()
        record()
        db.commit()
    return {"key": key} | iv.state_view(db, st)


@router.get("/detection-requests", summary="Detection requests of all systems (PROJ-2)")
def list_detection_requests(_: Reader, db: DB) -> dict:
    """The requests of the latest completed interview of every system with one, with their
    status and the risk score of their threat. Drafts and older interviews do not count, so
    the numbers agree with the system page. The page filters and sorts."""
    states = {}
    all_states = list(db.scalars(select(DetectionRequestState)))
    for st in all_states:
        states.setdefault(st.system_id, {})[st.key] = st
    known = iv.existing_links(db, all_states)
    rows = []
    for system in _systems(db, _system_query()):
        last = iv.latest_completed(system)
        if last is None:
            continue
        result = last.result or {}
        score = {
            (c["key"], t["category"]): t.get("score")
            for c in result.get("components", [])
            for t in c.get("threats", [])
        }
        for r in iv.upgrade_requests(result.get("requests", [])):
            rows.append(
                {
                    "key": r["key"],
                    "title": r["title"],
                    "description": r["description"],
                    "system_id": system.id,
                    "system_name": system.name,
                    "archived": system.archived,
                    "component": r["component_name"],
                    "category": r["category"],
                    "risk_score": score.get((r["component"], r["category"])),
                }
                | iv.state_view(db, states.get(system.id, {}).get(r["key"]), known)
            )
    return {"requests": rows}


# ---------------------------------------------------------------- STRIDE mapping


def _mapping_out(db: Session) -> MappingOut:
    rows = db.scalars(
        select(StrideMapping).options(selectinload(StrideMapping.l2).selectinload(L2UseCase.parent))
    )
    by_cat: dict[str, list[MappingL2]] = {c: [] for c in iv.STRIDE}
    for m in rows:
        if m.category in by_cat:
            by_cat[m.category].append(
                MappingL2(
                    l2_id=m.l2_id,
                    code=m.l2.code,
                    name=m.l2.name,
                    l1_applicable=m.l2.parent.applicable,
                )
            )
    return MappingOut(
        threshold=iv.threshold(db),
        log_source_filter=iv.log_source_filter(db),
        categories=[
            MappingCategory(category=c, l2s=sorted(by_cat[c], key=lambda x: x.code))
            for c in iv.STRIDE
        ],
    )


@router.get("/stride-mapping", response_model=MappingOut)
def get_mapping(_: Reader, db: DB) -> MappingOut:
    return _mapping_out(db)


@router.put("/stride-mapping/threshold", response_model=MappingOut)
def set_threshold(body: ThresholdIn, user: Admin, db: DB) -> MappingOut:
    s = iv.load_settings(db)
    old = s["proposal_threshold"]
    s["proposal_threshold"] = body.proposal_threshold
    iv.save_settings(db, s, user.username)
    changes = {"proposal_threshold": [old, body.proposal_threshold]}
    audit.record(db, user, "update", "stride_mapping", "proposal_threshold", changes)
    db.commit()
    return _mapping_out(db)


@router.put("/stride-mapping/log-source-filter", response_model=MappingOut)
def set_log_source_filter(body: LogSourceFilterIn, user: Admin, db: DB) -> MappingOut:
    """Issue #36: only propose L2s whose rules use a log source of the threatened component."""
    s = iv.load_settings(db)
    old = s["log_source_filter"]
    s["log_source_filter"] = body.enabled
    iv.save_settings(db, s, user.username)
    if old != body.enabled:
        changes = {"log_source_filter": [old, body.enabled]}
        audit.record(db, user, "update", "stride_mapping", "log_source_filter", changes)
    db.commit()
    return _mapping_out(db)


@router.post("/stride-mapping/reset", response_model=MappingOut)
def reset_mapping(user: Admin, db: DB) -> MappingOut:
    n = iv.apply_default_mapping(db)
    audit.record(db, user, "reset", "stride_mapping", "default", {"entries": n})
    db.commit()
    return _mapping_out(db)


@router.put("/stride-mapping/{category}", response_model=MappingOut)
def set_mapping(category: Stride, body: MappingIn, user: Admin, db: DB) -> MappingOut:
    ids = list(dict.fromkeys(body.l2_ids))
    found = dict(
        db.execute(select(L2UseCase.id, L2UseCase.code).where(L2UseCase.id.in_(ids))).all()
    )
    if set(ids) - set(found):
        raise HTTPException(422, "Unknown L2 use case; reload the page")
    current = {
        m.l2_id: m
        for m in db.scalars(
            select(StrideMapping)
            .options(selectinload(StrideMapping.l2))
            .where(StrideMapping.category == category)
        )
    }
    before = sorted(m.l2.code for m in current.values())
    for l2_id, m in current.items():
        if l2_id not in found:
            db.delete(m)
    for l2_id in ids:
        if l2_id not in current:
            db.add(StrideMapping(category=category, l2_id=l2_id))
    after = sorted(found.values())
    if before != after:
        audit.record(db, user, "update", "stride_mapping", category, {"l2": [before, after]})
    db.commit()
    return _mapping_out(db)
