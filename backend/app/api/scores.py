"""Scores, KPIs and verification (docs/PLAN.md sections 2.5 and 6a)."""

from datetime import date, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, configs
from app.api.deps import DB, SettingsDep
from app.models import L2UseCase, L3UseCase, Verification, VerificationResult
from app.schemas import NOTE_MAX, not_in_future
from app.score_queries import compute_scores, open_issues
from app.scoring import SCORED_STATES
from app.security import Editor, Reader

router = APIRouter(tags=["scores & verification"])


class MetricSet(BaseModel):
    effectiveness: float | None
    implementation: float | None
    coverage: float | None
    weight: float | None
    potential: float | None


class GroupOut(MetricSet):
    code: str
    name: str
    rules: int
    scored_rules: int


class L1ScoreOut(GroupOut):
    applicable: bool
    l2_count: int
    scored_l2: int


class L2ScoreOut(GroupOut):
    l1_code: str


class KpiOut(BaseModel):
    soc_detection_score: float | None
    catalogue_coverage: float | None
    growth_potential: float | None
    detection_gap: float | None
    framework_completeness: float | None
    l2_with_scored_rules: int
    applicable_l2: int
    assessment_coverage: float | None
    assessed_rules: int
    active_rules: int
    verification_health: float | None
    verified_in_time: int
    verification_overdue: int
    operational_rules: int
    default_verification_days: int


class ScoresOut(BaseModel):
    overall: MetricSet
    kpis: KpiOut
    l1: list[L1ScoreOut]
    l2: list[L2ScoreOut]


class DueOut(BaseModel):
    code: str
    name: str
    l2_code: str
    lifecycle_status: str
    last_verified_at: date | None
    last_verified_by: str | None
    due: date | None
    overdue: bool
    days_left: int | None
    # date of the latest check when it found issues (the rule stays due until a check is OK)
    issues_at: date | None = None


class VerifyIn(BaseModel):
    result: VerificationResult = VerificationResult.ok
    note: Annotated[str, Field(max_length=NOTE_MAX)] = ""
    verified_at: date | None = None


class VerificationOut(BaseModel):
    id: int
    verified_at: date
    username: str
    result: VerificationResult
    note: str
    config_tag: str | None = None
    test_id: int | None = None


@router.get("/scores", response_model=ScoresOut)
def scores(_: Reader, db: DB, settings: SettingsDep) -> ScoresOut:
    res, l1s, l2s, _l3s = compute_scores(db, settings.default_verification_days)
    l1_code = {x.id: x.code for x in l1s}
    return ScoresOut(
        overall=MetricSet(**res.overall.as_dict()),
        kpis=KpiOut(**vars(res.kpis), default_verification_days=settings.default_verification_days),
        l1=[
            L1ScoreOut(
                code=x.code,
                name=x.name,
                applicable=x.applicable,
                rules=res.l1[x.code].rules,
                scored_rules=res.l1[x.code].scored_rules,
                l2_count=res.l1[x.code].children,
                scored_l2=res.l1[x.code].scored_children,
                **res.l1[x.code].as_dict(),
            )
            for x in l1s
        ],
        l2=[
            L2ScoreOut(
                code=x.code,
                name=x.name,
                l1_code=l1_code[x.l1_id],
                rules=res.l2[x.code].rules,
                scored_rules=res.l2[x.code].scored_rules,
                **res.l2[x.code].as_dict(),
            )
            for x in l2s
        ],
    )


@router.get("/verification/due", response_model=list[DueOut])
def verification_due(
    _: Reader,
    db: DB,
    settings: SettingsDep,
    within_days: int = Query(30, ge=0, le=3650),
) -> list[DueOut]:
    """Operational rules that are overdue, never verified, or due within `within_days`."""
    res, _l1, _l2, l3s = compute_scores(db, settings.default_verification_days)
    today = date.today()
    horizon = today + timedelta(days=within_days)
    out = []
    issues = open_issues(db)
    for x in l3s:
        if x.lifecycle_status not in SCORED_STATES:
            continue
        s = res.rules[x.code]
        if s.verification_due is None or s.verification_due <= horizon or x.id in issues:
            out.append(
                DueOut(
                    code=x.code,
                    name=x.name,
                    l2_code=x.code[:6],
                    lifecycle_status=x.lifecycle_status.value,
                    last_verified_at=x.last_verified_at,
                    last_verified_by=x.last_verified_by,
                    due=s.verification_due,
                    overdue=s.verification_overdue,
                    days_left=(s.verification_due - today).days if s.verification_due else None,
                    issues_at=issues.get(x.id),
                )
            )
    out.sort(key=lambda d: (d.due is not None, d.due or today, d.code))
    return out


def _target(db: Session, level: str, code: str):
    model = {"l2": L2UseCase, "l3": L3UseCase}[level]
    obj = db.scalar(select(model).where(model.code == code))
    if obj is None:
        raise HTTPException(404, f"{level.upper()} use case not found")
    return obj


def _history(db: Session, level: str, obj) -> list[Verification]:
    col = Verification.l2_id if level == "l2" else Verification.l3_id
    q = select(Verification).where(col == obj.id)
    return list(db.scalars(q.order_by(Verification.verified_at.desc(), Verification.id.desc())))


def record_verification(db: Session, level: str, obj, body: VerifyIn, user) -> Verification:
    """Add one verification to a use case or rule (no commit); also used by the bulk edit."""
    when = body.verified_at or date.today()
    try:
        not_in_future(when)
    except ValueError:
        raise HTTPException(422, "Verification date cannot be in the future") from None
    v = Verification(verified_at=when, username=user.username, result=body.result, note=body.note)
    setattr(v, f"{level}_id", obj.id)
    db.add(v)
    # Only a check without issues counts as verified: a failed check must not clear the
    # overdue flag, raise verification health or tag the config as verified.
    tag = None
    if body.result == VerificationResult.ok:
        if obj.last_verified_at is None or when >= obj.last_verified_at:
            obj.last_verified_at = when
            obj.last_verified_by = user.username
        # Tag the configuration version that was verified (PLAN 4a); only rules have one
        if level == "l3":
            tag = configs.tag_verified(db, obj, when, user.username)
    audit.record(
        db,
        user,
        "verify",
        level,
        obj.code,
        {"result": body.result.value, "verified_at": when, "note": body.note}
        | ({"config_tag": tag} if tag else {}),
    )
    v.config_tag = tag
    return v


for _level in ("l2", "l3"):

    def _make(level: str) -> None:
        @router.post(f"/{level}/{{code}}/verify", response_model=VerificationOut, status_code=201)
        def verify(code: str, body: VerifyIn, user: Editor, db: DB) -> Verification:
            v = record_verification(db, level, _target(db, level, code), body, user)
            db.commit()
            return v

        @router.get(f"/{level}/{{code}}/verifications", response_model=list[VerificationOut])
        def history(code: str, _: Reader, db: DB) -> list[Verification]:
            return _history(db, level, _target(db, level, code))

    _make(_level)
