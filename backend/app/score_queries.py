"""Scores and open verification issues read from the database (the pure engine is app/scoring.py).

Shared by the API, snapshots, driver coverage and the threat-modelling pages.
"""

from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import L1UseCase, L2UseCase, L3UseCase, Verification, VerificationResult
from app.scoring import L1Input, L2Input, Result, RuleInput, compute


def open_issues(db: Session, level: str = "l3", ids: list[int] | None = None) -> dict[int, date]:
    """Use case id -> date of its latest verification, where that one found issues.

    With `ids` only those use cases are looked at (one rule's page or save)."""
    col = Verification.l3_id if level == "l3" else Verification.l2_id
    rank = (
        func.row_number()
        .over(partition_by=col, order_by=(Verification.verified_at.desc(), Verification.id.desc()))
        .label("rank")
    )
    q = select(col.label("uc"), Verification.verified_at, Verification.result, rank).where(
        col.is_not(None)
    )
    if ids is not None:
        q = q.where(col.in_(ids))
    latest = q.subquery()
    rows = db.execute(
        select(latest.c.uc, latest.c.verified_at).where(
            latest.c.rank == 1, latest.c.result == VerificationResult.issues
        )
    )
    return {uc: at for uc, at in rows}


def compute_scores(
    db: Session, default_interval: int, today: date | None = None
) -> tuple[Result, list, list, list]:
    l1s = list(db.scalars(select(L1UseCase).order_by(L1UseCase.sort_order)))
    l2s = list(db.scalars(select(L2UseCase).order_by(L2UseCase.code)))
    l3s = list(db.scalars(select(L3UseCase).order_by(L3UseCase.code)))
    l1_code = {x.id: x.code for x in l1s}
    l2_code = {x.id: x.code for x in l2s}
    res = compute(
        [L1Input(x.code, x.applicable) for x in l1s],
        [L2Input(x.code, l1_code[x.l1_id]) for x in l2s],
        [
            RuleInput(
                x.code,
                l2_code[x.l2_id],
                x.lifecycle_status,
                x.effectiveness,
                x.implementation,
                x.coverage,
                x.last_verified_at,
                x.verification_interval_days,
            )
            for x in l3s
        ],
        today or date.today(),
        default_interval,
    )
    return res, l1s, l2s, l3s
