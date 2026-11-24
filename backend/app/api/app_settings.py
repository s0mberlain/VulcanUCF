"""Settings admins change in the app. First one: the SIEM name of a rule (issue #29).

The SIEM name is built from a format such as `$companyName:$ucID:$ucName`. `$ucID`, `$ucName`,
`$l2ID` and `$l1ID` come from the rule; admins define further variables (`$companyName` =
`MYCORP`). The name is built in the browser (frontend/src/lib/ruleName.ts); unknown `$names`
stay as they are, so a typo is visible in the result.
"""

from datetime import datetime

from fastapi import APIRouter, HTTPException

from app import audit
from app.api.deps import DB
from app.models import AppSetting
from app.rulename import BUILTINS, RULE_NAME, RuleNameSettings, load
from app.security import Admin, Reader

router = APIRouter(tags=["settings"])


class RuleNameOut(RuleNameSettings):
    builtins: list[str] = list(BUILTINS)
    updated_at: datetime | None = None
    updated_by: str | None = None


@router.get("/settings/rule-name", response_model=RuleNameOut)
def get_rule_name(_: Reader, db: DB) -> RuleNameOut:
    s, row = load(db)
    return RuleNameOut(
        **s.model_dump(),
        updated_at=row.updated_at if row else None,
        updated_by=row.updated_by if row else None,
    )


@router.put("/settings/rule-name", response_model=RuleNameOut)
def put_rule_name(body: RuleNameSettings, user: Admin, db: DB) -> RuleNameOut:
    names = [v.name for v in body.variables]
    clash = sorted(set(names) & set(BUILTINS))
    if clash:
        raise HTTPException(422, f"${clash[0]} comes from the rule and cannot be redefined")
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise HTTPException(422, f"${dupes[0]} is defined twice")
    if not body.format:
        raise HTTPException(422, "The format cannot be empty")
    old, row = load(db)
    value = body.model_dump()
    if row is None:
        row = AppSetting(key=RULE_NAME, value=value, updated_by=user.username)
        db.add(row)
    else:
        row.value, row.updated_by = value, user.username
    audit.record(db, user, "update", "settings", RULE_NAME, audit.diff(old.model_dump(), value))
    db.commit()
    db.refresh(row)
    return RuleNameOut(**value, updated_at=row.updated_at, updated_by=row.updated_by)
