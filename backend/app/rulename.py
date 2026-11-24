"""SIEM name of an L3 rule (issue #29), built on the server (issue #50).

The format (e.g. `$companyName:$ucID:$ucName`) and admin variables live in app_settings key
`rule_name`. `$ucID`, `$ucName`, `$l2ID` and `$l1ID` come from the rule. The whole name counts
(`$ucIDx` is not `$ucID` + "x"); unknown names stay as they are so a typo is visible. The
frontend (lib/ruleName.ts) uses the same rules for its live preview.
"""

import re
from collections.abc import Callable
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy.orm import Session

from app.models import AppSetting, L3UseCase

_VAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")

RULE_NAME = "rule_name"  # app_settings key
BUILTINS = ("ucID", "ucName", "l2ID", "l1ID")
DEFAULT_FORMAT = "$ucID:$ucName"
VAR_NAME = r"^[A-Za-z_][A-Za-z0-9_]{0,49}$"


class Variable(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, pattern=VAR_NAME)]
    value: Annotated[str, StringConstraints(max_length=200)] = ""


class RuleNameSettings(BaseModel):
    format: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] = (
        DEFAULT_FORMAT
    )
    variables: list[Variable] = Field(default_factory=list, max_length=50)


def load(db: Session) -> tuple[RuleNameSettings, AppSetting | None]:
    row = db.get(AppSetting, RULE_NAME)
    return (RuleNameSettings.model_validate(row.value) if row else RuleNameSettings()), row


def render(fmt: str, values: dict[str, str]) -> str:
    return _VAR.sub(lambda m: values.get(m.group(1), m.group(0)), fmt)


def formatter(db: Session) -> Callable[[L3UseCase], str]:
    settings, _ = load(db)
    variables = {v.name: v.value for v in settings.variables}

    def name(rule: L3UseCase) -> str:
        values = variables | {
            "ucID": rule.code,
            "ucName": rule.name,
            "l2ID": rule.parent.code,
            "l1ID": rule.code[:2],
        }
        return render(settings.format, values)

    return name
