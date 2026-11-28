from datetime import date, datetime, timedelta
from typing import Annotated, ClassVar, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.models import AuthSource, Lifecycle, RefKind, Role

# Identifier rules from the MaGMa UCF tool: L1 "XX", L2 "XX-YYY", L3 "XX-YYY-NN".
L1Code = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]
L2Code = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}-[A-Z0-9]{3}$")]
# XX-YYY-NN, optionally with extra identifiers before the sequence number: XX-YYY-WIN-AD-01
L3_CODE_PATTERN = r"^[A-Z]{2}-[A-Z0-9]{3}-(?:[A-Z0-9]+-)*\d{2,3}$"
L3_CODE_MAX = 64
L3Code = Annotated[str, StringConstraints(pattern=L3_CODE_PATTERN, max_length=L3_CODE_MAX)]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
Metric = Annotated[float, Field(ge=0, le=1)]
AttackId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Patch(BaseModel):
    """PATCH body: a field left out is unchanged; an explicit null is only allowed for fields
    that may be empty (otherwise the database refuses it later with a misleading error)."""

    nullable: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="after")
    def _no_nulls(self):
        bad = sorted(
            k
            for k in self.model_fields_set
            if getattr(self, k) is None and k not in self.nullable and k != "expected_updated_at"
        )
        if bad:
            raise ValueError(f"cannot be empty: {', '.join(bad)}")
        return self


# Limits for free text, so one request cannot store megabytes (and again in the audit log).
TEXT_MAX = 20_000
NOTE_MAX = 2_000
LongText = Annotated[str, StringConstraints(max_length=TEXT_MAX)]
ShortText = Annotated[str, StringConstraints(max_length=255)]
DisplayName = Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)]
Password = Annotated[str, StringConstraints(max_length=1024)]


def not_in_future(v: date | None) -> date | None:
    # The server counts in UTC; a browser east of it is up to a day ahead, so "today" there
    # must not be refused as a future date.
    if v is not None and v > date.today() + timedelta(days=1):
        raise ValueError("date is in the future")
    return v


# ---------------------------------------------------------------- auth & users


class LoginIn(BaseModel):
    username: Annotated[str, StringConstraints(max_length=255)]
    password: Password
    # authenticator code or a recovery code, for accounts with two-factor login
    otp: Annotated[str, StringConstraints(max_length=64)] | None = None


class UserOut(ORM):
    id: int
    username: str
    display_name: str
    email: str | None
    role: Role
    auth_source: AuthSource
    active: bool
    totp_enabled: bool = False
    locale: str | None = None
    last_login_at: datetime | None
    created_at: datetime


class UserCreate(BaseModel):
    username: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._@-]{2,64}$")]
    display_name: DisplayName = ""
    email: EmailStr | None = None
    role: Role
    password: Password


class UserUpdate(BaseModel):
    display_name: DisplayName | None = None
    email: EmailStr | None = None
    role: Role | None = None
    active: bool | None = None
    password: Password | None = None


class PasswordChange(BaseModel):
    current_password: Password
    new_password: Password


class AuthConfigOut(BaseModel):
    local_login_enabled: bool
    sso_enabled: bool
    # empty: the login page shows "Sign in with Microsoft" / "Sign in with SSO" in its language
    sso_label: str = ""
    sso_provider: Literal["entra", "oidc"] = "oidc"


# ---------------------------------------------------------------- business layer & references


class RefItemIn(BaseModel):
    name: Name
    description: LongText = ""


class RefItemOut(ORM):
    id: int
    kind: RefKind
    name: str
    description: str


class RefItemUsageOut(RefItemOut):
    # Codes of what uses the entry: L2 use cases for threat actors, L3 rules for the other kinds.
    used_by: list[str] = []
    # Log sources only: systems whose interview lists the entry on a component (issue #39).
    used_by_systems: list[str] = []


class BusinessDriverIn(BaseModel):
    code: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32)]
    name: Name
    description: LongText = ""


class BusinessDriverOut(ORM):
    id: int
    code: str
    name: str
    description: str


class ComplianceDriverIn(BaseModel):
    ref: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    name: ShortText = ""
    description: LongText = ""


class ComplianceDriverOut(ORM):
    id: int
    source_id: int
    ref: str
    name: str
    description: str


class ComplianceSourceOut(ORM):
    id: int
    name: str
    drivers: list[ComplianceDriverOut]


class ComplianceSourceIn(BaseModel):
    name: Name


class ComplianceRef(BaseModel):
    """A linked compliance driver, with its source, as shown next to a use case."""

    id: int
    source_id: int
    source: str
    ref: str
    name: str


class LinkedUseCase(BaseModel):
    code: str
    name: str
    level: str  # l2 | l3


class DriverCoverage(BaseModel):
    """Coverage of one driver over the L2 use cases linked to it (app/drivers.py)."""

    id: int
    code: str  # business driver code or compliance reference
    name: str
    source_id: int | None = None
    source: str | None = None
    l2_count: int
    l3_count: int
    scored_l2: int
    coverage: float | None  # average L2 weight, L2s without scored rules count as 0
    gap: bool  # no linked use case
    low: bool  # linked, but coverage below the threshold
    l2_codes: list[str]


class SourceCoverage(BaseModel):
    id: int
    name: str
    drivers: int
    linked_drivers: int
    l2_count: int
    l3_count: int
    coverage: float | None
    gap_drivers: int
    low_drivers: int


class DriverCoverageOut(BaseModel):
    low_threshold: float
    business: list[DriverCoverage]
    compliance: list[DriverCoverage]
    sources: list[SourceCoverage]


# ---------------------------------------------------------------- use cases


class L1Base(BaseModel):
    name: Name
    threat_category: ShortText = ""
    purpose: LongText = ""
    stakeholders: LongText = ""
    description: LongText = ""
    applicable: bool = True
    sort_order: int = 0


class L1Create(L1Base):
    code: L1Code


class L1Update(Patch):
    name: Name | None = None
    threat_category: ShortText | None = None
    purpose: LongText | None = None
    stakeholders: LongText | None = None
    description: LongText | None = None
    applicable: bool | None = None
    sort_order: int | None = None


class L1Out(ORM):
    id: int
    code: str
    name: str
    threat_category: str
    purpose: str
    stakeholders: str
    description: str
    applicable: bool
    sort_order: int
    l2_count: int = 0
    l3_count: int = 0
    # inherited from the L2 use cases below (read-only)
    business_drivers: list[str] = []
    compliance_drivers: list[ComplianceRef] = []


class TrackingFields(BaseModel):
    lifecycle_status: Lifecycle | None = None
    onboarded_at: date | None = None
    last_verified_at: date | None = None

    # a verification date in the future would keep a rule "verified" for years
    _past = field_validator("onboarded_at", "last_verified_at")(not_in_future)


class L2Create(TrackingFields):
    code: L2Code
    name: Name
    description: LongText = ""
    risk_level: Annotated[int, Field(ge=1, le=5)] | None = None
    target_implementation: Metric | None = None
    actors: list[str] = []
    business_drivers: list[str] = []
    compliance_driver_ids: list[int] = []


class L2Update(TrackingFields, Patch):
    nullable = frozenset(
        {"onboarded_at", "last_verified_at", "risk_level", "target_implementation"}
    )
    # updated_at the edit started from; when someone saved in between the update is refused (409)
    expected_updated_at: datetime | None = None
    name: Name | None = None
    description: LongText | None = None
    risk_level: Annotated[int, Field(ge=1, le=5)] | None = None
    target_implementation: Metric | None = None
    actors: list[str] | None = None
    business_drivers: list[str] | None = None
    compliance_driver_ids: list[int] | None = None


class LinkedSystem(BaseModel):
    id: int
    name: str
    archived: bool


class L2Out(BaseModel):
    id: int
    code: str
    l1_code: str
    name: str
    description: str
    lifecycle_status: Lifecycle
    risk_level: int | None
    target_implementation: float | None
    onboarded_at: date | None
    last_verified_at: date | None
    last_verified_by: str | None
    updated_at: datetime | None = None
    actors: list[str]
    business_drivers: list[str]
    compliance_driver_ids: list[int]
    compliance_drivers: list[ComplianceRef] = []
    l3_count: int
    # systems whose latest completed interview linked this use case (#17)
    systems: list[LinkedSystem] = []


SiemRuleId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
SiemRuleIds = Annotated[
    list[SiemRuleId], Field(max_length=50), AfterValidator(lambda v: list(dict.fromkeys(v)))
]


class L3Create(TrackingFields):
    code: L3Code
    name: Name
    description: LongText = ""
    effectiveness: Metric | None = None
    implementation: Metric | None = None
    coverage: Metric | None = None
    comments: LongText = ""
    attack_techniques: list[AttackId] = []
    siem_rule_ids: SiemRuleIds = []
    verification_interval_days: Annotated[int, Field(ge=1, le=3650)] | None = None
    risk_level: Annotated[int, Field(ge=1, le=5)] | None = None
    target_implementation: Metric | None = None
    log_sources: list[str] = []
    detection_technologies: list[str] = []
    scopes: list[str] = []


class L3Update(TrackingFields, Patch):
    nullable = frozenset(
        {
            "onboarded_at",
            "last_verified_at",
            "risk_level",
            "target_implementation",
            "effectiveness",
            "implementation",
            "coverage",
            "verification_interval_days",
        }
    )
    # updated_at the edit started from; when someone saved in between the update is refused (409)
    expected_updated_at: datetime | None = None
    name: Name | None = None
    description: LongText | None = None
    effectiveness: Metric | None = None
    implementation: Metric | None = None
    coverage: Metric | None = None
    comments: LongText | None = None
    attack_techniques: list[AttackId] | None = None
    siem_rule_ids: SiemRuleIds | None = None
    verification_interval_days: Annotated[int, Field(ge=1, le=3650)] | None = None
    risk_level: Annotated[int, Field(ge=1, le=5)] | None = None
    target_implementation: Metric | None = None
    log_sources: list[str] | None = None
    detection_technologies: list[str] | None = None
    scopes: list[str] | None = None


class L3Out(BaseModel):
    id: int
    code: str
    l1_code: str
    l2_code: str
    name: str
    description: str
    effectiveness: float | None
    implementation: float | None
    coverage: float | None
    lifecycle_status: Lifecycle
    comments: str
    attack_techniques: list[str]
    siem_rule_ids: list[str] = []
    # built from the SIEM name format in the settings (issues #29, #50)
    siem_name: str | None = None
    onboarded_at: date | None
    last_verified_at: date | None
    last_verified_by: str | None
    verification_interval_days: int | None
    risk_level: int | None
    target_implementation: float | None
    log_sources: list[str]
    detection_technologies: list[str]
    scopes: list[str]
    updated_at: datetime
    # inherited from the L2 use case (read-only)
    business_drivers: list[str] = []
    compliance_drivers: list[ComplianceRef] = []
    # risk and target in effect (own value, else the L2's, else derived from the risk level)
    effective_risk: int | None = None
    risk_source: str | None = None
    risk_system: str | None = None
    effective_target: float | None = None
    target_source: str | None = None
    implementation_gap: float | None = None
    priority: float | None = None
    # factor from the drivers linked to the L2 (app/drivers.py); lets the UI preview the
    # priority while metrics are being edited
    driver_boost: float = 1.0
    # calculated (app/scoring.py)
    weight: float | None = None
    potential: float | None = None
    assessed: bool = False
    scored: bool = False
    verification_due: date | None = None
    verification_overdue: bool = False
    # date of the latest check when it found issues (it does not count as verified)
    issues_at: date | None = None


class CatalogueSummary(BaseModel):
    l1: int
    l2: int
    l3: int
    business_drivers: int
    compliance_drivers: int
    references: dict[str, int]


class AuditOut(ORM):
    id: int
    at: datetime
    username: str
    action: str
    entity: str
    entity_key: str
    changes: dict
    ip: str | None = None
