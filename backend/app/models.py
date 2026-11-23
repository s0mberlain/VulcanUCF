"""Database models for the MaGMa Use Case Framework.

Layers (see docs/PLAN.md section 4):
- business layer: business drivers, compliance sources and drivers
- threat layer: L1 and L2 use cases
- implementation layer: L3 rules and the reference lists (log sources, detection
  technologies, scopes) plus threat actors used on L2
"""

import enum
from datetime import UTC, date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Date,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    false,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Timestamp stored in UTC that always comes back timezone-aware.

    SQLite drops the offset of ``DateTime(timezone=True)`` and returns naive values,
    which the API then sent without "Z"; browsers read those as local time, so times
    were shifted by the viewer's UTC offset. PostgreSQL already returns aware values.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is not None and value.tzinfo is not None:
            value = value.astimezone(UTC)
        return value

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value


class Role(enum.StrEnum):
    admin = "admin"
    analyst = "analyst"
    auditor = "auditor"


class AuthSource(enum.StrEnum):
    local = "local"
    sso = "sso"
    service = "service"  # API token account for integrations (no interactive login)


class Lifecycle(enum.StrEnum):
    onboarding = "onboarding"
    operational = "operational"
    maintenance = "maintenance"
    offloading = "offloading"
    retired = "retired"


class VerificationResult(enum.StrEnum):
    ok = "ok"
    issues = "issues"


class RefKind(enum.StrEnum):
    threat_actor = "threat_actor"
    detection_technology = "detection_technology"
    log_source = "log_source"
    scope = "scope"


def _enum(e: type[enum.Enum], name: str) -> Enum:
    # Store as plain strings (no native DB enum) so new values need no type migration.
    return Enum(e, name=name, native_enum=False, length=32, validate_strings=True)


# ---------------------------------------------------------------- users & auth


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str | None] = mapped_column(String(254))
    role: Mapped[Role] = mapped_column(_enum(Role, "role"))
    auth_source: Mapped[AuthSource] = mapped_column(
        _enum(AuthSource, "auth_source"), default=AuthSource.local
    )
    password_hash: Mapped[str | None] = mapped_column(String(255))
    sso_subject: Mapped[str | None] = mapped_column(String(255), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    # TOTP second factor for local accounts (app/totp.py). The secret is encrypted with SECRET_KEY.
    totp_secret: Mapped[str | None] = mapped_column(String(255))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # UI language (en, de, nl); None = follow the browser
    locale: Mapped[str | None] = mapped_column(String(8))
    totp_last_step: Mapped[int | None] = mapped_column(Integer)
    # sha256 hashes of unused one-time recovery codes
    recovery_codes: Mapped[list[str]] = mapped_column(JSON, default=list)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())

    user: Mapped[User] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    username: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))  # create | update | delete | login ...
    entity: Mapped[str] = mapped_column(String(32), index=True)
    entity_key: Mapped[str] = mapped_column(String(128))
    changes: Mapped[dict] = mapped_column(JSON, default=dict)
    # client address of the request that caused the entry (None for background jobs)
    ip: Mapped[str | None] = mapped_column(String(64))


# ---------------------------------------------------------------- business layer


class BusinessDriver(Base):
    __tablename__ = "business_drivers"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")


class ComplianceSource(Base):
    __tablename__ = "compliance_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)

    drivers: Mapped[list["ComplianceDriver"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class ComplianceDriver(Base):
    __tablename__ = "compliance_drivers"
    __table_args__ = (UniqueConstraint("source_id", "ref"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("compliance_sources.id", ondelete="CASCADE"))
    ref: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")

    source: Mapped[ComplianceSource] = relationship(back_populates="drivers")


class ReferenceItem(Base):
    """Threat actors, detection technologies, log sources and scopes."""

    __tablename__ = "reference_items"
    __table_args__ = (UniqueConstraint("kind", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[RefKind] = mapped_column(_enum(RefKind, "ref_kind"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")


# ---------------------------------------------------------------- threat layer

l2_actors = Table(
    "l2_actors",
    Base.metadata,
    Column("l2_id", ForeignKey("l2_use_cases.id", ondelete="CASCADE"), primary_key=True),
    Column("item_id", ForeignKey("reference_items.id", ondelete="CASCADE"), primary_key=True),
)
l2_business_drivers = Table(
    "l2_business_drivers",
    Base.metadata,
    Column("l2_id", ForeignKey("l2_use_cases.id", ondelete="CASCADE"), primary_key=True),
    Column("driver_id", ForeignKey("business_drivers.id", ondelete="CASCADE"), primary_key=True),
)
l2_compliance_drivers = Table(
    "l2_compliance_drivers",
    Base.metadata,
    Column("l2_id", ForeignKey("l2_use_cases.id", ondelete="CASCADE"), primary_key=True),
    Column("driver_id", ForeignKey("compliance_drivers.id", ondelete="CASCADE"), primary_key=True),
)
l3_references = Table(
    "l3_references",
    Base.metadata,
    Column("l3_id", ForeignKey("l3_use_cases.id", ondelete="CASCADE"), primary_key=True),
    Column("item_id", ForeignKey("reference_items.id", ondelete="CASCADE"), primary_key=True),
)


class L1UseCase(Base):
    __tablename__ = "l1_use_cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(2), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    threat_category: Mapped[str] = mapped_column(String(128), default="")
    purpose: Mapped[str] = mapped_column(Text, default="")
    stakeholders: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    applicable: Mapped[bool] = mapped_column(Boolean, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    children: Mapped[list["L2UseCase"]] = relationship(
        back_populates="parent", order_by="L2UseCase.code"
    )


class L2UseCase(Base):
    __tablename__ = "l2_use_cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    l1_id: Mapped[int] = mapped_column(
        ForeignKey("l1_use_cases.id", ondelete="RESTRICT"), index=True
    )
    code: Mapped[str] = mapped_column(String(6), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    lifecycle_status: Mapped[Lifecycle] = mapped_column(
        _enum(Lifecycle, "lifecycle"), default=Lifecycle.onboarding
    )
    risk_level: Mapped[int | None] = mapped_column(Integer)
    target_implementation: Mapped[float | None] = mapped_column(Float)
    onboarded_at: Mapped[date | None] = mapped_column(Date)
    last_verified_at: Mapped[date | None] = mapped_column(Date)
    last_verified_by: Mapped[str | None] = mapped_column(String(64))
    # "Operational" definition of done: {item_key: {"by": user, "at": iso date}} (app/lifecycle.py)
    dod: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    parent: Mapped[L1UseCase] = relationship(back_populates="children")
    children: Mapped[list["L3UseCase"]] = relationship(
        back_populates="parent", order_by="L3UseCase.code"
    )
    actors: Mapped[list[ReferenceItem]] = relationship(secondary=l2_actors)
    business_drivers: Mapped[list[BusinessDriver]] = relationship(secondary=l2_business_drivers)
    compliance_drivers: Mapped[list[ComplianceDriver]] = relationship(
        secondary=l2_compliance_drivers
    )


class L3UseCase(Base):
    __tablename__ = "l3_use_cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    l2_id: Mapped[int] = mapped_column(
        ForeignKey("l2_use_cases.id", ondelete="RESTRICT"), index=True
    )
    code: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    # Metrics are fractions 0..1; NULL = not assessed (see PLAN 2.5).
    effectiveness: Mapped[float | None] = mapped_column(Float)
    implementation: Mapped[float | None] = mapped_column(Float)
    coverage: Mapped[float | None] = mapped_column(Float)
    lifecycle_status: Mapped[Lifecycle] = mapped_column(
        _enum(Lifecycle, "lifecycle"), default=Lifecycle.onboarding
    )
    comments: Mapped[str] = mapped_column(Text, default="")
    attack_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    # ids of the rule in the SIEM (saved search name, analytics rule id ...), see app/siem.py
    siem_rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    onboarded_at: Mapped[date | None] = mapped_column(Date)
    last_verified_at: Mapped[date | None] = mapped_column(Date)
    last_verified_by: Mapped[str | None] = mapped_column(String(64))
    verification_interval_days: Mapped[int | None] = mapped_column(Integer)
    # Risk-based prioritisation (PLAN 2.11); NULL = inherit from the L2 use case.
    risk_level: Mapped[int | None] = mapped_column(Integer)
    target_implementation: Mapped[float | None] = mapped_column(Float)
    dod: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    parent: Mapped[L2UseCase] = relationship(back_populates="children")
    references: Mapped[list[ReferenceItem]] = relationship(secondary=l3_references)


class Verification(Base):
    """History behind last_verified_at on L2 use cases and L3 rules."""

    __tablename__ = "verifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    l2_id: Mapped[int | None] = mapped_column(
        ForeignKey("l2_use_cases.id", ondelete="CASCADE"), index=True
    )
    l3_id: Mapped[int | None] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="CASCADE"), index=True
    )
    verified_at: Mapped[date] = mapped_column(Date)
    username: Mapped[str] = mapped_column(String(64))
    result: Mapped[VerificationResult] = mapped_column(
        _enum(VerificationResult, "verification_result")
    )
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class ConfigCommit(Base):
    """One immutable version of the free-form JSON configuration of an L3 rule (older rows may
    belong to an L2 use case and hold YAML, from before issues #25 and #28).

    Commits are never changed or deleted (docs/PLAN.md section 4a). `sha` is a SHA-256 over the
    parent, author, time, message and content, like a git commit id.
    """

    __tablename__ = "config_commits"
    # one revision number per use case, also when two people save at the same moment
    __table_args__ = (
        UniqueConstraint("l2_id", "rev", name="uq_config_commits_l2_rev"),
        UniqueConstraint("l3_id", "rev", name="uq_config_commits_l3_rev"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    l2_id: Mapped[int | None] = mapped_column(
        ForeignKey("l2_use_cases.id", ondelete="CASCADE"), index=True
    )
    l3_id: Mapped[int | None] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="CASCADE"), index=True
    )
    rev: Mapped[int] = mapped_column(Integer)
    sha: Mapped[str] = mapped_column(String(64), unique=True)
    parent_sha: Mapped[str | None] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(String(500))
    author: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    restored_from: Mapped[str | None] = mapped_column(String(64))
    # optional git repository sync (app/gitsync.py): commit id in the connected repo
    git_sha: Mapped[str | None] = mapped_column(String(64))
    # "app" = saved in the app, "git" = imported from a commit made directly in the repository
    source: Mapped[str] = mapped_column(String(8), default="app", server_default="app")

    tags: Mapped[list["ConfigTag"]] = relationship(
        back_populates="commit", cascade="all, delete-orphan", order_by="ConfigTag.id"
    )


class ConfigTag(Base):
    """A named marker on a commit, e.g. `prod` or `verified-2026-11-13`."""

    __tablename__ = "config_tags"
    __table_args__ = (UniqueConstraint("commit_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    commit_id: Mapped[int] = mapped_column(
        ForeignKey("config_commits.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    commit: Mapped[ConfigCommit] = relationship(back_populates="tags")


class LifecycleEvent(Base):
    """A lifecycle status change with the reason (change driver) behind it (PLAN 2.4)."""

    __tablename__ = "lifecycle_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    l2_id: Mapped[int | None] = mapped_column(
        ForeignKey("l2_use_cases.id", ondelete="CASCADE"), index=True
    )
    l3_id: Mapped[int | None] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="CASCADE"), index=True
    )
    from_status: Mapped[Lifecycle | None] = mapped_column(_enum(Lifecycle, "lifecycle"))
    to_status: Mapped[Lifecycle] = mapped_column(_enum(Lifecycle, "lifecycle"))
    driver_type: Mapped[str] = mapped_column(String(32), default="unspecified")
    driver: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    dod_override: Mapped[bool] = mapped_column(Boolean, default=False)
    username: Mapped[str] = mapped_column(String(64))
    at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)


class Snapshot(Base):
    """Frozen copy of all computed scores and counts, for trends and comparisons."""

    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(200), default="")
    kind: Mapped[str] = mapped_column(String(16), default="manual")  # manual|scheduled|demo
    taken_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    taken_by: Mapped[str] = mapped_column(String(64), default="system")
    data: Mapped[dict] = mapped_column(JSON)


class GitSyncState(Base):
    """Single row with the state of the optional git repository sync."""

    __tablename__ = "git_sync_state"

    id: Mapped[int] = mapped_column(primary_key=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_error: Mapped[str | None] = mapped_column(Text)
    head_sha: Mapped[str | None] = mapped_column(String(64))
    # two-way sync: remote commits up to this one have been read back into the app
    last_imported_sha: Mapped[str | None] = mapped_column(String(64))
    last_import_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    # what the last import did not take over (conflicts, invalid YAML, unknown paths)
    import_notes: Mapped[list | None] = mapped_column(JSON, default=list)


class OutputMetric(Base):
    """Output metrics of an L3 rule for one month (PLAN 2.13)."""

    __tablename__ = "output_metrics"
    __table_args__ = (UniqueConstraint("l3_id", "period"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    l3_id: Mapped[int] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="CASCADE"), index=True
    )
    period: Mapped[date] = mapped_column(Date, index=True)  # first day of the month
    alerts: Mapped[int] = mapped_column(Integer, default=0)
    incidents: Mapped[int] = mapped_column(Integer, default=0)
    false_positives: Mapped[int] = mapped_column(Integer, default=0)
    false_negatives: Mapped[int | None] = mapped_column(Integer)  # often unknown
    note: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="manual")  # manual | csv | demo
    updated_by: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)


# ---------------------------------------------------------------- integrations (M7)


class ApiToken(Base):
    """Bearer token of a service account, for scripts and SIEM integrations."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    prefix: Mapped[str] = mapped_column(String(16))  # shown in the list to recognise a token
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    # what the token may call (app/security.py TOKEN_SCOPES): "siem" = the SIEM push API,
    # "read" = read-only access to the rest of the API
    scopes: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["siem"])

    user: Mapped[User] = relationship()


class SiemSource(Base):
    """A SIEM that pushes its rule inventory or alert counts (Splunk, Sentinel, QRadar ...)."""

    __tablename__ = "siem_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True)
    inventory_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    inventory_by: Mapped[str | None] = mapped_column(String(64))
    alerts_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    alerts_by: Mapped[str | None] = mapped_column(String(64))
    # outcome of the last alert push: counts and SIEM rule ids that matched no use case
    alerts_report: Mapped[dict | None] = mapped_column(JSON, default=dict)

    rules: Mapped[list["SiemRule"]] = relationship(
        back_populates="source", cascade="all, delete-orphan", order_by="SiemRule.rule_id"
    )


class SiemRule(Base):
    """One detection rule as the SIEM reported it in its last inventory push."""

    __tablename__ = "siem_rules"
    __table_args__ = (UniqueConstraint("source_id", "rule_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("siem_sources.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str] = mapped_column(String(32), default="")
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)

    source: Mapped[SiemSource] = relationship(back_populates="rules")


class SiemAlertBatch(Base):
    """An alert push that carried a batch id: a retry with the same id is not counted twice."""

    __tablename__ = "siem_alert_batches"
    __table_args__ = (UniqueConstraint("source_id", "batch_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("siem_sources.id", ondelete="CASCADE"), index=True
    )
    batch_id: Mapped[str] = mapped_column(String(128))
    applied_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    applied_by: Mapped[str] = mapped_column(String(64))


class AppSetting(Base):
    """Settings admins change in the app (not in the environment), one JSON value per key.

    `rule_name`: format and variables of the SIEM name shown on each rule (issue #29).
    """

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="system")


# ---------------------------------------------------------------- business owner interviews (#17)


class InterviewStatus(enum.StrEnum):
    draft = "draft"
    completed = "completed"
    confirmed = "confirmed"


class System(Base):
    """A business application or platform whose owner is interviewed (app/interviews.py).

    The business owner is a contact, not a user account.
    """

    __tablename__ = "systems"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    # lower-case name: system names are unique regardless of case
    name_key: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    owner_name: Mapped[str] = mapped_column(String(255))
    owner_department: Mapped[str] = mapped_column(String(255), default="")
    owner_email: Mapped[str | None] = mapped_column(String(254))
    criticality: Mapped[int] = mapped_column(Integer)  # 1..5
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    # public | internal | confidential | restricted
    data_classification: Mapped[str] = mapped_column(String(16), default="internal")
    review_interval_months: Mapped[int] = mapped_column(Integer, default=12)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    interviews: Mapped[list["Interview"]] = relationship(
        back_populates="system",
        cascade="all, delete-orphan",
        order_by="Interview.id",
        foreign_keys="Interview.system_id",
    )


class Interview(Base):
    """One threat interview with the business owner of a system.

    `data` holds what the analyst enters (components with log source ids and STRIDE threats,
    L2 use cases added or removed by hand, detection requests). While the interview is a draft,
    proposals are worked out from it on every read. On completion the evaluated interview
    (names, proposals, gaps) is frozen into `result` and never changes again.
    """

    __tablename__ = "interviews"
    # at most one draft per system (#45)
    __table_args__ = (
        Index(
            "uq_interviews_one_draft",
            "system_id",
            unique=True,
            sqlite_where=text("status = 'draft'"),
            postgresql_where=text("status = 'draft'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"), index=True)
    status: Mapped[InterviewStatus] = mapped_column(
        _enum(InterviewStatus, "interview_status"), default=InterviewStatus.draft
    )
    interview_date: Mapped[date] = mapped_column(Date)
    participants: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict | None] = mapped_column(JSON)
    # the completed interview this one started from (re-interview), for the comparison
    previous_id: Mapped[int | None] = mapped_column(
        ForeignKey("interviews.id", ondelete="SET NULL")
    )
    analyst: Mapped[str] = mapped_column(String(64))
    # optimistic locking: a save must name the version it started from
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    completed_by: Mapped[str | None] = mapped_column(String(64))
    confirmed_by: Mapped[str | None] = mapped_column(String(255))
    confirmed_at: Mapped[date | None] = mapped_column(Date)
    confirmation_recorded_by: Mapped[str | None] = mapped_column(String(64))

    system: Mapped[System] = relationship(back_populates="interviews", foreign_keys=[system_id])
    attachments: Mapped[list["InterviewAttachment"]] = relationship(
        back_populates="interview",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="InterviewAttachment.id",
    )


class InterviewAttachment(Base):
    """An evidence file uploaded to an interview (issue #34): PDF, image, diagram or threat model.

    The file is kept in the database (so backups and `magma db-copy` take it along). `data` is
    deferred: lists of attachments do not load the file contents.
    """

    __tablename__ = "interview_attachments"

    id: Mapped[int] = mapped_column(primary_key=True)
    interview_id: Mapped[int] = mapped_column(
        ForeignKey("interviews.id", ondelete="CASCADE"), index=True
    )
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(128))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    data: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
    uploaded_by: Mapped[str] = mapped_column(String(64))
    uploaded_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    # the business owner's sign-off (#42): may be added after completion, until confirmed
    signoff: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())

    interview: Mapped[Interview] = relationship(back_populates="attachments")


class SystemLink(Base):
    """An L2 use case (or a single L3 rule of it) the latest completed interview of a system
    accepted.

    Replaced as a whole when the next interview of the system is completed. Follows the L2 by
    id (also when its code changes) and disappears with it. An L3 link (`l3_id` set) keeps the
    rule's L2 in `l2_id`, so filters by L2 still find it; it disappears with the rule.
    """

    __tablename__ = "system_links"
    __table_args__ = (
        UniqueConstraint("system_id", "l2_id", "l3_id", name="uq_system_links_system_l2_l3"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"), index=True)
    l2_id: Mapped[int] = mapped_column(
        ForeignKey("l2_use_cases.id", ondelete="CASCADE"), index=True
    )
    # set when a single L3 rule (not the whole L2) was selected for the threats
    l3_id: Mapped[int | None] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="CASCADE"), index=True, default=None
    )
    interview_id: Mapped[int] = mapped_column(ForeignKey("interviews.id", ondelete="CASCADE"))
    # highest risk score (likelihood x impact, 1..25) of the threats the link came from
    risk_score: Mapped[int] = mapped_column(Integer)
    # [{"component": name, "category": stride key, "score": int}]
    sources: Mapped[list] = mapped_column(JSON, default=list)

    system: Mapped[System] = relationship()
    l2: Mapped[L2UseCase] = relationship()
    l3: Mapped[L3UseCase | None] = relationship()


class RequestStatus(enum.StrEnum):
    open = "open"
    in_progress = "in_progress"
    implemented = "implemented"
    rejected = "rejected"
    not_feasible = "not_feasible"


class DetectionRequestState(Base):
    """Implementation status of one detection request of a system.

    The request itself (title, description, threat) lives in the interview data and is frozen
    with the interview. Its status changes later, also after completion, and is shared by the
    interviews of the system: a re-interview copies the request under the same `key`, so there
    is one status per (system, key). No row means "open". Last write wins (PROJ-1).
    """

    __tablename__ = "detection_request_states"
    __table_args__ = (UniqueConstraint("system_id", "key", name="uq_detection_request_system_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(40))
    status: Mapped[RequestStatus] = mapped_column(
        _enum(RequestStatus, "request_status"), default=RequestStatus.open
    )
    note: Mapped[str] = mapped_column(Text, default="")
    # what implemented the request: an L2 use case or a single L3 rule. Plain ids (no foreign
    # key) with the code as recorded, so a deleted use case shows as deleted and the code stays
    link_l2_id: Mapped[int | None] = mapped_column(Integer)
    link_l3_id: Mapped[int | None] = mapped_column(Integer)
    link_code: Mapped[str | None] = mapped_column(String(64))
    updated_by: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class StrideMapping(Base):
    """Admin-maintained STRIDE category -> L2 use case mapping that drives the proposals."""

    __tablename__ = "stride_mappings"

    category: Mapped[str] = mapped_column(String(32), primary_key=True)
    l2_id: Mapped[int] = mapped_column(
        ForeignKey("l2_use_cases.id", ondelete="CASCADE"), primary_key=True
    )

    l2: Mapped[L2UseCase] = relationship()


# Systems that need an L2 use case (read-only, for the use case pages)
L2UseCase.linked_systems = relationship(
    System, secondary="system_links", viewonly=True, order_by=System.name
)


# ---------------------------------------------------------------- purple teaming (VECTR-style)


class PtAssessmentStatus(enum.StrEnum):
    planned = "planned"
    in_progress = "in_progress"
    completed = "completed"


class PtRedStatus(enum.StrEnum):
    """Execution of a test, like VECTR's test case status: planned = Not performed,
    in_progress = In progress, paused = Paused, executed = Completed, not_executed = Abandoned."""

    planned = "planned"
    in_progress = "in_progress"
    paused = "paused"
    executed = "executed"
    not_executed = "not_executed"


class PtBlueStatus(enum.StrEnum):
    waiting = "waiting"
    in_review = "in_review"
    done = "done"


class PtOutcome(enum.StrEnum):
    """Per-tool outcome of a test (VECTR order of priority, best first, see app/purple.py)."""

    blocked = "blocked"
    alerted = "alerted"
    logged_central = "logged_central"
    logged_local = "logged_local"
    none = "none"
    not_applicable = "not_applicable"
    tbd = "tbd"


class PtTemplate(Base):
    """A reusable test procedure (VECTR "test case template") in the purple team library."""

    __tablename__ = "pt_templates"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    name_key: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    tactic: Mapped[str] = mapped_column(String(64), default="")
    platforms: Mapped[list[str]] = mapped_column(JSON, default=list)
    executor: Mapped[str] = mapped_column(String(64), default="")
    command: Mapped[str] = mapped_column(Text, default="")
    cleanup: Mapped[str] = mapped_column(Text, default="")
    operator_guidance: Mapped[str] = mapped_column(Text, default="")
    # detection technologies expected to see the test (become expected detection rows)
    expected_defenses: Mapped[list[str]] = mapped_column(JSON, default=list)
    # how the test is expected to be detected / prevented (copied to the test case)
    detection_steps: Mapped[str] = mapped_column(Text, default="")
    prevention_steps: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    # custom | atomic | vectr | csv
    source: Mapped[str] = mapped_column(String(16), default="custom")
    source_ref: Mapped[str] = mapped_column(String(128), default="", index=True)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)


class PtCampaignTemplate(Base):
    """A named, ordered set of test procedures, e.g. an adversary emulation plan."""

    __tablename__ = "pt_campaign_templates"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    name_key: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    template_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)


class PtAssessment(Base):
    """The scope of one purple team exercise: campaigns of test cases."""

    __tablename__ = "pt_assessments"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    environment: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[str] = mapped_column(Text, default="")
    # overall findings and conclusions (markdown)
    summary: Mapped[str] = mapped_column(Text, default="")
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[PtAssessmentStatus] = mapped_column(
        _enum(PtAssessmentStatus, "pt_assessment_status"), default=PtAssessmentStatus.planned
    )
    # the assessment this one re-runs (resilience trending)
    previous_id: Mapped[int | None] = mapped_column(
        ForeignKey("pt_assessments.id", ondelete="SET NULL")
    )
    # "assessment", or "quick": the one hidden container of the quick tests
    # (app/api/purple_quick.py), not listed with the assessments
    kind: Mapped[str] = mapped_column(String(16), default="assessment", server_default="assessment")
    created_by: Mapped[str] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    campaigns: Mapped[list["PtCampaign"]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="(PtCampaign.position, PtCampaign.id)",
    )


class PtCampaign(Base):
    __tablename__ = "pt_campaigns"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("pt_assessments.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    position: Mapped[int] = mapped_column(Integer, default=0)

    assessment: Mapped[PtAssessment] = relationship(back_populates="campaigns")
    test_cases: Mapped[list["PtTestCase"]] = relationship(
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="(PtTestCase.position, PtTestCase.id)",
    )


class PtTestCase(Base):
    """One executed procedure. The red and blue sides are saved separately, each with its own
    version (optimistic locking), so both teams can work on a test at the same time. The overall
    outcome is derived from the detections on read (app/purple.py), never stored."""

    __tablename__ = "pt_test_cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(
        ForeignKey("pt_campaigns.id", ondelete="CASCADE"), index=True
    )
    template_id: Mapped[int | None] = mapped_column(
        ForeignKey("pt_templates.id", ondelete="SET NULL"), index=True
    )
    # the same procedure across assessments ("tpl:<id>" or "tc:<uuid>"), for trending
    lineage_key: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    tactic: Mapped[str] = mapped_column(String(64), default="")
    platforms: Mapped[list[str]] = mapped_column(JSON, default=list)
    executor: Mapped[str] = mapped_column(String(64), default="")
    command: Mapped[str] = mapped_column(Text, default="")
    cleanup: Mapped[str] = mapped_column(Text, default="")
    operator_guidance: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    position: Mapped[int] = mapped_column(Integer, default=0)
    # red side
    red_status: Mapped[PtRedStatus] = mapped_column(
        _enum(PtRedStatus, "pt_red_status"), default=PtRedStatus.planned
    )
    red_assignee: Mapped[str] = mapped_column(String(64), default="")
    attack_start: Mapped[datetime | None] = mapped_column(UTCDateTime())
    attack_stop: Mapped[datetime | None] = mapped_column(UTCDateTime())
    targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    red_tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    red_notes: Mapped[str] = mapped_column(Text, default="")
    red_version: Mapped[int] = mapped_column(Integer, default=1)
    red_updated_by: Mapped[str] = mapped_column(String(64), default="")
    # blue side
    blue_status: Mapped[PtBlueStatus] = mapped_column(
        _enum(PtBlueStatus, "pt_blue_status"), default=PtBlueStatus.waiting
    )
    blue_assignee: Mapped[str] = mapped_column(String(64), default="")
    # findings: what was seen, what is missing, what to fix (markdown)
    blue_notes: Mapped[str] = mapped_column(Text, default="")
    detection_steps: Mapped[str] = mapped_column(Text, default="")
    prevention_steps: Mapped[str] = mapped_column(Text, default="")
    outcome_override: Mapped[PtOutcome | None] = mapped_column(_enum(PtOutcome, "pt_outcome"))
    blue_version: Mapped[int] = mapped_column(Integer, default=1)
    blue_updated_by: Mapped[str] = mapped_column(String(64), default="")
    plan_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    campaign: Mapped[PtCampaign] = relationship(back_populates="test_cases")
    detections: Mapped[list["PtDetection"]] = relationship(
        back_populates="test_case",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="(PtDetection.position, PtDetection.id)",
    )
    attachments: Mapped[list["PtAttachment"]] = relationship(
        back_populates="test_case",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="PtAttachment.id",
    )


class PtDetection(Base):
    """What one defense did about a test: an L3 rule of the catalogue (kind "rule") or any other
    tool or observation (kind "tool", e.g. "Microsoft Defender alert", "only in the logs")."""

    __tablename__ = "pt_detections"

    id: Mapped[int] = mapped_column(primary_key=True)
    test_case_id: Mapped[int] = mapped_column(
        ForeignKey("pt_test_cases.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(8), default="tool")  # rule | tool
    l3_id: Mapped[int | None] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="SET NULL"), index=True
    )
    # code of the rule when it was recorded; kept when the rule is deleted
    rule_code: Mapped[str] = mapped_column(String(64), default="")
    tool: Mapped[str] = mapped_column(String(255), default="")
    outcome: Mapped[PtOutcome] = mapped_column(
        _enum(PtOutcome, "pt_outcome"), default=PtOutcome.tbd
    )
    expected: Mapped[bool] = mapped_column(Boolean, default=False)
    alert_name: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    detected_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    note: Mapped[str] = mapped_column(Text, default="")
    position: Mapped[int] = mapped_column(Integer, default=0)

    test_case: Mapped[PtTestCase] = relationship(back_populates="detections")
    l3: Mapped[L3UseCase | None] = relationship()


class PtAttachment(Base):
    """Evidence on a test case (screenshot, log extract, PCAP ...), kept in the database."""

    __tablename__ = "pt_attachments"

    id: Mapped[int] = mapped_column(primary_key=True)
    test_case_id: Mapped[int] = mapped_column(
        ForeignKey("pt_test_cases.id", ondelete="CASCADE"), index=True
    )
    side: Mapped[str] = mapped_column(String(8))  # red | blue
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(128))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    data: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
    uploaded_by: Mapped[str] = mapped_column(String(64))
    uploaded_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    test_case: Mapped[PtTestCase] = relationship(back_populates="attachments")
