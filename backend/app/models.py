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
    CheckConstraint,
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

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class Role(enum.StrEnum):
    admin = "admin"
    analyst = "analyst"
    auditor = "auditor"
    # external tester: sees only the campaigns it is assigned to (PROJ-3)
    red_team = "red_team"


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
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # TOTP second factor for local accounts (app/totp.py). The secret is encrypted with SECRET_KEY.
    totp_secret: Mapped[str | None] = mapped_column(String(255))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # UI language (en, de, nl); None = follow the browser
    locale: Mapped[str | None] = mapped_column(String(8))
    totp_last_step: Mapped[int | None] = mapped_column(Integer)
    # sha256 hashes of unused one-time recovery codes
    recovery_codes: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Red team accounts end on a date (PROJ-3). It follows the assigned campaigns unless an
    # admin fixed it by hand (expiry_follows_campaign false).
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expiry_follows_campaign: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false()
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # set when the entry comes from a test result (PROJ-3); recomputed with the test
    test_id: Mapped[int | None] = mapped_column(
        ForeignKey("test_cases.id", ondelete="CASCADE"), index=True
    )


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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

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
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Snapshot(Base):
    """Frozen copy of all computed scores and counts, for trends and comparisons."""

    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(200), default="")
    kind: Mapped[str] = mapped_column(String(16), default="manual")  # manual|scheduled|demo
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    taken_by: Mapped[str] = mapped_column(String(64), default="system")
    data: Mapped[dict] = mapped_column(JSON)


class GitSyncState(Base):
    """Single row with the state of the optional git repository sync."""

    __tablename__ = "git_sync_state"

    id: Mapped[int] = mapped_column(primary_key=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    head_sha: Mapped[str | None] = mapped_column(String(64))
    # two-way sync: remote commits up to this one have been read back into the app
    last_imported_sha: Mapped[str | None] = mapped_column(String(64))
    last_import_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ImportedIncident(Base):
    """An incident from a SIEM case export (Microsoft Sentinel / Defender XDR) counted in the
    output metrics of a rule. The incident id is the key: importing the same or an overlapping
    export again replaces the incident instead of counting it twice."""

    __tablename__ = "imported_incidents"
    __table_args__ = (UniqueConstraint("incident_id", "l3_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    l3_id: Mapped[int] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="CASCADE"), index=True
    )
    period: Mapped[date] = mapped_column(Date)  # first day of the month the incident was created
    verdict: Mapped[str] = mapped_column(
        String(16)
    )  # true_positive | false_positive | benign | unknown
    title: Mapped[str] = mapped_column(String(300), default="")
    imported_by: Mapped[str] = mapped_column(String(64))
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


# ---------------------------------------------------------------- log source verification (#75)

# The fixed check items of a log source verification (PROJ-6)
LOG_SOURCE_CHECKS = ("intake", "configuration", "filtering", "responsibilities")


class LogSourceProfile(Base):
    """What a log source needs beyond its reference list entry: who is responsible and how
    often it is verified. One row per log source, created on first use."""

    __tablename__ = "log_source_profiles"

    item_id: Mapped[int] = mapped_column(
        ForeignKey("reference_items.id", ondelete="CASCADE"), primary_key=True
    )
    owner: Mapped[str] = mapped_column(String(255), default="")
    verification_interval_days: Mapped[int | None] = mapped_column(Integer)
    last_verified_at: Mapped[date | None] = mapped_column(Date)
    last_verified_by: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class LogSourceVerification(Base):
    """One check of a log source: intake, configuration, filtering and responsibilities, each
    ok / issues / n/a with a note. Only a check without issues counts as verified."""

    __tablename__ = "log_source_verifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(
        ForeignKey("reference_items.id", ondelete="CASCADE"), index=True
    )
    verified_at: Mapped[date] = mapped_column(Date)
    username: Mapped[str] = mapped_column(String(64))
    result: Mapped[VerificationResult] = mapped_column(
        _enum(VerificationResult, "verification_result")
    )
    note: Mapped[str] = mapped_column(Text, default="")
    # {check: {"result": "ok" | "issues" | "na", "note": str}} for LOG_SOURCE_CHECKS
    checks: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------- tasks (issue #74, PROJ-5)


class TaskKind(enum.StrEnum):
    review = "review"
    tune = "tune"
    update_settings = "update_settings"
    other = "other"


class TaskStatus(enum.StrEnum):
    open = "open"
    done = "done"


class Task(Base):
    """A to-do on an L2 use case or an L3 rule (review, tune, update settings ...)."""

    __tablename__ = "tasks"
    __table_args__ = (
        CheckConstraint("(l2_id IS NULL) <> (l3_id IS NULL)", name="ck_tasks_one_owner"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    l2_id: Mapped[int | None] = mapped_column(
        ForeignKey("l2_use_cases.id", ondelete="CASCADE"), index=True
    )
    l3_id: Mapped[int | None] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[TaskKind] = mapped_column(String(32), default=TaskKind.other)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text, default="")  # Markdown
    status: Mapped[TaskStatus] = mapped_column(String(16), default=TaskStatus.open, index=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    due_date: Mapped[date | None] = mapped_column(Date)
    assignee: Mapped[str | None] = mapped_column(String(64), index=True)
    done_by: Mapped[str | None] = mapped_column(String(64))
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    l2: Mapped["L2UseCase | None"] = relationship()
    l3: Mapped["L3UseCase | None"] = relationship()


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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # what the token may call (app/security.py TOKEN_SCOPES): "siem" = the SIEM push API,
    # "read" = read-only access to the rest of the API
    scopes: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["siem"])

    user: Mapped[User] = relationship()


class SiemSource(Base):
    """A SIEM that pushes its rule inventory or alert counts (Splunk, Sentinel, QRadar ...)."""

    __tablename__ = "siem_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True)
    inventory_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    inventory_by: Mapped[str | None] = mapped_column(String(64))
    alerts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    applied_by: Mapped[str] = mapped_column(String(64))


class AppSetting(Base):
    """Settings admins change in the app (not in the environment), one JSON value per key.

    `rule_name`: format and variables of the SIEM name shown on each rule (issue #29).
    """

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
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


# ---------------------------------------------------------------- tests (PROJ-3)


class CampaignStatus(enum.StrEnum):
    planned = "planned"
    running = "running"
    closed = "closed"


class TestStatus(enum.StrEnum):
    not_run = "not_run"
    executed = "executed"
    not_executable = "not_executable"


class TestOutcome(enum.StrEnum):
    blocked = "blocked"
    alerted = "alerted"
    logged = "logged"
    not_detected = "not_detected"


campaign_accounts = Table(
    "campaign_accounts",
    Base.metadata,
    Column("campaign_id", ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)


class TestTemplate(Base):
    """A reusable test script (library). Tests made from it are copies."""

    __test__ = False
    __tablename__ = "test_templates"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    technique: Mapped[str] = mapped_column(String(32), index=True)
    # Markdown
    description: Mapped[str] = mapped_column(Text, default="")
    procedure: Mapped[str] = mapped_column(Text, default="")
    tools: Mapped[str] = mapped_column(String(500), default="")
    prerequisites: Mapped[str] = mapped_column(Text, default="")
    expected_detection: Mapped[str] = mapped_column(Text, default="")
    uses: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    planned_start: Mapped[date] = mapped_column(Date)
    planned_end: Mapped[date] = mapped_column(Date)
    status: Mapped[CampaignStatus] = mapped_column(
        _enum(CampaignStatus, "campaign_status"), default=CampaignStatus.planned
    )
    # hidden: the red team sees the blue team's results after closing; open: at once (PROJ-4)
    collaboration: Mapped[str] = mapped_column(
        String(16), default="hidden", server_default="hidden"
    )
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    accounts: Mapped[list[User]] = relationship(secondary=campaign_accounts)
    tests: Mapped[list["TestCase"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan", order_by="TestCase.id"
    )


class TestCase(Base):
    """One test. campaign_id is empty for a quick test."""

    __test__ = False
    __tablename__ = "test_cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(200))
    technique: Mapped[str] = mapped_column(String(32), index=True)
    # Markdown
    description: Mapped[str] = mapped_column(Text, default="")
    procedure: Mapped[str] = mapped_column(Text, default="")
    tools: Mapped[str] = mapped_column(String(500), default="")
    prerequisites: Mapped[str] = mapped_column(Text, default="")
    expected_detection: Mapped[str] = mapped_column(Text, default="")
    template_id: Mapped[int | None] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(String(64))
    created_by_red_team: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    # red team part
    exec_status: Mapped[TestStatus] = mapped_column(
        _enum(TestStatus, "test_status"), default=TestStatus.not_run
    )
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    red_notes: Mapped[str] = mapped_column(Text, default="")
    red_by: Mapped[str | None] = mapped_column(String(64))
    red_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # blue team part
    outcome: Mapped[TestOutcome | None] = mapped_column(_enum(TestOutcome, "test_outcome"))
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    blue_notes: Mapped[str] = mapped_column(Text, default="")
    blue_by: Mapped[str | None] = mapped_column(String(64))
    blue_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # three parts that can conflict on their own: the definition, the red and the blue fields
    version: Mapped[int] = mapped_column(Integer, default=1)
    red_version: Mapped[int] = mapped_column(Integer, default=1)
    blue_version: Mapped[int] = mapped_column(Integer, default=1)

    campaign: Mapped[Campaign | None] = relationship(back_populates="tests")
    rules: Mapped[list["TestRule"]] = relationship(
        back_populates="test", cascade="all, delete-orphan", order_by="TestRule.id"
    )
    attachments: Mapped[list["TestAttachment"]] = relationship(
        back_populates="test", cascade="all, delete-orphan", order_by="TestAttachment.id"
    )
    rounds: Mapped[list["TestRound"]] = relationship(
        back_populates="test", cascade="all, delete-orphan", order_by="TestRound.number"
    )
    events: Mapped[list["TestEvent"]] = relationship(
        back_populates="test", cascade="all, delete-orphan", order_by="TestEvent.id"
    )


class TestRule(Base):
    """The link of a test to an L3 rule with the scopes the test covers for that rule."""

    __test__ = False
    __tablename__ = "test_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    test_id: Mapped[int] = mapped_column(
        ForeignKey("test_cases.id", ondelete="CASCADE"), index=True
    )
    l3_id: Mapped[int | None] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="SET NULL"), index=True
    )
    # kept when the rule is deleted ("Rule deleted: CODE")
    rule_code: Mapped[str] = mapped_column(String(64))
    rule_name: Mapped[str] = mapped_column(String(255), default="")
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)

    test: Mapped[TestCase] = relationship(back_populates="rules")


class TestAttachment(Base):
    __test__ = False
    __tablename__ = "test_attachments"

    id: Mapped[int] = mapped_column(primary_key=True)
    test_id: Mapped[int] = mapped_column(
        ForeignKey("test_cases.id", ondelete="CASCADE"), index=True
    )
    side: Mapped[str] = mapped_column(String(8))  # red | blue
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(128))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    data: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
    uploaded_by: Mapped[str] = mapped_column(String(64))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # the round the file belongs to (PROJ-4)
    round_id: Mapped[int | None] = mapped_column(
        ForeignKey("test_rounds.id", ondelete="SET NULL"), index=True
    )

    test: Mapped[TestCase] = relationship(back_populates="attachments")


class GapAcceptance(Base):
    """A gap from a test that an analyst accepted with a reason (it stays in the history)."""

    __tablename__ = "gap_acceptances"

    id: Mapped[int] = mapped_column(primary_key=True)
    l3_id: Mapped[int | None] = mapped_column(
        ForeignKey("l3_use_cases.id", ondelete="CASCADE"), index=True
    )
    technique: Mapped[str] = mapped_column(String(32))
    scope: Mapped[str] = mapped_column(String(128), default="")
    # the test whose result is accepted; a later test starts the question again
    test_id: Mapped[int] = mapped_column(ForeignKey("test_cases.id", ondelete="CASCADE"))
    reason: Mapped[str] = mapped_column(Text)
    accepted_by: Mapped[str] = mapped_column(String(64))
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TestRound(Base):
    """One attempt of a test: the red team's execution and the blue team's result (PROJ-4)."""

    __test__ = False
    __tablename__ = "test_rounds"
    __table_args__ = (UniqueConstraint("test_id", "number"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    test_id: Mapped[int] = mapped_column(
        ForeignKey("test_cases.id", ondelete="CASCADE"), index=True
    )
    number: Mapped[int] = mapped_column(Integer)
    opened_by: Mapped[str] = mapped_column(String(64))
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # red team
    exec_status: Mapped[TestStatus] = mapped_column(
        _enum(TestStatus, "test_status"), default=TestStatus.not_run
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    executed_what: Mapped[str] = mapped_column(Text, default="")
    red_notes: Mapped[str] = mapped_column(Text, default="")
    red_by: Mapped[str | None] = mapped_column(String(64))
    red_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # blue team
    outcome: Mapped[TestOutcome | None] = mapped_column(_enum(TestOutcome, "test_outcome"))
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    blue_notes: Mapped[str] = mapped_column(Text, default="")
    blue_by: Mapped[str | None] = mapped_column(String(64))
    blue_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    red_version: Mapped[int] = mapped_column(Integer, default=1)
    blue_version: Mapped[int] = mapped_column(Integer, default=1)

    test: Mapped[TestCase] = relationship(back_populates="rounds")
    detections: Mapped[list["RoundDetection"]] = relationship(
        back_populates="round", cascade="all, delete-orphan", order_by="RoundDetection.id"
    )


class RoundDetection(Base):
    """What detected the attack in a round: an entry of the list "Detection technologies"."""

    __tablename__ = "round_detections"

    id: Mapped[int] = mapped_column(primary_key=True)
    round_id: Mapped[int] = mapped_column(
        ForeignKey("test_rounds.id", ondelete="CASCADE"), index=True
    )
    item_id: Mapped[int | None] = mapped_column(
        ForeignKey("reference_items.id", ondelete="SET NULL"), index=True
    )
    # kept when the entry is deleted from the list (shown as plain text then)
    name: Mapped[str] = mapped_column(String(255))

    round: Mapped[TestRound] = relationship(back_populates="detections")
    item: Mapped[ReferenceItem | None] = relationship()


class TestEvent(Base):
    """The history of a test: comments of both sides and automatic entries (PROJ-4)."""

    __test__ = False
    __tablename__ = "test_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    test_id: Mapped[int] = mapped_column(
        ForeignKey("test_cases.id", ondelete="CASCADE"), index=True
    )
    round_number: Mapped[int | None] = mapped_column(Integer)
    # comment | round_opened | round_deleted | execution | result | result_changed | file_added
    # | file_removed | campaign_status | collaboration | comment_removed
    kind: Mapped[str] = mapped_column(String(32))
    side: Mapped[str] = mapped_column(String(8))  # red | blue | system
    author: Mapped[str] = mapped_column(String(64))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    text: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    removed_by: Mapped[str | None] = mapped_column(String(64))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    test: Mapped[TestCase] = relationship(back_populates="events")
