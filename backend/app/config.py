import logging
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET_KEY_LENGTH = 32
WEAK_SECRET_KEYS = {"change-me", "changeme", "secret", "magma"}


class WeakSecretKey(RuntimeError):
    pass


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables (see .env.example)."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vulcan UCF"
    database_url: str = "sqlite:////data/magma.db"
    # PostgreSQL connection pool and limits (ignored for SQLite).
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_recycle: int = 1800
    db_statement_timeout_ms: int = 0
    # How long startup waits for the database to accept connections.
    db_wait_seconds: int = 60
    # Encrypts TOTP seeds and signs the SSO state cookie. Startup refuses a missing, default or
    # short key unless ALLOW_WEAK_SECRET_KEY=true (local development only).
    secret_key: str = ""
    allow_weak_secret_key: bool = False
    base_url: str = "http://localhost:8080"
    # Directory with the built frontend (index.html + assets). Empty or missing = API only.
    static_dir: Path = Path(__file__).resolve().parent.parent / "static"

    # Run migrations and seed the catalogue on startup.
    auto_migrate: bool = True

    # First admin account, created when the user table is empty.
    admin_user: str = "admin"
    admin_password: str | None = None

    local_login_enabled: bool = True
    session_hours: int = 12
    # SSO sessions are shorter: the app only learns at the next sign-in that someone lost access
    # at the identity provider.
    sso_session_hours: int = 8
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    min_password_length: int = 12
    # Failed sign-ins per client address before /auth/login answers 429 (0 = off).
    login_ip_max_failures: int = 20
    login_ip_window_minutes: int = 15

    # Verification interval used when a rule has no own interval.
    default_verification_days: int = 180

    # Target implementation per risk level when a use case sets no own target (app/priorities.py).
    risk_targets: str = "1=0.4,2=0.5,3=0.6,4=0.75,5=0.9"

    # A business or compliance driver whose linked use cases score below this average weight is
    # listed as "low coverage" on the Priorities page and in the report (app/drivers.py).
    driver_low_coverage: float = 0.3

    # Fill the catalogue with generated demo data on first start (see app/demo.py).
    demo_data: bool = False
    demo_seed: int = 42
    # "Load demo data" (admin, Import / Export page) replaces metrics and deletes the verification,
    # lifecycle and config history, so it is refused unless this or DEMO_DATA is on.
    allow_demo_data: bool = False

    # Automatic snapshots for trend charts: off | daily | weekly | monthly (app/snapshots.py).
    snapshot_schedule: str = "monthly"

    # Optional git repository for the JSON configs (app/gitsync.py). Off when the URL is empty.
    git_remote_url: str = ""
    git_branch: str = "main"
    git_username: str = "magma"
    git_token: str | None = None
    git_ssh_key_file: str | None = None
    git_workdir: Path = Path("/data/git-repo")
    git_author_email_domain: str = "magma.local"
    # Push automatically after each config commit and tag (in the background).
    git_auto_sync: bool = True
    # Two-way sync: also read config changes made directly in the repository back into the app.
    git_pull: bool = False
    # How often to look for changes in the repository (minutes, 0 = only via webhook / by hand).
    git_pull_interval_minutes: int = 5
    # Shared secret for POST /api/git/webhook (GitHub, Gitea, GitLab push events). Empty = off.
    git_webhook_secret: str | None = None

    # SSO via OpenID Connect (see app/oidc.py). Enabled when issuer and client id are set.
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: str = "openid profile email"
    # Claim with the user's groups or roles, e.g. "groups" or "roles".
    oidc_role_claim: str = "groups"
    # IdP group -> app role, e.g. "SOC-Admins=admin,SOC-Analysts=analyst,Audit=auditor".
    oidc_role_map: str = ""
    # Role for users without a matching group; empty = no access.
    oidc_default_role: str | None = None
    oidc_username_claim: str = "preferred_username"
    oidc_button_label: str = "Sign in with SSO"

    # Largest request body (uploads are capped at 20 MB on their own).
    max_body_mb: int = 25
    # Total size of all interview evidence files in the database (#47); 0 = no limit.
    evidence_max_total_mb: int = 2048

    @property
    def demo_data_allowed(self) -> bool:
        return self.demo_data or self.allow_demo_data

    @property
    def sso_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)

    @property
    def risk_target_map(self) -> dict[int, float]:
        from app.priorities import parse_risk_targets

        return parse_risk_targets(self.risk_targets)

    @property
    def git_enabled(self) -> bool:
        return bool(self.git_remote_url)

    @property
    def secret_key_problem(self) -> str | None:
        key = self.secret_key.strip()
        if not key:
            return "SECRET_KEY is not set"
        if key.lower() in WEAK_SECRET_KEYS:
            return "SECRET_KEY still has the example value"
        if len(key) < MIN_SECRET_KEY_LENGTH:
            return f"SECRET_KEY is shorter than {MIN_SECRET_KEY_LENGTH} characters"
        return None

    @property
    def cookie_secure(self) -> bool:
        return self.base_url.startswith("https://")


def check_secret_key(settings: "Settings") -> None:
    """Refuse to run with a guessable key: it protects the TOTP seeds in the database."""
    problem = settings.secret_key_problem
    if problem is None:
        return
    hint = 'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
    if settings.allow_weak_secret_key:
        logging.getLogger("magma.config").warning(
            "%s; running anyway because ALLOW_WEAK_SECRET_KEY is set. %s", problem, hint
        )
        return
    raise WeakSecretKey(f"{problem}. {hint}")


@lru_cache
def get_settings() -> Settings:
    return Settings()
