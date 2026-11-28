"""Where the SSO settings come from (docs/PLAN.md section 5a, login flow in app/api/oidc.py).

Admins set up SSO in the app (Administration → Single sign-on). The settings live in
app_settings key `sso`; the client secret is stored encrypted with SECRET_KEY. When OIDC_ISSUER is
set in the environment, the OIDC_* variables apply instead and the page only shows them, so
existing deployments and setups kept in infrastructure code keep working.
"""

import base64
import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Annotated, Literal
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AppSetting, Role

log = logging.getLogger("magma.oidc")

SSO = "sso"  # app_settings key of the settings
SSO_TEST = "sso_test"  # app_settings key of the last test sign-in (admins only)
ENTRA_LOGIN = "https://login.microsoftonline.com"
# Entra ID endpoints that accept accounts of any tenant: never what a company wants.
MULTI_TENANT = {"common", "organizations", "consumers"}
TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
SSO_ROLES = ("admin", "analyst", "auditor")  # red team accounts are local only
DEFAULT_SCOPES = {"entra": "openid profile email User.Read", "oidc": "openid profile email"}
DEFAULT_ROLE_CLAIM = {"entra": "roles", "oidc": "groups"}

SsoRole = Literal["admin", "analyst", "auditor"]
Short = Annotated[str, StringConstraints(strip_whitespace=True, max_length=255)]


class RoleMapping(BaseModel):
    """A group or role value the IdP sends, and the app role it gives."""

    value: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
    role: SsoRole


class SsoSettings(BaseModel):
    """What an admin sets on the page. The client secret is stored on its own (encrypted)."""

    enabled: bool = False
    provider: Literal["entra", "oidc"] = "entra"
    # Entra ID: the directory (tenant) id or a verified domain; other IdPs: the issuer URL
    tenant_id: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253)] = ""
    issuer: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] = ""
    client_id: Short = ""
    scopes: Short = DEFAULT_SCOPES["entra"]
    role_claim: Short = DEFAULT_ROLE_CLAIM["entra"]
    role_map: list[RoleMapping] = Field(default_factory=list, max_length=200)
    default_role: SsoRole | None = None
    username_claim: Short = "preferred_username"
    # empty = "Sign in with Microsoft" / "Sign in with SSO" in the user's language
    button_label: Annotated[str, StringConstraints(strip_whitespace=True, max_length=80)] = ""

    def issuer_url(self) -> str:
        if self.provider == "entra":
            return f"{ENTRA_LOGIN}/{self.tenant_id}/v2.0" if self.tenant_id else ""
        return self.issuer.rstrip("/")


@dataclass(frozen=True)
class OidcConfig:
    """The SSO settings in effect, from the environment or from the app."""

    source: Literal["env", "app"]
    enabled: bool
    provider: Literal["entra", "oidc"]
    issuer: str
    client_id: str
    client_secret: str | None
    scopes: str
    role_claim: str
    role_map: dict[str, Role]
    default_role: Role | None
    username_claim: str
    button_label: str

    @property
    def configured(self) -> bool:
        return bool(self.issuer and self.client_id)


def parse_role_map(raw: str) -> dict[str, Role]:
    """OIDC_ROLE_MAP: "SOC-Admins=admin,SOC-Analysts=analyst" (the group may contain "=")."""
    out: dict[str, Role] = {}
    for part in raw.split(","):
        if "=" not in part:
            continue
        group, role = (x.strip() for x in part.rsplit("=", 1))
        if group and role in SSO_ROLES:
            out[group] = Role(role)
        elif group:
            log.warning("OIDC_ROLE_MAP: unknown role %r for group %r", role, group)
    return out


def is_entra(issuer: str) -> bool:
    return urlparse(issuer).hostname == urlparse(ENTRA_LOGIN).hostname


def from_env(settings: Settings) -> OidcConfig:
    default = (settings.oidc_default_role or "").strip()
    issuer = (settings.oidc_issuer or "").rstrip("/")
    return OidcConfig(
        source="env",
        enabled=settings.sso_enabled,
        provider="entra" if is_entra(issuer) else "oidc",
        issuer=issuer,
        client_id=settings.oidc_client_id or "",
        client_secret=settings.oidc_client_secret or None,
        scopes=settings.oidc_scopes,
        role_claim=settings.oidc_role_claim,
        role_map=parse_role_map(settings.oidc_role_map),
        default_role=Role(default) if default in SSO_ROLES else None,
        username_claim=settings.oidc_username_claim,
        button_label=settings.oidc_button_label,
    )


def from_app(s: SsoSettings, client_secret: str | None) -> OidcConfig:
    issuer = s.issuer_url()
    return OidcConfig(
        source="app",
        enabled=s.enabled and bool(issuer and s.client_id),
        provider=s.provider,
        issuer=issuer,
        client_id=s.client_id,
        client_secret=client_secret or None,
        scopes=s.scopes or DEFAULT_SCOPES[s.provider],
        role_claim=s.role_claim or DEFAULT_ROLE_CLAIM[s.provider],
        role_map={m.value: Role(m.role) for m in s.role_map},
        default_role=Role(s.default_role) if s.default_role else None,
        username_claim=s.username_claim or "preferred_username",
        button_label=s.button_label,
    )


def env_managed(settings: Settings) -> bool:
    return bool(settings.oidc_issuer)


def load(db: Session) -> tuple[SsoSettings, AppSetting | None]:
    row = db.get(AppSetting, SSO)
    return (SsoSettings.model_validate(row.value) if row else SsoSettings()), row


def effective(db: Session, settings: Settings) -> OidcConfig:
    if env_managed(settings):
        return from_env(settings)
    s, row = load(db)
    return from_app(s, stored_secret(row, settings.secret_key)[0])


# ---------------------------------------------------------------- client secret at rest


def _fernet(secret_key: str) -> Fernet:
    key = hashlib.sha256(b"magma-sso:" + secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(secret: str, secret_key: str) -> str:
    return _fernet(secret_key).encrypt(secret.encode()).decode()


def decrypt_secret(token: str, secret_key: str) -> str | None:
    try:
        return _fernet(secret_key).decrypt(token.encode()).decode()
    except InvalidToken:
        return None


SecretStatus = Literal["set", "unset", "unreadable"]


def stored_secret(row: AppSetting | None, secret_key: str) -> tuple[str | None, SecretStatus]:
    """The stored client secret. "unreadable" when SECRET_KEY changed without rotate-secret."""
    token = (row.value or {}).get("client_secret") if row else None
    if not token:
        return None, "unset"
    secret = decrypt_secret(token, secret_key)
    if secret is None:
        log.warning("The stored SSO client secret cannot be decrypted (SECRET_KEY changed?)")
        return None, "unreadable"
    return secret, "set"


def reencrypt(db: Session, old_key: str, new_key: str) -> bool | None:
    """Re-encrypt the client secret after SECRET_KEY changed (magma rotate-secret).
    True = done, False = nothing to do, None = it cannot be read with the old key either."""
    row = db.get(AppSetting, SSO)
    token = (row.value or {}).get("client_secret") if row else None
    if not token or decrypt_secret(token, new_key) is not None:
        return False
    secret = decrypt_secret(token, old_key)
    if secret is None:
        return None
    row.value = {**row.value, "client_secret": encrypt_secret(secret, new_key)}
    return True
