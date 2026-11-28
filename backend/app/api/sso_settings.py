"""Administration → Single sign-on: SSO settings set in the app (app/sso.py), admins only.

GET shows the settings in effect (from the app or, read-only, from the OIDC_* variables) with the
values the IAM team needs. PUT saves them; the client secret is write-only. POST /check tests the
connection with the values in the form before they are saved. GET /test is the result of the last
test sign-in (started with GET /api/auth/oidc/test).
"""

from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, StringConstraints

from app import audit, sso
from app.api import oidc
from app.api.deps import DB, SettingsDep
from app.config import Settings
from app.models import AppSetting
from app.security import Admin
from app.sso import RoleMapping, SsoSettings

router = APIRouter(prefix="/settings/sso", tags=["settings"])

ENV_MANAGED = "SSO is set in the environment (OIDC_* variables); change it there"
Secret = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)]


class SsoSettingsIn(SsoSettings):
    client_secret: Secret | None = None  # None keeps the stored secret, "" removes it


class SsoSettingsOut(SsoSettings):
    source: Literal["env", "app"]
    client_secret_status: sso.SecretStatus
    redirect_uri: str
    login_url: str
    base_url: str
    updated_at: datetime | None = None
    updated_by: str | None = None


class SsoCheckItem(BaseModel):
    key: str
    status: Literal["ok", "warn", "fail"]
    detail: str = ""
    params: dict[str, str] = {}


class SsoTestOut(BaseModel):
    at: datetime
    by: str
    ok: bool
    error: str | None = None
    detail: str = ""
    issuer: str = ""
    role_claim: str = ""
    claims: dict[str, Any] = {}
    groups_from: str | None = None
    values: list[str] = []
    matched: list[str] = []
    role: str | None = None
    username: str | None = None
    account: str | None = None


def _out(db, settings: Settings) -> SsoSettingsOut:
    urls = {
        "redirect_uri": oidc.redirect_uri(settings),
        "login_url": settings.base_url.rstrip("/") + "/login",
        "base_url": settings.base_url,
    }
    if sso.env_managed(settings):
        cfg = sso.from_env(settings)
        entra = cfg.provider == "entra"
        return SsoSettingsOut(
            source="env",
            enabled=cfg.enabled,
            provider=cfg.provider,
            tenant_id=urlparse(cfg.issuer).path.strip("/").split("/")[0] if entra else "",
            issuer=cfg.issuer,
            client_id=cfg.client_id,
            scopes=cfg.scopes,
            role_claim=cfg.role_claim,
            role_map=[RoleMapping(value=k[:256], role=v.value) for k, v in cfg.role_map.items()],
            default_role=cfg.default_role.value if cfg.default_role else None,
            username_claim=cfg.username_claim,
            button_label=cfg.button_label[:80],
            client_secret_status="set" if cfg.client_secret else "unset",
            **urls,
        )
    s, row = sso.load(db)
    return SsoSettingsOut(
        **s.model_dump(),
        source="app",
        client_secret_status=sso.stored_secret(row, settings.secret_key)[1],
        updated_at=row.updated_at if row else None,
        updated_by=row.updated_by if row else None,
        **urls,
    )


def _validate(s: SsoSettings, settings: Settings) -> None:
    if s.provider == "entra":
        if s.tenant_id.lower() in sso.MULTI_TENANT:
            raise HTTPException(
                422,
                "Enter your own tenant ID: common, organizations and consumers let in "
                "accounts of any tenant",
            )
        if s.tenant_id and not sso.TENANT.match(s.tenant_id):
            raise HTTPException(
                422, "The tenant ID is a GUID or a domain such as contoso.onmicrosoft.com"
            )
    elif s.issuer:
        u = urlparse(s.issuer)
        # plain http only while the app itself runs on http (a local test IdP)
        if (
            not u.hostname
            or u.scheme not in ("https", "http")
            or (u.scheme == "http" and settings.cookie_secure)
            or u.query
            or u.fragment
        ):
            raise HTTPException(422, "The issuer must be an https:// URL")
    if "openid" not in s.scopes.split():
        raise HTTPException(422, "The scopes must include openid")
    values = [m.value for m in s.role_map]
    dupes = sorted({v for v in values if values.count(v) > 1})
    if dupes:
        raise HTTPException(422, f"{dupes[0]} is mapped twice")
    if s.enabled:
        if not (s.issuer_url() and s.client_id):
            raise HTTPException(
                422, "Enter the tenant ID or issuer and the client ID before turning SSO on"
            )
        if not s.role_map and not s.default_role:
            raise HTTPException(
                422, "Map at least one group or role, or set a default role, before turning SSO on"
            )


def _secret_mark(token: str | None) -> str:
    return "set" if token else "not set"


@router.get("", response_model=SsoSettingsOut)
def get_sso(_: Admin, db: DB, settings: SettingsDep) -> SsoSettingsOut:
    return _out(db, settings)


@router.put("", response_model=SsoSettingsOut)
def put_sso(body: SsoSettingsIn, user: Admin, db: DB, settings: SettingsDep) -> SsoSettingsOut:
    if sso.env_managed(settings):
        raise HTTPException(409, ENV_MANAGED)
    new = SsoSettings.model_validate(body.model_dump(exclude={"client_secret"}))
    _validate(new, settings)
    old, row = sso.load(db)
    old_token = (row.value or {}).get("client_secret") if row else None
    token = old_token
    if body.client_secret is not None:
        secret = body.client_secret
        token = sso.encrypt_secret(secret, settings.secret_key) if secret else None
    value = new.model_dump()
    if token:
        value["client_secret"] = token
    changes = audit.diff(old.model_dump(), new.model_dump())
    if token != old_token:  # never the secret itself
        changes["client_secret"] = [_secret_mark(old_token), "changed" if token else "removed"]
    if row is None:
        db.add(AppSetting(key=sso.SSO, value=value, updated_by=user.username))
    else:
        row.value, row.updated_by = value, user.username
    audit.record(db, user, "update", "settings", sso.SSO, changes)
    db.commit()
    return _out(db, settings)


@router.post("/check", response_model=list[SsoCheckItem])
def check_sso(body: SsoSettingsIn, _: Admin, db: DB, settings: SettingsDep) -> list[dict]:
    """Test the connection with the values in the form (not saved yet). Without a new client
    secret in the form the stored one is used."""
    if sso.env_managed(settings):
        cfg = sso.from_env(settings)
    else:
        new = SsoSettings.model_validate(body.model_dump(exclude={"client_secret"}))
        _validate(new.model_copy(update={"enabled": False}), settings)
        if body.client_secret is None:
            secret = sso.stored_secret(sso.load(db)[1], settings.secret_key)[0]
        else:
            secret = body.client_secret
        cfg = sso.from_app(new, secret)
    if not cfg.configured:
        raise HTTPException(422, "Enter the tenant ID or issuer and the client ID first")
    return oidc.check_connection(cfg, settings)


@router.get("/test", response_model=SsoTestOut | None)
def last_test(_: Admin, db: DB) -> dict | None:
    row = db.get(AppSetting, sso.SSO_TEST)
    return row.value if row else None
