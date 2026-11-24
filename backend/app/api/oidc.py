"""SSO login via OpenID Connect, authorization code flow with PKCE (docs/PLAN.md section 5a).

Works with any standard IdP (Entra ID, Keycloak, Okta, ADFS, Authentik ...). Users are created
on first login. Their role comes from a group/role claim mapped with OIDC_ROLE_MAP and is
updated on every login, so the IdP stays the source of truth.
"""

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from app import audit
from app.api.deps import DB, SettingsDep
from app.config import Settings
from app.models import AuthSource, Role, User
from app.security import SESSION_COOKIE, create_session

log = logging.getLogger("magma.oidc")
router = APIRouter(prefix="/auth/oidc", tags=["auth"])

STATE_COOKIE = "magma_oidc"
STATE_TTL = 600
ROLE_RANK = {Role.admin: 3, Role.analyst: 2, Role.auditor: 1}
_discovery: dict[str, tuple[float, dict]] = {}


class SsoError(Exception):
    """A failed SSO sign-in. Only `code` reaches the browser (the login page maps it to a fixed
    text); `detail` goes to the log, so nobody can put their own text on the login page."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


# Codes the login page knows (frontend/src/pages/Login.tsx SSO_ERRORS).
SSO_ERROR_CODES = {
    "unreachable",
    "rejected",
    "invalid_token",
    "local_account",
    "name_taken",
    "disabled",
    "no_access",
    "cancelled",
    "expired",
}


def http_client() -> httpx.Client:
    """Replaced in tests with a client that talks to a fake IdP."""
    return httpx.Client(timeout=10, follow_redirects=False)


def parse_role_map(raw: str) -> dict[str, Role]:
    out: dict[str, Role] = {}
    for part in raw.split(","):
        if "=" not in part:
            continue
        group, role = (x.strip() for x in part.rsplit("=", 1))
        if group and role in Role.__members__ and role != Role.red_team:
            out[group] = Role(role)
        elif group:
            log.warning("OIDC_ROLE_MAP: unknown role %r for group %r", role, group)
    return out


def claim_values(claims: dict, path: str) -> list[str]:
    """Values of a claim; dotted paths reach nested claims (e.g. realm_access.roles)."""
    v: Any = claims
    for key in path.split("."):
        v = v.get(key) if isinstance(v, dict) else None
    if v is None:
        return []
    if isinstance(v, str):
        return [x for x in v.replace(",", " ").split() if x]
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def map_role(claims: dict, settings: Settings) -> Role | None:
    mapping = parse_role_map(settings.oidc_role_map)
    groups = claim_values(claims, settings.oidc_role_claim)
    roles = [mapping[g] for g in groups if g in mapping]
    if roles:
        return max(roles, key=ROLE_RANK.__getitem__)
    d = (settings.oidc_default_role or "").strip()
    return Role(d) if d in Role.__members__ and d != Role.red_team else None


def discover(settings: Settings) -> dict:
    issuer = settings.oidc_issuer.rstrip("/")
    cached = _discovery.get(issuer)
    if cached and cached[0] > time.time():
        return cached[1]
    with http_client() as c:
        r = c.get(f"{issuer}/.well-known/openid-configuration")
    if r.status_code != 200:
        raise SsoError("unreachable", f"Identity provider discovery failed ({r.status_code})")
    meta = r.json()
    _discovery[issuer] = (time.time() + 3600, meta)
    return meta


def _sign(payload: dict, key: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    mac = hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def _unsign(value: str | None, key: str) -> dict | None:
    if not value or "." not in value:
        return None
    body, mac = value.rsplit(".", 1)
    good = hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, good):
        return None
    data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    return data if data.get("exp", 0) > time.time() else None


def redirect_uri(settings: Settings) -> str:
    return settings.base_url.rstrip("/") + "/api/auth/oidc/callback"


def _safe_next(target: str | None) -> str:
    return target if target and target.startswith("/") and not target.startswith("//") else "/"


def _fail(code: str) -> RedirectResponse:
    code = code if code in SSO_ERROR_CODES else "rejected"
    resp = RedirectResponse("/login?" + urlencode({"sso_error": code}), status_code=303)
    resp.delete_cookie(STATE_COOKIE, path="/api/auth/oidc")
    return resp


@router.get("/login")
def oidc_login(settings: SettingsDep, next: str = "/") -> RedirectResponse:  # noqa: A002
    if not settings.sso_enabled:
        raise HTTPException(404, "SSO is not configured")
    try:
        meta = discover(settings)
    except (SsoError, httpx.HTTPError) as e:
        log.warning("OIDC discovery failed: %s", e)
        return _fail("unreachable")
    state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": redirect_uri(settings),
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    resp = RedirectResponse(f"{meta['authorization_endpoint']}?{urlencode(params)}", 303)
    cookie = _sign(
        {
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "next": _safe_next(next),
            "exp": time.time() + STATE_TTL,
        },
        settings.secret_key,
    )
    # Lax, not Strict: the browser must send it on the redirect back from the IdP.
    resp.set_cookie(
        STATE_COOKIE,
        cookie,
        max_age=STATE_TTL,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/api/auth/oidc",
    )
    return resp


def _exchange(settings: Settings, meta: dict, code: str, verifier: str) -> dict:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(settings),
        "code_verifier": verifier,
    }
    methods = meta.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    auth = None
    if settings.oidc_client_secret and "client_secret_basic" in methods:
        auth = (settings.oidc_client_id, settings.oidc_client_secret)
    else:
        data["client_id"] = settings.oidc_client_id
        if settings.oidc_client_secret:
            data["client_secret"] = settings.oidc_client_secret
    with http_client() as c:
        r = c.post(meta["token_endpoint"], data=data, auth=auth)
    if r.status_code != 200:
        log.warning("OIDC token exchange failed: %s %s", r.status_code, r.text[:300])
        raise SsoError("rejected", f"Token exchange failed ({r.status_code})")
    return r.json()


def _validate_id_token(settings: Settings, meta: dict, token: str, nonce: str) -> dict:
    with http_client() as c:
        r = c.get(meta["jwks_uri"])
    if r.status_code != 200:
        raise SsoError("invalid_token", "Could not load the identity provider's signing keys")
    keys = jwt.PyJWKSet.from_dict(r.json())
    header = jwt.get_unverified_header(token)
    key = next((k for k in keys.keys if k.key_id == header.get("kid")), None)
    if key is None and len(keys.keys) == 1:
        key = keys.keys[0]
    if key is None:
        raise SsoError("invalid_token", "Unknown signing key in the ID token")
    algs = meta.get("id_token_signing_alg_values_supported") or ["RS256"]
    try:
        claims = jwt.decode(
            token,
            key.key,
            algorithms=[a for a in algs if a != "none"],
            audience=settings.oidc_client_id,
            issuer=meta.get("issuer", settings.oidc_issuer),
            leeway=60,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as e:
        raise SsoError("invalid_token", f"Invalid ID token: {e}") from e
    if claims.get("nonce") != nonce:
        raise SsoError("invalid_token", "Invalid ID token: nonce mismatch")
    return claims


def _userinfo(meta: dict, access_token: str | None) -> dict:
    if not access_token or not meta.get("userinfo_endpoint"):
        return {}
    with http_client() as c:
        r = c.get(meta["userinfo_endpoint"], headers={"Authorization": f"Bearer {access_token}"})
    return r.json() if r.status_code == 200 else {}


def sso_username(raw: object) -> str:
    """The same characters local user names may use (it also ends up as a git author name)."""
    name = re.sub(r"[^A-Za-z0-9._@-]+", "_", str(raw)).strip("_")[:64]
    if len(name) < 2:
        name = ("sso_" + hashlib.sha256(str(raw).encode()).hexdigest())[:16]
    return name


def _upsert_user(db, settings: Settings, claims: dict, role: Role) -> User:
    subject = f"{claims['iss']}|{claims['sub']}"
    username = sso_username(
        claims.get(settings.oidc_username_claim)
        or claims.get("preferred_username")
        or claims.get("email")
        or claims["sub"]
    )
    user = db.scalar(select(User).where(User.sso_subject == subject))
    if user is None:
        clash = db.scalar(select(User).where(User.username == username))
        if clash is not None:
            if clash.auth_source == AuthSource.local:
                raise SsoError("local_account", f"user name {username!r} is a local account")
            raise SsoError("name_taken", f"user name {username!r} is used by another SSO account")
        user = User(
            username=username,
            auth_source=AuthSource.sso,
            sso_subject=subject,
            role=role,
            active=True,
            display_name="",
        )
        db.add(user)
        audit.record(db, None, "create", "user", username, {"source": "sso", "role": role.value})
    if not user.active:
        raise SsoError("disabled", f"account {user.username!r} is disabled")
    if user.role != role:
        audit.record(db, None, "update", "user", user.username, {"role": [user.role, role]})
        user.role = role
    user.display_name = str(claims.get("name") or user.display_name or username)[:128]
    user.email = claims.get("email") or user.email
    user.last_login_at = datetime.now(UTC)
    return user


@router.get("/callback")
def oidc_callback(request: Request, db: DB, settings: SettingsDep) -> RedirectResponse:
    if not settings.sso_enabled:
        raise HTTPException(404, "SSO is not configured")
    q = request.query_params
    if q.get("error"):
        log.info("OIDC sign-in returned error %r", q.get("error"))
        return _fail("cancelled")
    saved = _unsign(request.cookies.get(STATE_COOKIE), settings.secret_key)
    if not saved or not q.get("state") or not hmac.compare_digest(saved["state"], q["state"]):
        return _fail("expired")
    try:
        meta = discover(settings)
        tokens = _exchange(settings, meta, q.get("code", ""), saved["verifier"])
        claims = _validate_id_token(settings, meta, tokens.get("id_token", ""), saved["nonce"])
        if not claim_values(claims, settings.oidc_role_claim):
            claims = _userinfo(meta, tokens.get("access_token")) | claims
        role = map_role(claims, settings)
        if role is None:
            log.info("OIDC login refused for %s: no mapped group", claims.get("sub"))
            raise SsoError("no_access", "no matching group")
        user = _upsert_user(db, settings, claims, role)
        db.flush()
        token = create_session(db, user, settings, hours=settings.sso_session_hours)
        audit.record(db, user, "login", "user", user.username, {"source": "sso"})
        db.commit()
    except SsoError as e:
        db.rollback()
        log.info("OIDC sign-in refused (%s): %s", e.code, e.detail)
        return _fail(e.code)
    except httpx.HTTPError as e:
        db.rollback()
        log.warning("OIDC request failed: %s", e)
        return _fail("unreachable")

    resp = RedirectResponse(saved["next"], status_code=303)
    resp.delete_cookie(STATE_COOKIE, path="/api/auth/oidc")
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.sso_session_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return resp
