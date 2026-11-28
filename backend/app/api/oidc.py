"""SSO login via OpenID Connect, authorization code flow with PKCE (docs/PLAN.md section 5a).

Works with any standard IdP (Entra ID, Keycloak, Okta, ADFS, Authentik ...). The settings come
from Administration → Single sign-on or from the OIDC_* environment variables (app/sso.py).
Users are created on first login. Their role comes from a group/role claim mapped to app roles and
is updated on every login, so the IdP stays the source of truth.

Admins can run a test sign-in (/api/auth/oidc/test), also before SSO is turned on: it records
what the IdP sent and which role that gives, and creates neither an account nor a session.
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
from typing import Any, Literal
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, sso
from app.api.deps import DB, SettingsDep
from app.config import Settings
from app.models import AppSetting, AuthSource, Role, User
from app.security import SESSION_COOKIE, Admin, create_session
from app.sso import OidcConfig

log = logging.getLogger("magma.oidc")
router = APIRouter(prefix="/auth/oidc", tags=["auth"])

STATE_COOKIE = "magma_oidc"
STATE_TTL = 600
ROLE_RANK = {Role.admin: 3, Role.analyst: 2, Role.auditor: 1}
SSO_PAGE = "/admin/sso"  # the settings page, where a test sign-in returns to
_discovery: dict[str, tuple[float, dict]] = {}

# Microsoft Graph of each Entra ID cloud, by sign-in host (for the groups overage, _entra_groups).
ENTRA_GRAPH = {
    "login.microsoftonline.com": "https://graph.microsoft.com",
    "login.microsoftonline.us": "https://graph.microsoft.us",
    "login.partner.microsoftonline.cn": "https://microsoftgraph.chinacloudapi.cn",
}
GRAPH_BATCH = 20  # checkMemberGroups takes at most 20 group ids per call
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
# Opaque claims left out of the test sign-in result.
HIDDEN_CLAIMS = {"nonce", "aio", "rh", "uti", "at_hash", "c_hash", "_claim_sources"}


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


def map_role(claims: dict, cfg: OidcConfig) -> Role | None:
    roles = [cfg.role_map[g] for g in claim_values(claims, cfg.role_claim) if g in cfg.role_map]
    if roles:
        return max(roles, key=ROLE_RANK.__getitem__)
    return cfg.default_role


def discover(issuer: str, fresh: bool = False) -> dict:
    issuer = issuer.rstrip("/")
    cached = _discovery.get(issuer)
    if cached and cached[0] > time.time() and not fresh:
        return cached[1]
    with http_client() as c:
        r = c.get(f"{issuer}/.well-known/openid-configuration")
    if r.status_code != 200:
        raise SsoError("unreachable", f"Identity provider discovery failed ({r.status_code})")
    try:
        meta = r.json()
    except ValueError as e:
        raise SsoError("unreachable", "The discovery document is not JSON") from e
    missing = [
        k
        for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")
        if not isinstance(meta, dict) or not meta.get(k)
    ]
    if missing:
        raise SsoError("unreachable", "The discovery document has no " + ", ".join(missing))
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
    if not hmac.compare_digest(mac.encode(), good.encode()):
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


def _start(cfg: OidcConfig, settings: Settings, extra: dict) -> RedirectResponse:
    """Redirect to the IdP. Raises SsoError / httpx.HTTPError when it cannot be reached."""
    meta = discover(cfg.issuer)
    state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": redirect_uri(settings),
        "scope": cfg.scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if extra.get("test") and cfg.provider == "entra":
        params["prompt"] = "select_account"  # test with another account than the admin's own
    resp = RedirectResponse(f"{meta['authorization_endpoint']}?{urlencode(params)}", 303)
    exp = time.time() + STATE_TTL
    payload = {"state": state, "nonce": nonce, "verifier": verifier, "exp": exp} | extra
    cookie = _sign(payload, settings.secret_key)
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


@router.get("/login")
def oidc_login(db: DB, settings: SettingsDep, next: str = "/") -> RedirectResponse:  # noqa: A002
    cfg = sso.effective(db, settings)
    if not cfg.enabled:
        raise HTTPException(404, "SSO is not configured")
    try:
        return _start(cfg, settings, {"next": _safe_next(next)})
    except (SsoError, httpx.HTTPError) as e:
        log.warning("OIDC discovery failed: %s", e)
        return _fail("unreachable")


@router.get("/test")
def oidc_test(user: Admin, db: DB, settings: SettingsDep) -> RedirectResponse:
    """Test sign-in for admins. Works before SSO is turned on; creates no account."""
    cfg = sso.effective(db, settings)
    if not cfg.configured:
        raise HTTPException(409, "Save the tenant ID or issuer and the client ID first")
    try:
        return _start(cfg, settings, {"next": SSO_PAGE, "test": user.username})
    except (SsoError, httpx.HTTPError) as e:
        detail = e.detail if isinstance(e, SsoError) else str(e)
        return _test_done(db, user.username, cfg, {"ok": False, "error": "unreachable"}, detail)


def _client_auth(cfg: OidcConfig, meta: dict, data: dict) -> tuple[str, str] | None:
    """client_secret_basic when the IdP supports it, else the client id (and secret) in the form."""
    methods = meta.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    if cfg.client_secret and "client_secret_basic" in methods:
        return (cfg.client_id, cfg.client_secret)
    data["client_id"] = cfg.client_id
    if cfg.client_secret:
        data["client_secret"] = cfg.client_secret
    return None


def _exchange(cfg: OidcConfig, settings: Settings, meta: dict, code: str, verifier: str) -> dict:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(settings),
        "code_verifier": verifier,
    }
    auth = _client_auth(cfg, meta, data)
    with http_client() as c:
        r = c.post(meta["token_endpoint"], data=data, auth=auth)
    if r.status_code != 200:
        log.warning("OIDC token exchange failed: %s %s", r.status_code, r.text[:300])
        raise SsoError("rejected", f"Token exchange failed ({r.status_code}): {r.text[:300]}")
    return r.json()


def _validate_id_token(cfg: OidcConfig, meta: dict, token: str, nonce: str) -> dict:
    with http_client() as c:
        r = c.get(meta["jwks_uri"])
    if r.status_code != 200:
        raise SsoError("invalid_token", "Could not load the identity provider's signing keys")
    try:
        keys = jwt.PyJWKSet.from_dict(r.json())
        header = jwt.get_unverified_header(token)
    except (jwt.PyJWTError, ValueError) as e:
        raise SsoError("invalid_token", f"Invalid ID token or signing keys: {e}") from e
    key = next((k for k in keys.keys if k.key_id == header.get("kid")), None)
    if key is None and len(keys.keys) == 1:
        key = keys.keys[0]
    if key is None:
        raise SsoError("invalid_token", "Unknown signing key in the ID token")
    algs = meta.get("id_token_signing_alg_values_supported") or ["RS256"]
    issuer = meta.get("issuer", cfg.issuer)
    if "{tenantid}" in issuer:
        # .../common/v2.0 and .../organizations/v2.0 accept every Entra ID tenant in the world.
        raise SsoError(
            "invalid_token",
            "The issuer is the multi-tenant Entra ID endpoint; use your directory (tenant) id",
        )
    try:
        claims = jwt.decode(
            token,
            key.key,
            algorithms=[a for a in algs if a != "none"],
            audience=cfg.client_id,
            issuer=issuer,
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


def entra_graph(cfg: OidcConfig) -> str | None:
    """Microsoft Graph base URL when the issuer is Entra ID, else None."""
    return ENTRA_GRAPH.get(urlparse(cfg.issuer).hostname or "")


def entra_overage(claims: dict, cfg: OidcConfig) -> bool:
    """Entra ID leaves the groups out of the token when a user is in more than 200 groups and
    names them in _claim_names instead (hasgroups in the implicit flow)."""
    if entra_graph(cfg) is None:
        return False
    names = claims.get("_claim_names")
    if isinstance(names, dict) and cfg.role_claim in names:
        return True
    return cfg.role_claim == "groups" and claims.get("hasgroups") in (True, "true")


def _entra_groups(cfg: OidcConfig, access_token: str | None) -> list[str]:
    """Which of the mapped groups the user is in, asked from Microsoft Graph after an overage.

    The link in the token's _claim_sources points to the retired Azure AD Graph, so this calls
    Microsoft Graph's checkMemberGroups, which needs only the User.Read permission. That only
    works with group object ids in the role mapping, not with group names.
    """
    graph = entra_graph(cfg)
    ids = [g for g in cfg.role_map if GUID.match(g)]
    if not access_token or not ids:
        reason = "the role mapping has no group object ids" if not ids else "no access token"
        log.warning(
            "Entra ID left the groups out of the token (user in more than 200 groups) and %s. "
            "Map group object ids, or use app roles (role claim: roles)",
            reason,
        )
        return []
    found: list[str] = []
    with http_client() as c:
        for i in range(0, len(ids), GRAPH_BATCH):
            r = c.post(
                f"{graph}/v1.0/me/checkMemberGroups",
                json={"groupIds": ids[i : i + GRAPH_BATCH]},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if r.status_code != 200:
                log.warning(
                    "Microsoft Graph checkMemberGroups failed (%s), check that the scopes have "
                    "User.Read: %s",
                    r.status_code,
                    r.text[:300],
                )
                return []
            found += [str(g) for g in r.json().get("value", [])]
    return found


GroupsFrom = Literal["token", "userinfo", "microsoft_graph", "none"]


def _identify(
    cfg: OidcConfig, meta: dict, tokens: dict, nonce: str
) -> tuple[dict, Role | None, GroupsFrom]:
    """Claims of the signed-in person, their app role and where the groups/roles came from."""
    claims = _validate_id_token(cfg, meta, tokens.get("id_token", ""), nonce)
    source: GroupsFrom = "token"
    if not claim_values(claims, cfg.role_claim):
        if entra_overage(claims, cfg):
            groups = _entra_groups(cfg, tokens.get("access_token"))
            claims = claims | {cfg.role_claim: groups}
            source = "microsoft_graph"
        else:
            extra = _userinfo(meta, tokens.get("access_token"))
            claims = extra | claims
            source = "userinfo" if claim_values(extra, cfg.role_claim) else "none"
    return claims, map_role(claims, cfg), source


def sso_username(raw: object) -> str:
    """The same characters local user names may use (it also ends up as a git author name)."""
    name = re.sub(r"[^A-Za-z0-9._@-]+", "_", str(raw)).strip("_")[:64]
    if len(name) < 2:
        name = ("sso_" + hashlib.sha256(str(raw).encode()).hexdigest())[:16]
    return name


def _username(cfg: OidcConfig, claims: dict) -> str:
    return sso_username(
        claims.get(cfg.username_claim)
        or claims.get("preferred_username")
        or claims.get("email")
        or claims["sub"]
    )


def _find_user(db: Session, cfg: OidcConfig, claims: dict) -> tuple[User | None, str, str]:
    """The account of this SSO identity (None = new), its user name and subject. Refuses a name
    that belongs to a local account or another SSO account, and disabled accounts."""
    subject = f"{claims['iss']}|{claims['sub']}"
    username = _username(cfg, claims)
    user = db.scalar(select(User).where(User.sso_subject == subject))
    if user is None:
        clash = db.scalar(select(User).where(User.username == username))
        if clash is not None:
            if clash.auth_source == AuthSource.local:
                raise SsoError("local_account", f"user name {username!r} is a local account")
            raise SsoError("name_taken", f"user name {username!r} is used by another SSO account")
    elif not user.active:
        raise SsoError("disabled", f"account {user.username!r} is disabled")
    return user, username, subject


def _upsert_user(db: Session, cfg: OidcConfig, claims: dict, role: Role) -> User:
    user, username, subject = _find_user(db, cfg, claims)
    if user is None:
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
    if user.role != role:
        audit.record(db, None, "update", "user", user.username, {"role": [user.role, role]})
        user.role = role
    user.display_name = str(claims.get("name") or user.display_name or username)[:128]
    user.email = claims.get("email") or user.email
    user.last_login_at = datetime.now(UTC)
    return user


@router.get("/callback")
def oidc_callback(request: Request, db: DB, settings: SettingsDep) -> RedirectResponse:
    cfg = sso.effective(db, settings)
    q = request.query_params
    saved = _unsign(request.cookies.get(STATE_COOKIE), settings.secret_key)
    state_ok = bool(
        saved
        and q.get("state")
        and hmac.compare_digest(str(saved["state"]).encode(), q["state"].encode())
    )
    tester = saved.get("test") if saved and state_ok else None
    if not cfg.configured or not (cfg.enabled or tester):
        raise HTTPException(404, "SSO is not configured")
    if tester:
        return _test_callback(db, settings, cfg, q, saved)
    if q.get("error"):
        log.info("OIDC sign-in returned error %r", q.get("error"))
        return _fail("cancelled")
    if not state_ok:
        return _fail("expired")
    try:
        meta = discover(cfg.issuer)
        tokens = _exchange(cfg, settings, meta, q.get("code", ""), saved["verifier"])
        claims, role, _ = _identify(cfg, meta, tokens, saved["nonce"])
        if role is None:
            log.info("OIDC login refused for %s: no mapped group", claims.get("sub"))
            raise SsoError("no_access", "no matching group")
        user = _upsert_user(db, cfg, claims, role)
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


# ---------------------------------------------------------------- test sign-in and checks


def _shown_claims(claims: dict) -> dict:
    """The claims for the test result, without opaque ones and with long lists cut short."""
    out: dict = {}
    for k, v in claims.items():
        if k in HIDDEN_CLAIMS:
            continue
        if isinstance(v, list) and len(v) > 50:
            v = v[:50] + [f"… {len(v) - 50} more"]
        out[k] = v
    return out


def _test_callback(db: Session, settings: Settings, cfg: OidcConfig, q, saved: dict):
    result: dict[str, Any] = {"ok": False}
    detail = ""
    try:
        if q.get("error"):
            raise SsoError("cancelled", str(q.get("error_description") or q["error"])[:300])
        meta = discover(cfg.issuer)
        tokens = _exchange(cfg, settings, meta, q.get("code", ""), saved["verifier"])
        claims, role, source = _identify(cfg, meta, tokens, saved["nonce"])
        values = claim_values(claims, cfg.role_claim)
        result |= {
            "claims": _shown_claims(claims),
            "groups_from": source,
            "values": values[:200],
            "matched": [v for v in values if v in cfg.role_map],
            "role": role.value if role else None,
            "username": _username(cfg, claims),
        }
        if role is None:
            raise SsoError("no_access", "")
        user, _, _ = _find_user(db, cfg, claims)
        result |= {"ok": True, "account": "existing" if user else "new"}
    except SsoError as e:
        result["error"], detail = e.code, e.detail
    except httpx.HTTPError as e:
        result["error"], detail = "unreachable", str(e)
    return _test_done(db, saved["test"], cfg, result, detail)


def _test_done(
    db: Session, username: str, cfg: OidcConfig, result: dict, detail: str
) -> RedirectResponse:
    """Keep the result of a test sign-in for the settings page and go back there."""
    db.rollback()
    value = result | {
        "at": datetime.now(UTC).isoformat(),
        "by": username,
        "issuer": cfg.issuer,
        "role_claim": cfg.role_claim,
        "detail": detail[:500],
    }
    row = db.get(AppSetting, sso.SSO_TEST)
    if row is None:
        db.add(AppSetting(key=sso.SSO_TEST, value=value, updated_by=username))
    else:
        row.value, row.updated_by = value, username
    admin = db.scalar(select(User).where(User.username == username))
    audit.record(
        db, admin, "test", "settings", sso.SSO, {"ok": value["ok"], "error": value.get("error")}
    )
    db.commit()
    resp = RedirectResponse(f"{SSO_PAGE}?test=done", status_code=303)
    resp.delete_cookie(STATE_COOKIE, path="/api/auth/oidc")
    return resp


def _json(r: httpx.Response) -> dict:
    try:
        data = r.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def check_connection(cfg: OidcConfig, settings: Settings) -> list[dict]:
    """What the settings page shows for "Check connection": can the IdP be found, are its signing
    keys there and does it accept the client id and secret. `key` + `status` select a fixed text
    in the browser; `detail` is the IdP's own answer, shown to the admin as it is."""
    out: list[dict] = []

    def add(key: str, status: str, detail: str = "", **params: str) -> None:
        out.append({"key": key, "status": status, "detail": detail[:500], "params": params})

    url = f"{cfg.issuer}/.well-known/openid-configuration"
    try:
        meta = discover(cfg.issuer, fresh=True)
    except SsoError as e:
        add("discovery", "fail", e.detail, url=url)
        return out
    except httpx.HTTPError as e:
        add("discovery", "fail", str(e) or type(e).__name__, url=url)
        return out
    if "{tenantid}" in meta["issuer"]:
        add("multi_tenant", "fail")
        return out
    add("discovery", "ok", issuer=meta["issuer"])

    try:
        with http_client() as c:
            r = c.get(meta["jwks_uri"])
        keys = _json(r).get("keys") if r.status_code == 200 else None
        if isinstance(keys, list) and keys:
            add("keys", "ok", n=str(len(keys)))
        else:
            add("keys", "fail", f"HTTP {r.status_code} {r.text[:200]}")
    except httpx.HTTPError as e:
        add("keys", "fail", str(e) or type(e).__name__)

    if not cfg.client_secret:
        add("client_public", "warn")
    else:
        # A client credentials request: a wrong id or secret gives invalid_client. Any other
        # answer means the credentials were read, even if this grant is not allowed.
        data = {"grant_type": "client_credentials"}
        if cfg.provider == "entra" and (graph := entra_graph(cfg)):
            data["scope"] = f"{graph}/.default"
        auth = _client_auth(cfg, meta, data)
        try:
            with http_client() as c:
                r = c.post(meta["token_endpoint"], data=data, auth=auth)
            answer = _json(r)
            error = str(answer.get("error") or "")
            text = str(answer.get("error_description") or error or f"HTTP {r.status_code}")
            if r.status_code == 200:
                add("client", "ok")
            elif error == "invalid_client":
                add("client", "fail", text)
            else:
                add("client_unknown", "warn", text)
        except httpx.HTTPError as e:
            add("client_unknown", "warn", str(e) or type(e).__name__)

    base = urlparse(settings.base_url)
    if base.scheme != "https" and base.hostname not in ("localhost", "127.0.0.1"):
        add("redirect_http", "warn")
    if not cfg.role_map and not cfg.default_role:
        add("no_roles", "warn")
    if cfg.provider == "entra" and cfg.role_claim == "groups":
        names = [v for v in cfg.role_map if not GUID.match(v)]
        if names:
            add("entra_group_names", "warn", values=", ".join(names[:5]))
    return out
