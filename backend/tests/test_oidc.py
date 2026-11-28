import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import sso
from app.api import oidc
from app.config import Settings
from app.main import create_app
from app.models import Role

ISSUER = "https://idp.example.test/realms/soc"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})


TENANT = "9b2c4f1e-3a5d-4e6f-8a7b-1c2d3e4f5a6b"
ENTRA = f"https://login.microsoftonline.com/{TENANT}/v2.0"
ADMINS = "6c1f6d32-0e0c-4a4b-9c7e-0b1d2a3c4d5e"
ANALYSTS = "a2b3c4d5-e6f7-4890-a1b2-c3d4e5f60718"
# What Entra ID puts in the token instead of the groups for a user in more than 200 groups.
OVERAGE = {
    "_claim_names": {"groups": "src1"},
    "_claim_sources": {"src1": {"endpoint": "https://graph.windows.net/t/users/u/memberOf"}},
}


class FakeIdp:
    """An OIDC provider and, for Entra ID, Microsoft Graph's checkMemberGroups."""

    def __init__(self, issuer=ISSUER, meta_issuer=None):
        self.issuer = issuer
        self.meta_issuer = meta_issuer or issuer
        self.claims: dict = {}
        self.nonce = None
        self.token_requests: list[dict] = []
        self.member_of: set[str] = set()
        self.graph_status = 200
        self.graph_requests: list[dict] = []
        self.down = False  # every request fails
        self.token_error: tuple[str, str] | None = None  # (error, description) from /token

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if self.down:
            return httpx.Response(503, text="Service Unavailable")
        if request.url.host == "graph.microsoft.com":
            assert path == "/v1.0/me/checkMemberGroups"
            ids = json.loads(request.content)["groupIds"]
            self.graph_requests.append({"ids": ids, "auth": request.headers.get("authorization")})
            if self.graph_status != 200:
                return httpx.Response(self.graph_status, json={"error": {"code": "Forbidden"}})
            return httpx.Response(200, json={"value": [g for g in ids if g in self.member_of]})
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": self.meta_issuer,
                    "authorization_endpoint": f"{self.issuer}/auth",
                    "token_endpoint": f"{self.issuer}/token",
                    "jwks_uri": f"{self.issuer}/certs",
                    "userinfo_endpoint": f"{self.issuer}/userinfo",
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                },
            )
        if path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [JWK]})
        if path.endswith("/token"):
            form = parse_qs(request.content.decode())
            self.token_requests.append({"form": form, "auth": request.headers.get("authorization")})
            if self.token_error:
                error, text = self.token_error
                return httpx.Response(401, json={"error": error, "error_description": text})
            now = int(time.time())
            claims = {
                "iss": self.issuer,
                "aud": "magma",
                "iat": now,
                "exp": now + 300,
                "nonce": self.nonce,
                **self.claims,
            }
            token = jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "k1"})
            return httpx.Response(200, json={"id_token": token, "access_token": "at"})
        if path.endswith("/userinfo"):
            return httpx.Response(200, json={"groups": ["SOC-Analysts"]})
        return httpx.Response(404)


def use_idp(monkeypatch, fake: FakeIdp) -> FakeIdp:
    monkeypatch.setattr(
        oidc, "http_client", lambda: httpx.Client(transport=httpx.MockTransport(fake.handler))
    )
    oidc._discovery.clear()
    return fake


@pytest.fixture
def idp(monkeypatch):
    return use_idp(monkeypatch, FakeIdp())


def make_client(tmp_path, issuer, role_map, **kw):
    s = Settings(
        database_url=f"sqlite:///{tmp_path}/t.db",
        static_dir=tmp_path / "static",
        admin_password="admin-password-123",
        oidc_issuer=issuer,
        oidc_client_id="magma",
        oidc_client_secret="s3cret",
        oidc_role_map=role_map,
        **kw,
    )
    return TestClient(create_app(s), follow_redirects=False)


@pytest.fixture
def sso_client(tmp_path, idp):
    role_map = "SOC-Admins=admin, SOC-Analysts=analyst, Audit=auditor"
    with make_client(tmp_path, ISSUER, role_map) as c:
        yield c


def sign_in(client, idp, claims, next_="/usecases"):
    r = client.get("/api/auth/oidc/login", params={"next": next_})
    assert r.status_code == 303
    loc = urlparse(r.headers["location"])
    q = parse_qs(loc.query)
    assert loc.path == urlparse(idp.issuer).path + "/auth"
    assert q["code_challenge_method"] == ["S256"]
    idp.nonce = q["nonce"][0]
    idp.claims = claims
    return client.get("/api/auth/oidc/callback", params={"code": "c0de", "state": q["state"][0]})


def test_role_mapping():
    s = Settings(oidc_role_map="A=auditor,B=admin,C=analyst,D=bogus", oidc_role_claim="realm.roles")
    cfg = sso.from_env(s)
    assert oidc.map_role({"realm": {"roles": ["A", "C"]}}, cfg) == Role.analyst
    assert oidc.map_role({"realm": {"roles": ["A", "B"]}}, cfg) == Role.admin
    assert oidc.map_role({"realm": {"roles": ["X"]}}, cfg) is None
    assert "D" not in cfg.role_map
    s.oidc_default_role = "auditor"
    assert oidc.map_role({}, sso.from_env(s)) == Role.auditor


def test_auth_config_shows_sso(sso_client):
    cfg = sso_client.get("/api/auth/config").json()
    assert cfg["sso_enabled"] and cfg["local_login_enabled"]


def test_sso_login_creates_user_and_session(sso_client, idp):
    r = sign_in(
        sso_client,
        idp,
        {
            "sub": "u-1",
            "preferred_username": "jana",
            "name": "Jana Analyst",
            "groups": ["SOC-Admins", "Audit"],
        },
    )
    assert r.status_code == 303 and r.headers["location"] == "/usecases"
    me = sso_client.get("/api/auth/me").json()
    assert me["username"] == "jana" and me["role"] == "admin" and me["auth_source"] == "sso"
    assert idp.token_requests[0]["auth"].startswith("Basic ")
    assert idp.token_requests[0]["form"]["code_verifier"]

    # role follows the IdP on the next login; no duplicate user
    sso_client.post("/api/auth/logout")
    sign_in(sso_client, idp, {"sub": "u-1", "preferred_username": "jana", "groups": ["Audit"]})
    assert sso_client.get("/api/auth/me").json()["role"] == "auditor"
    sso_client.post("/api/auth/logout")
    login = sso_client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin-password-123"}
    )
    users = sso_client.get("/api/users").json()
    assert login.status_code == 200 and sum(u["username"] == "jana" for u in users) == 1


def test_groups_from_userinfo(sso_client, idp):
    sign_in(sso_client, idp, {"sub": "u-2", "preferred_username": "tom"})
    assert sso_client.get("/api/auth/me").json()["role"] == "analyst"
    # distributed claims of an IdP other than Entra ID still fall back to userinfo
    sso_client.post("/api/auth/logout")
    sign_in(sso_client, idp, {"sub": "u-3", "preferred_username": "ann", **OVERAGE})
    assert sso_client.get("/api/auth/me").json()["role"] == "analyst"
    assert idp.graph_requests == []


def test_entra_groups_overage_asks_microsoft_graph(tmp_path, monkeypatch):
    idp = use_idp(monkeypatch, FakeIdp(ENTRA))
    idp.member_of = {ANALYSTS, "11111111-2222-4333-8444-555555555555"}
    role_map = f"{ADMINS}=admin,{ANALYSTS}=analyst,Audit=auditor"
    jana = {"sub": "e-1", "preferred_username": "jana.doe@corp.example", **OVERAGE}
    with make_client(tmp_path, ENTRA, role_map) as c:
        # Graph refuses (e.g. no User.Read): no groups, so no access rather than a guess
        idp.graph_status = 403
        r = sign_in(c, idp, jana)
        assert r.headers["location"].endswith("sso_error=no_access")
        assert c.get("/api/auth/me").status_code == 401

        idp.graph_status = 200
        r = sign_in(c, idp, jana)
        assert r.headers["location"] == "/usecases"
        me = c.get("/api/auth/me").json()
        assert me["username"] == "jana.doe@corp.example" and me["role"] == "analyst"
    # only the group object ids of the role map, with the user's access token
    assert idp.graph_requests[-1] == {"ids": [ADMINS, ANALYSTS], "auth": "Bearer at"}


def test_entra_graph_lookup_in_batches(monkeypatch):
    idp = use_idp(monkeypatch, FakeIdp(ENTRA))
    ids = [f"00000000-0000-4000-8000-{n:012d}" for n in range(25)]
    idp.member_of = {ids[22]}
    role_map = ",".join(f"{g}=auditor" for g in ids)
    s = Settings(oidc_issuer=ENTRA, oidc_client_id="magma", oidc_role_map=role_map)
    assert oidc._entra_groups(sso.from_env(s), "at") == [ids[22]]
    assert [len(r["ids"]) for r in idp.graph_requests] == [20, 5]
    # group names cannot be looked up in Graph: nothing is sent
    s.oidc_role_map = "SOC-Admins=admin"
    assert oidc._entra_groups(sso.from_env(s), "at") == [] and len(idp.graph_requests) == 2


def test_entra_app_roles(tmp_path, monkeypatch):
    idp = use_idp(monkeypatch, FakeIdp(ENTRA))
    role_map = "Vulcan.Admin=admin,Vulcan.Analyst=analyst"
    with make_client(tmp_path, ENTRA, role_map, oidc_role_claim="roles") as c:
        # app roles come in the token; an overage of the groups claim does not matter then
        r = sign_in(c, idp, {"sub": "e-2", "roles": ["Vulcan.Analyst"], **OVERAGE})
        assert r.headers["location"] == "/usecases"
        assert c.get("/api/auth/me").json()["role"] == "analyst"
    assert idp.graph_requests == []


def test_entra_multi_tenant_issuer_is_refused(tmp_path, monkeypatch, caplog):
    common = "https://login.microsoftonline.com/organizations/v2.0"
    template = "https://login.microsoftonline.com/{tenantid}/v2.0"
    idp = use_idp(monkeypatch, FakeIdp(common, meta_issuer=template))
    with make_client(tmp_path, common, f"{ADMINS}=admin") as c:
        with caplog.at_level("INFO", logger="magma.oidc"):
            r = sign_in(c, idp, {"iss": ENTRA, "sub": "e-3", "groups": [ADMINS]})
        assert r.headers["location"].endswith("sso_error=invalid_token")
        assert c.get("/api/auth/me").status_code == 401
    assert "multi-tenant Entra ID endpoint" in caplog.text


def test_refused_logins(sso_client, idp):
    # a group that is not mapped and no default role -> no access
    r = sign_in(
        sso_client, idp, {"sub": "u-4", "preferred_username": "mallory", "groups": ["Other"]}
    )
    assert r.status_code == 303 and r.headers["location"].endswith("sso_error=no_access")
    assert sso_client.get("/api/auth/me").status_code == 401

    # a local account with the same name is not taken over
    r = sign_in(
        sso_client, idp, {"sub": "u-5", "preferred_username": "admin", "groups": ["SOC-Admins"]}
    )
    assert r.headers["location"].endswith("sso_error=local_account")
    assert sso_client.get("/api/auth/me").status_code == 401


def test_bad_state_and_bad_nonce(sso_client, idp):
    r = sso_client.get("/api/auth/oidc/callback", params={"code": "x", "state": "forged"})
    assert r.headers["location"].endswith("sso_error=expired")
    # the IdP's error text is not reflected onto the login page
    r = sso_client.get("/api/auth/oidc/callback", params={"error": "Call +1 555 now"})
    assert r.headers["location"] == "/login?sso_error=cancelled"

    r = sso_client.get("/api/auth/oidc/login")
    q = parse_qs(urlparse(r.headers["location"]).query)
    idp.nonce = "wrong"
    idp.claims = {"sub": "u-6", "groups": ["Audit"]}
    r = sso_client.get("/api/auth/oidc/callback", params={"code": "c", "state": q["state"][0]})
    assert r.headers["location"].endswith("sso_error=invalid_token")
    assert sso_client.get("/api/auth/me").status_code == 401


def test_sso_disabled_by_default(anon):
    assert anon.get("/api/auth/oidc/login", follow_redirects=False).status_code == 404
    assert not anon.get("/api/auth/config").json()["sso_enabled"]


def test_sso_username_is_normalised():
    from app.api.oidc import sso_username

    assert sso_username("Jane Doe <jane@x>") == "Jane_Doe_jane@x"
    assert sso_username("ok.name-1") == "ok.name-1"
    assert sso_username("??").startswith("sso_") and len(sso_username("x" * 200)) == 64
