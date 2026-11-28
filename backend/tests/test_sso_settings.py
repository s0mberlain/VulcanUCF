"""SSO set up in the app (Administration → Single sign-on): app/sso.py, api/sso_settings.py."""

import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import sso
from app.models import AppSetting, AuditLog
from tests.test_oidc import ENTRA, ISSUER, TENANT, FakeIdp, make_client, sign_in, use_idp

FORM = {
    "enabled": False,
    "provider": "entra",
    "tenant_id": TENANT,
    "client_id": "magma",
    "client_secret": "s3cret",
    "role_claim": "roles",
    "role_map": [
        {"value": "Vulcan.Admin", "role": "admin"},
        {"value": "Vulcan.Analyst", "role": "analyst"},
    ],
}


@pytest.fixture
def entra(monkeypatch):
    return use_idp(monkeypatch, FakeIdp(ENTRA))


def check(admin, form) -> dict:
    """Check connection, by item key."""
    r = admin.post("/api/settings/sso/check", json=form)
    assert r.status_code == 200, r.text
    return {i["key"]: i for i in r.json()}


def start_test(admin, idp, claims):
    """A test sign-in by the admin, through the fake IdP back to the settings page."""
    r = admin.get("/api/auth/oidc/test", follow_redirects=False)
    assert r.status_code == 303, r.text
    q = parse_qs(urlparse(r.headers["location"]).query)
    idp.nonce, idp.claims = q["nonce"][0], claims
    params = {"code": "c0de", "state": q["state"][0]}
    r = admin.get("/api/auth/oidc/callback", params=params, follow_redirects=False)
    assert r.headers["location"] == "/admin/sso?test=done"
    return q, admin.get("/api/settings/sso/test").json()


def test_defaults_and_access(admin, make_user):
    s = admin.get("/api/settings/sso").json()
    assert s["source"] == "app" and not s["enabled"] and s["provider"] == "entra"
    assert s["redirect_uri"] == "http://localhost:8080/api/auth/oidc/callback"
    assert s["client_secret_status"] == "unset" and s["scopes"] == "openid profile email User.Read"
    assert admin.get("/api/settings/sso/test").json() is None

    analyst = make_user("analyst")
    assert analyst.get("/api/settings/sso").status_code == 403
    assert analyst.put("/api/settings/sso", json=FORM).status_code == 403
    assert analyst.post("/api/settings/sso/check", json=FORM).status_code == 403
    assert analyst.get("/api/auth/oidc/test", follow_redirects=False).status_code == 403


def test_client_secret_is_stored_encrypted_and_write_only(admin, app, settings):
    r = admin.put("/api/settings/sso", json=FORM)
    assert r.status_code == 200, r.text
    assert r.json()["client_secret_status"] == "set" and "s3cret" not in r.text
    with app.state.sessionmaker() as db:
        token = db.get(AppSetting, sso.SSO).value["client_secret"]
        assert "s3cret" not in token
        assert sso.decrypt_secret(token, settings.secret_key) == "s3cret"

    # no secret in the form keeps it, "" removes it
    r = admin.put("/api/settings/sso", json={**FORM, "client_secret": None, "client_id": "other"})
    assert r.json()["client_secret_status"] == "set" and r.json()["client_id"] == "other"
    r = admin.put("/api/settings/sso", json={**FORM, "client_secret": ""})
    assert r.json()["client_secret_status"] == "unset"

    with app.state.sessionmaker() as db:
        entries = db.scalars(
            select(AuditLog)
            .where(AuditLog.entity == "settings", AuditLog.entity_key == "sso")
            .order_by(AuditLog.id)
        ).all()
    assert "s3cret" not in json.dumps([e.changes for e in entries])
    assert [e.changes.get("client_secret") for e in entries] == [
        ["not set", "changed"],
        None,
        ["set", "removed"],
    ]


@pytest.mark.parametrize(
    "patch, message",
    [
        ({"tenant_id": "organizations"}, "Enter your own tenant ID"),
        ({"tenant_id": "contoso tenant"}, "The tenant ID is a GUID"),
        ({"provider": "oidc", "issuer": "ftp://idp.example.test"}, "https:// URL"),
        ({"scopes": "profile email"}, "openid"),
        (
            {"role_map": [{"value": "A", "role": "admin"}, {"value": "A", "role": "auditor"}]},
            "A is mapped twice",
        ),
        ({"enabled": True, "role_map": []}, "Map at least one group or role"),
        ({"enabled": True, "client_id": ""}, "before turning SSO on"),
        ({"role_map": [{"value": "A", "role": "red_team"}]}, None),
    ],
)
def test_validation(admin, patch, message):
    r = admin.put("/api/settings/sso", json={**FORM, **patch})
    assert r.status_code == 422
    if message:
        assert message in r.json()["detail"]


def test_sign_in_with_the_settings_from_the_app(admin, app, entra):
    user = TestClient(app, follow_redirects=False)
    admin.put("/api/settings/sso", json=FORM)
    # saved but not turned on: no button and no sign-in
    assert not user.get("/api/auth/config").json()["sso_enabled"]
    assert user.get("/api/auth/oidc/login").status_code == 404

    assert admin.put("/api/settings/sso", json={**FORM, "enabled": True}).status_code == 200
    cfg = user.get("/api/auth/config").json()
    assert cfg["sso_enabled"] and cfg["sso_provider"] == "entra" and cfg["sso_label"] == ""
    claims = {"sub": "e-9", "preferred_username": "jana@corp.example", "roles": ["Vulcan.Analyst"]}
    r = sign_in(user, entra, claims)
    assert r.headers["location"] == "/usecases"
    me = user.get("/api/auth/me").json()
    assert me["username"] == "jana@corp.example" and me["role"] == "analyst"
    # the stored secret went to the token endpoint
    assert entra.token_requests[-1]["auth"] == "Basic " + base64.b64encode(b"magma:s3cret").decode()

    # turned off again: the button goes away
    admin.put("/api/settings/sso", json={**FORM, "client_secret": None})
    assert not user.get("/api/auth/config").json()["sso_enabled"]


def test_test_sign_in_creates_no_account(admin, entra):
    assert admin.put("/api/settings/sso", json=FORM).status_code == 200  # not turned on
    claims = {
        "sub": "e-10",
        "preferred_username": "tom@corp.example",
        "name": "Tom",
        "roles": ["Vulcan.Admin", "Other"],
        "aio": "opaque",
    }
    q, res = start_test(admin, entra, claims)
    assert q["prompt"] == ["select_account"]
    assert res["ok"] and res["role"] == "admin" and res["matched"] == ["Vulcan.Admin"]
    assert res["values"] == ["Vulcan.Admin", "Other"] and res["groups_from"] == "token"
    assert res["username"] == "tom@corp.example" and res["account"] == "new"
    assert res["by"] == "admin" and res["claims"]["name"] == "Tom" and "aio" not in res["claims"]
    # no account was made and the admin is still signed in as themselves
    assert admin.get("/api/auth/me").json()["username"] == "admin"
    assert all(u["username"] != "tom@corp.example" for u in admin.get("/api/users").json())

    # a refused sign-in is recorded with the reason
    claims = {"sub": "e-11", "preferred_username": "admin", "roles": ["Vulcan.Analyst"]}
    _, res = start_test(admin, entra, claims)
    assert not res["ok"] and res["error"] == "local_account" and res["role"] == "analyst"
    _, res = start_test(admin, entra, {"sub": "e-12", "roles": ["Nobody"]})
    assert not res["ok"] and res["error"] == "no_access" and res["role"] is None


def test_test_sign_in_when_the_provider_is_down(admin, entra):
    admin.put("/api/settings/sso", json=FORM)
    entra.down = True
    r = admin.get("/api/auth/oidc/test", follow_redirects=False)
    assert r.headers["location"] == "/admin/sso?test=done"
    res = admin.get("/api/settings/sso/test").json()
    assert not res["ok"] and res["error"] == "unreachable" and "503" in res["detail"]


def test_check_connection(admin, entra):
    items = check(admin, FORM)
    assert items["discovery"] == {
        "key": "discovery",
        "status": "ok",
        "detail": "",
        "params": {"issuer": ENTRA},
    }
    assert items["keys"]["params"] == {"n": "1"} and items["client"]["status"] == "ok"
    form = entra.token_requests[-1]["form"]
    assert form["grant_type"] == ["client_credentials"]
    assert form["scope"] == ["https://graph.microsoft.com/.default"]
    assert set(items) == {"discovery", "keys", "client"}  # nothing to warn about

    entra.token_error = ("invalid_client", "AADSTS7000215: Invalid client secret provided.")
    items = check(admin, FORM)
    assert items["client"]["status"] == "fail" and "AADSTS7000215" in items["client"]["detail"]
    entra.token_error = ("unauthorized_client", "AADSTS700016: Application not found")
    items = check(admin, FORM)
    assert items["client_unknown"]["status"] == "warn"
    entra.token_error = None

    # Entra ID sends group object ids, so names in the mapping never match
    form = {**FORM, "role_claim": "groups", "role_map": [{"value": "SOC-Admins", "role": "admin"}]}
    assert check(admin, form)["entra_group_names"]["params"] == {"values": "SOC-Admins"}
    assert check(admin, {**FORM, "role_map": []})["no_roles"]["status"] == "warn"
    # without a secret in the form the stored one is used; none stored: a warning
    assert "client_public" in check(admin, {**FORM, "client_secret": None})

    entra.down = True
    items = admin.post("/api/settings/sso/check", json=FORM).json()
    assert [(i["key"], i["status"]) for i in items] == [("discovery", "fail")]
    assert items[0]["params"]["url"] == f"{ENTRA}/.well-known/openid-configuration"

    r = admin.post("/api/settings/sso/check", json={**FORM, "tenant_id": ""})
    assert r.status_code == 422


def test_multi_tenant_discovery_fails_the_check(admin, monkeypatch):
    template = "https://login.microsoftonline.com/{tenantid}/v2.0"
    use_idp(monkeypatch, FakeIdp(ENTRA, meta_issuer=template))
    items = admin.post("/api/settings/sso/check", json=FORM).json()
    assert [(i["key"], i["status"]) for i in items] == [("multi_tenant", "fail")]


def test_environment_settings_win(tmp_path, monkeypatch):
    use_idp(monkeypatch, FakeIdp())
    with make_client(tmp_path, ISSUER, "SOC-Admins=admin") as c:
        r = c.post("/api/auth/login", json={"username": "admin", "password": "admin-password-123"})
        assert r.status_code == 200
        s = c.get("/api/settings/sso").json()
        assert s["source"] == "env" and s["enabled"] and s["provider"] == "oidc"
        assert s["issuer"] == ISSUER and s["client_secret_status"] == "set"
        assert s["role_map"] == [{"value": "SOC-Admins", "role": "admin"}]
        r = c.put("/api/settings/sso", json=FORM)
        assert r.status_code == 409 and "OIDC_*" in r.json()["detail"]
        items = c.post("/api/settings/sso/check", json=FORM).json()
        assert items[0]["params"]["issuer"] == ISSUER


def test_rotate_secret_reencrypts_the_client_secret(admin, app, settings):
    admin.put("/api/settings/sso", json=FORM)
    new_key = "another-secret-key-0123456789-abcdefghijkl"
    with app.state.sessionmaker() as db:
        assert sso.reencrypt(db, settings.secret_key, new_key) is True
        db.commit()
        token = db.get(AppSetting, sso.SSO).value["client_secret"]
        assert sso.decrypt_secret(token, new_key) == "s3cret"
        assert sso.reencrypt(db, settings.secret_key, new_key) is False  # done already
        assert sso.reencrypt(db, "wrong-old-key", "third-key") is None
    # this app still runs with the old key, so it can no longer read the secret
    assert admin.get("/api/settings/sso").json()["client_secret_status"] == "unreadable"
