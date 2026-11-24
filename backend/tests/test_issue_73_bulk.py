"""Issue #73: bulk edit of L2 use cases from the use case tree."""

import pytest


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


def l2(client, code):
    return client.get(f"/api/l2/{code}").json()


def test_set_fields_and_add_remove_lists(admin, analyst):
    for code in ("BD-91", "BD-92"):
        r = admin.post("/api/business-drivers", json={"code": code, "name": code})
        assert r.status_code == 201, r.text
    actor = admin.get("/api/references/threat_actor").json()[0]["name"]
    admin.patch("/api/l2/AO-CRE", json={"business_drivers": ["BD-92"]})

    r = analyst.post(
        "/api/l2-bulk/update",
        json={
            "codes": ["AO-ACC", "AO-CRE", "NOPE"],
            "risk_level": 4,
            "target_implementation": 0.8,
            "business_drivers": {"add": ["BD-91"], "remove": ["BD-92"]},
            "actors": {"add": [actor]},
        },
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["changed"] == 2
    assert out["results"][2] == {"code": "NOPE", "ok": False, "error": "L2 use case not found"}
    for code in ("AO-ACC", "AO-CRE"):
        x = l2(analyst, code)
        assert x["risk_level"] == 4 and x["target_implementation"] == 0.8
        assert "BD-91" in x["business_drivers"] and "BD-92" not in x["business_drivers"]
        assert actor in x["actors"]
    # null clears an optional field; lists not named stay as they are
    r = analyst.post("/api/l2-bulk/update", json={"codes": ["AO-ACC"], "risk_level": None})
    assert r.status_code == 200
    x = l2(analyst, "AO-ACC")
    assert x["risk_level"] is None and "BD-91" in x["business_drivers"]
    entries = admin.get("/api/audit?entity=l2&key=AO-CRE").json()
    assert entries[0]["action"] == "update" and entries[0]["changes"]["bulk"] is True


def test_update_validation(analyst, make_user):
    assert analyst.post("/api/l2-bulk/update", json={"codes": ["AO-ACC"]}).status_code == 422
    assert (
        analyst.post("/api/l2-bulk/update", json={"codes": [], "risk_level": 2}).status_code == 422
    )
    r = analyst.post(
        "/api/l2-bulk/update",
        json={"codes": ["AO-ACC"], "business_drivers": {"add": ["BD-UNKNOWN"]}},
    )
    assert r.status_code == 422 and "BD-UNKNOWN" in r.json()["detail"]
    auditor = make_user("auditor")
    assert (
        auditor.post("/api/l2-bulk/update", json={"codes": ["AO-ACC"], "risk_level": 2}).status_code
        == 403
    )


def test_lifecycle_applies_where_allowed(admin, analyst):
    dod = {k: True for k in ("log_sources", "scope", "incident_response", "roles", "rules")}
    assert analyst.put("/api/l2/AO-ACC/dod", json={"items": dod}).status_code == 200
    body = {"to_status": "operational", "driver_type": "operational", "driver": "red_teaming"}
    r = analyst.post("/api/l2-bulk/lifecycle", json=body | {"codes": ["AO-ACC", "AO-CRE"]})
    assert r.status_code == 200, r.text
    res = {x["code"]: x for x in r.json()["results"]}
    assert res["AO-ACC"]["ok"] and not res["AO-CRE"]["ok"]
    assert "Definition of done" in res["AO-CRE"]["error"]
    assert l2(analyst, "AO-ACC")["lifecycle_status"] == "operational"
    assert l2(analyst, "AO-CRE")["lifecycle_status"] != "operational"
    # skipping the definition of done stays a single-use-case decision, also for admins
    r = admin.post("/api/l2-bulk/lifecycle", json=body | {"codes": ["AO-CRE"], "override": True})
    assert r.status_code == 422


def test_bulk_verify(analyst):
    r = analyst.post(
        "/api/l2-bulk/verify",
        json={"codes": ["AO-ACC", "AO-CRE"], "result": "ok", "note": "quarterly review"},
    )
    assert r.status_code == 200 and r.json()["changed"] == 2
    for code in ("AO-ACC", "AO-CRE"):
        assert l2(analyst, code)["last_verified_by"] == "analyst1"
        hist = analyst.get(f"/api/l2/{code}/verifications").json()
        assert hist[0]["note"] == "quarterly review"
