"""Issue #75: verification of log sources (overview, checks, owner and interval)."""

from datetime import date, timedelta

import pytest

CHECKS = ("intake", "configuration", "filtering", "responsibilities")


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


def all_ok(**over):
    return {c: {"result": over.get(c, "ok"), "note": ""} for c in CHECKS}


def source(client, name="Test log source 75"):
    r = client.post("/api/references/log_source", json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def status_of(client, item_id, days=30):
    rows = client.get(f"/api/log-sources/verification?within_days={days}").json()
    return next(x for x in rows if x["id"] == item_id)


def test_never_verified_then_ok_then_issues(analyst):
    sid = source(analyst)
    st = status_of(analyst, sid)
    assert st["status"] == "never" and st["due"] is None and st["interval"] == 180

    r = analyst.post(f"/api/log-sources/{sid}/verify", json={"checks": all_ok(), "note": "fine"})
    assert r.status_code == 201, r.text
    assert r.json()["result"] == "ok"
    st = status_of(analyst, sid)
    assert st["status"] == "ok" and st["last_verified_by"] == "analyst1"
    assert st["due"] == (date.today() + timedelta(days=180)).isoformat()

    # a check with issues does not move the due date, and the log source shows "issues"
    r = analyst.post(f"/api/log-sources/{sid}/verify", json={"checks": all_ok(filtering="issues")})
    assert r.json()["result"] == "issues"
    st = status_of(analyst, sid)
    assert st["status"] == "issues" and st["issues_at"] == date.today().isoformat()
    assert st["last_verified_at"] == date.today().isoformat()
    hist = analyst.get(f"/api/log-sources/{sid}/verifications").json()
    assert [h["result"] for h in hist] == ["issues", "ok"]
    assert hist[0]["checks"]["filtering"]["result"] == "issues"

    # a later check without issues clears it
    analyst.post(f"/api/log-sources/{sid}/verify", json={"checks": all_ok(intake="na")})
    assert status_of(analyst, sid)["status"] == "ok"


def test_overdue_and_interval(admin, analyst):
    sid = source(analyst)
    old = (date.today() - timedelta(days=40)).isoformat()
    analyst.post(f"/api/log-sources/{sid}/verify", json={"checks": all_ok(), "verified_at": old})
    assert status_of(analyst, sid)["status"] == "ok"
    r = analyst.put(
        f"/api/log-sources/{sid}/profile",
        json={"owner": "Network team", "verification_interval_days": 30},
    )
    assert r.status_code == 200 and r.json()["status"] == "overdue"
    assert r.json()["owner"] == "Network team" and r.json()["days_left"] == -10
    # the default interval is an admin setting
    analyst.put(f"/api/log-sources/{sid}/profile", json={"owner": "Network team"})
    assert analyst.put("/api/log-sources/settings", json={"default_days": 45}).status_code == 403
    assert admin.put("/api/log-sources/settings", json={"default_days": 45}).status_code == 200
    st = status_of(analyst, sid)
    assert st["interval"] == 45 and st["status"] == "due"
    assert status_of(analyst, sid, days=0)["status"] == "ok"


def test_usage_validation_and_permissions(admin, analyst, make_user):
    sid = source(analyst, "Firewall log")
    admin.patch("/api/l3/AO-ACC-01", json={"log_sources": ["Firewall log"]})
    assert status_of(analyst, sid)["rules"] == ["AO-ACC-01"]
    bad = {"checks": {"intake": {"result": "ok"}}}
    assert analyst.post(f"/api/log-sources/{sid}/verify", json=bad).status_code == 422
    future = (date.today() + timedelta(days=5)).isoformat()
    r = analyst.post(
        f"/api/log-sources/{sid}/verify", json={"checks": all_ok(), "verified_at": future}
    )
    assert r.status_code == 422
    actor = admin.get("/api/references/threat_actor").json()[0]["id"]
    assert (
        analyst.post(f"/api/log-sources/{actor}/verify", json={"checks": all_ok()}).status_code
        == 404
    )
    auditor = make_user("auditor")
    assert (
        auditor.post(f"/api/log-sources/{sid}/verify", json={"checks": all_ok()}).status_code == 403
    )
    assert auditor.get("/api/log-sources/verification").status_code == 200
    # deleting the log source removes its checks
    analyst.post(f"/api/log-sources/{sid}/verify", json={"checks": all_ok()})
    admin.patch("/api/l3/AO-ACC-01", json={"log_sources": []})
    assert admin.delete(f"/api/references/log_source/{sid}").status_code == 204
    assert all(x["id"] != sid for x in auditor.get("/api/log-sources/verification").json())
