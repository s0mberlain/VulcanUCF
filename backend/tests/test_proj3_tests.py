"""PROJ-3: tests against detection rules (campaigns, quick tests, library, gaps, red team).

Test names carry the acceptance criterion (AK-n) or edge case (EC-n) of features/PROJ-3.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.conftest import login

RULE = "PV-PRC-01"  # a seeded rule
RULE2 = "PV-POL-01"


def iso(days_ago=0, hour=10):
    d = datetime.now(UTC).replace(hour=hour, minute=0, second=0, microsecond=0)
    return (d - timedelta(days=days_ago)).isoformat()


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


@pytest.fixture
def auditor(make_user):
    return make_user("auditor")


@pytest.fixture
def scopes(admin):
    """Two scopes and a rule that has both."""
    for n in ("Windows", "Linux"):
        admin.post("/api/references/scope", json={"name": n})
    r = admin.patch(
        f"/api/l3/{RULE}",
        json={
            "scopes": ["Windows", "Linux"],
            "attack_techniques": ["T1059.001"],
            "lifecycle_status": "operational",
            "verification_interval_days": 30,
        },
    )
    assert r.status_code == 200, r.text
    return ["Linux", "Windows"]


def quick(client, outcome="alerted", scopes=("Windows", "Linux"), days_ago=1, rule=RULE, **extra):
    body = {
        "title": "PowerShell encoded command",
        "technique": "T1059.001",
        "links": [{"l3_code": rule, "scopes": list(scopes)}],
        "exec_status": "executed",
        "executed_at": iso(days_ago),
        "outcome": outcome,
        "detected_at": iso(days_ago, 11) if outcome in ("alerted", "blocked") else None,
    } | extra
    r = client.post("/api/quick-tests", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def rule_state(client, rule=RULE):
    r = client.get(f"/api/l3/{rule}/tests")
    assert r.status_code == 200, r.text
    return r.json()


def history(client, rule=RULE):
    return client.get(f"/api/l3/{rule}/verifications").json()


# ------------------------------------------------------------------ scopes and verification


def test_ak38_41_successful_test_verifies_the_rule(admin, analyst, scopes):  # AK-38, AK-40
    quick(analyst)
    st = rule_state(analyst)
    assert st["state"] == "verified" and st["covered"] == 2
    h = history(analyst)
    assert h[0]["result"] == "ok" and "Test:" in h[0]["note"]
    assert admin.get(f"/api/l3/{RULE}").json()["last_verified_at"] is not None


def test_ak39_partial_scope_does_not_verify_the_rule(analyst, scopes):  # AK-39
    quick(analyst, scopes=("Windows",))
    st = rule_state(analyst)
    assert st["state"] == "partial" and st["covered"] == 1 and st["total"] == 2
    assert [s["status"] for s in st["scopes"]] == ["open", "covered"]  # Linux, Windows
    assert history(analyst) == []
    assert analyst.get(f"/api/l3/{RULE}").json()["last_verified_at"] is None


def test_ak40_two_tests_cover_all_scopes_and_date_is_the_oldest(analyst, scopes):  # AK-40
    quick(analyst, scopes=("Windows",), days_ago=10)
    quick(analyst, scopes=("Linux",), days_ago=2)
    st = rule_state(analyst)
    assert st["state"] == "verified"
    assert st["verified_date"] == iso(10)[:10]


def test_ak42_failed_test_is_a_problem_and_a_gap(analyst, scopes):  # AK-42, AK-46
    quick(analyst, outcome="not_detected", scopes=("Windows", "Linux"))
    st = rule_state(analyst)
    assert st["state"] == "issues"
    assert history(analyst)[0]["result"] == "issues"
    gaps = analyst.get("/api/test-gaps").json()
    assert {(g["l3_code"], g["scope"]) for g in gaps} == {(RULE, "Windows"), (RULE, "Linux")}


def test_ak43_not_executed_test_changes_nothing(analyst, scopes):  # AK-43
    quick(analyst, exec_status="not_executable", executed_at=None, outcome=None, detected_at=None)
    assert rule_state(analyst)["state"] == "none"
    assert history(analyst) == []


def test_ak44_verification_expires_after_the_rule_interval(analyst, scopes):  # AK-44
    quick(analyst, days_ago=40)  # interval is 30 days
    st = rule_state(analyst)
    assert st["state"] == "due"
    assert all(s["status"] == "expired" for s in st["scopes"])


def test_ak45_changing_the_result_recomputes(analyst, scopes):  # AK-45
    t = quick(analyst)
    assert rule_state(analyst)["state"] == "verified"
    r = analyst.put(
        f"/api/tests/{t['id']}/blue",
        json={
            "outcome": "logged",
            "blue_notes": "only logged",
            "expected_version": t["blue_version"],
        },
    )
    assert r.status_code == 200, r.text
    assert rule_state(analyst)["state"] == "issues"
    assert len(history(analyst)) == 1  # replaced, not doubled


def test_ak45_removing_a_rule_removes_its_verification(analyst, scopes):  # AK-45
    t = quick(analyst)
    r = analyst.put(
        f"/api/tests/{t['id']}",
        json={
            "title": t["title"],
            "technique": t["technique"],
            "links": [],
            "expected_version": t["version"],
        },
    )
    assert r.status_code == 200, r.text
    assert rule_state(analyst)["state"] == "none"
    assert history(analyst) == []


def test_ak45b_l2_gets_no_automatic_verification(admin, analyst, scopes):  # AK-45b
    before = admin.get("/api/l2/PV-PRC").json()["last_verified_at"]
    quick(analyst)
    assert admin.get("/api/l2/PV-PRC").json()["last_verified_at"] == before
    s = analyst.get("/api/l2/PV-PRC/tests-summary").json()
    assert s["tests"] == 1 and s["states"]["verified"] == 1


def test_ak25a_scope_choice_is_required_and_checked(analyst, scopes):  # AK-25a
    body = {"title": "t", "technique": "T1059.001", "links": [{"l3_code": RULE, "scopes": []}]}
    r = analyst.post("/api/quick-tests", json=body | {"exec_status": "not_run"})
    assert r.status_code == 422 and "scopes" in r.text
    body["links"][0]["scopes"] = ["Mars"]
    assert (
        analyst.post("/api/quick-tests", json=body | {"exec_status": "not_run"}).status_code == 422
    )


def test_rule_without_scopes_is_verified_by_one_test(analyst):  # AK-41
    quick(analyst, rule=RULE2, scopes=())
    assert rule_state(analyst, RULE2)["state"] == "verified"


def test_ec3_latest_test_decides(analyst, scopes):  # EC-3
    quick(analyst, outcome="not_detected", days_ago=5)
    quick(analyst, outcome="alerted", days_ago=1)
    assert analyst.get("/api/test-gaps").json() == []  # a later success closes the gap
    quick(analyst, outcome="logged", days_ago=0, hour=18)
    assert len(analyst.get("/api/test-gaps").json()) == 2


def test_ak48_success_on_another_scope_does_not_close_a_gap(analyst, scopes):  # AK-48
    quick(analyst, outcome="not_detected", scopes=("Windows",), days_ago=5)
    quick(analyst, outcome="alerted", scopes=("Linux",), days_ago=1)
    g = analyst.get("/api/test-gaps").json()
    assert [x["scope"] for x in g] == ["Windows"]


def test_ak47_failed_test_without_rule_is_a_gap_of_the_technique(analyst):  # AK-47
    r = analyst.post(
        "/api/quick-tests",
        json={
            "title": "t",
            "technique": "T1003",
            "exec_status": "executed",
            "executed_at": iso(1),
            "outcome": "not_detected",
        },
    )
    assert r.status_code == 201
    g = analyst.get("/api/test-gaps").json()
    assert g[0]["l3_code"] is None and g[0]["technique"] == "T1003"


def test_ak49_accepting_a_gap(analyst, scopes):  # AK-49
    t = quick(analyst, outcome="not_detected", scopes=("Windows",))
    r = analyst.post(
        "/api/test-gaps/accept",
        json={
            "l3_code": RULE,
            "technique": "T1059.001",
            "scope": "Windows",
            "test_id": t["id"],
            "reason": "legacy",
        },
    )
    assert r.status_code == 204, r.text
    assert analyst.get("/api/test-gaps/count").json() == {"open": 0}
    assert (
        analyst.get("/api/test-gaps", params={"accepted": True}).json()[0]["accepted_reason"]
        == "legacy"
    )


def test_ec1_deleted_rule_keeps_the_test(admin, analyst, scopes):  # EC-1
    t = quick(analyst, rule=RULE2, scopes=())
    r = admin.delete(f"/api/l3/{RULE2}")
    assert r.status_code in (204, 200), r.text
    got = analyst.get(f"/api/tests/{t['id']}").json()
    assert got["links"][0]["deleted"] is True and got["links"][0]["l3_code"] == RULE2


def test_ak33_detection_before_execution_is_refused(analyst, scopes):  # AK-33
    body = {
        "title": "t",
        "technique": "T1059.001",
        "links": [{"l3_code": RULE, "scopes": ["Windows"]}],
        "exec_status": "executed",
        "executed_at": iso(1, 12),
        "outcome": "alerted",
        "detected_at": iso(1, 9),
    }
    assert analyst.post("/api/quick-tests", json=body).status_code == 422


def test_ak34_time_to_detect(analyst, scopes):  # AK-34
    t = quick(analyst, outcome="alerted")
    assert t["time_to_detect_seconds"] == 3600
    assert quick(analyst, outcome="logged")["time_to_detect_seconds"] is None


# ------------------------------------------------------------------ campaigns


def campaign(client, name="Q4 purple team", accounts=()):
    r = client.post(
        "/api/campaigns",
        json={
            "name": name,
            "planned_start": "2026-11-01",
            "planned_end": "2026-12-15",
            "account_ids": list(accounts),
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


def red_user(admin, app, name="rt1"):
    r = admin.post(
        "/api/users",
        json={
            "username": name,
            "role": "red_team",
            "password": "red-password-1234",
            "expires_at": iso(-30),
        },
    )
    assert r.status_code == 201, r.text
    c = TestClient(app)
    login(c, name, "red-password-1234")
    return r.json()["id"], c


def test_ak10_campaign_rules(analyst, admin, app, auditor):  # AK-10, AK-3
    c = campaign(analyst)
    assert c["status"] == "planned"
    assert (
        analyst.post(
            "/api/campaigns",
            json={
                "name": "Q4 purple team",
                "planned_start": "2026-11-01",
                "planned_end": "2026-12-01",
            },
        ).status_code
        == 409
    )
    assert (
        analyst.post(
            "/api/campaigns",
            json={"name": "x", "planned_start": "2026-12-01", "planned_end": "2026-11-01"},
        ).status_code
        == 422
    )
    assert auditor.get("/api/campaigns").status_code == 200
    assert (
        auditor.post(
            "/api/campaigns",
            json={"name": "y", "planned_start": "2026-11-01", "planned_end": "2026-12-01"},
        ).status_code
        == 403
    )


def test_ak11_15_status_flow(analyst, scopes):  # AK-11..15
    c = campaign(analyst)
    t = analyst.post(
        f"/api/campaigns/{c['id']}/tests",
        json={
            "title": "t",
            "technique": "T1059.001",
            "links": [{"l3_code": RULE, "scopes": ["Windows"]}],
        },
    ).json()
    # results only while running
    assert (
        analyst.put(
            f"/api/tests/{t['id']}/red", json={"exec_status": "executed", "executed_at": iso(1)}
        ).status_code
        == 409
    )
    assert (
        analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "running"}).status_code
        == 200
    )
    # cannot close while the test is not run
    r = analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "closed"})
    assert r.status_code == 409 and "t" in r.text
    assert (
        analyst.put(
            f"/api/tests/{t['id']}/red", json={"exec_status": "executed", "executed_at": iso(1)}
        ).status_code
        == 200
    )
    assert (
        analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "closed"}).status_code
        == 409
    )  # no result yet
    assert (
        analyst.put(
            f"/api/tests/{t['id']}/blue", json={"outcome": "alerted", "detected_at": iso(1, 11)}
        ).status_code
        == 200
    )
    assert (
        analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "closed"}).status_code
        == 200
    )
    # closed: read-only
    assert analyst.put(f"/api/tests/{t['id']}/blue", json={"outcome": "logged"}).status_code == 409
    assert (
        analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "running"}).status_code
        == 200
    )


def test_ak16_17_deleting_a_campaign(admin, analyst):  # AK-16, AK-17
    c = campaign(analyst)
    assert analyst.delete(f"/api/campaigns/{c['id']}").status_code == 403
    assert admin.delete(f"/api/campaigns/{c['id']}").status_code == 204


def test_ak19_proposals_one_test_per_technique(analyst, scopes):  # AK-19, AK-21
    c = campaign(analyst)
    r = analyst.post(f"/api/campaigns/{c['id']}/proposals", json={"l3_codes": [RULE, RULE2]}).json()
    techs = {p["technique"]: [x["code"] for x in p["rules"]] for p in r["proposals"]}
    assert techs["T1059.001"] == [RULE]
    assert any(x["code"] == RULE2 for x in r["no_technique"]) or RULE2 in sum(techs.values(), [])


def test_ak8_template_is_a_copy(analyst, scopes):  # AK-7, AK-8
    t = quick(analyst, procedure="powershell -enc ...")
    tpl = analyst.post(f"/api/tests/{t['id']}/library").json()
    assert tpl["technique"] == "T1059.001"
    analyst.put(f"/api/library/{tpl['id']}", json={"title": "Changed", "technique": "T1059.001"})
    analyst.delete(f"/api/library/{tpl['id']}")
    assert analyst.get(f"/api/tests/{t['id']}").json()["title"] == t["title"]


# ------------------------------------------------------------------ red team


def test_ak2_red_team_sees_only_its_campaigns(admin, analyst, app, scopes):  # AK-2, AK-15
    rid, rt = red_user(admin, app)
    mine = campaign(analyst, "mine", [rid])
    other = campaign(analyst, "other")
    assert [c["name"] for c in rt.get("/api/campaigns").json()] == ["mine"]
    assert rt.get(f"/api/campaigns/{other['id']}").status_code == 404
    for path in (
        "/api/systems",
        "/api/l3",
        "/api/scores",
        "/api/library",
        "/api/quick-tests",
        "/api/users",
        "/api/test-gaps",
    ):
        assert rt.get(path).status_code == 403, path
    assert rt.get("/api/auth/me").status_code == 200
    assert mine["id"]


def test_ak26_29_red_team_creates_tests_but_cannot_link(admin, analyst, app, scopes):  # AK-26..29
    rid, rt = red_user(admin, app)
    c = campaign(analyst, "mine", [rid])
    analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "running"})
    r = rt.post(f"/api/campaigns/{c['id']}/tests", json={"title": "mine", "technique": "T1003"})
    assert r.status_code == 201, r.text
    t = r.json()
    assert t["created_by_red_team"] and t["needs_rules"]
    assert (
        rt.post(
            f"/api/campaigns/{c['id']}/tests",
            json={
                "title": "x",
                "technique": "T1003",
                "links": [{"l3_code": RULE, "scopes": ["Windows"]}],
            },
        ).status_code
        == 403
    )
    assert rt.post(f"/api/tests/{t['id']}/library").status_code == 403
    assert (
        rt.put(f"/api/tests/{t['id']}", json={"title": "mine v2", "technique": "T1003"}).status_code
        == 200
    )
    # an analyst's test cannot be edited by the red team, only executed
    a = analyst.post(
        f"/api/campaigns/{c['id']}/tests",
        json={
            "title": "blue test",
            "technique": "T1059.001",
            "links": [{"l3_code": RULE, "scopes": ["Windows"]}],
        },
    ).json()
    assert (
        rt.put(f"/api/tests/{a['id']}", json={"title": "x", "technique": "T1059.001"}).status_code
        == 403
    )
    assert (
        rt.put(
            f"/api/tests/{a['id']}/red", json={"exec_status": "executed", "executed_at": iso(0, 9)}
        ).status_code
        == 200
    )
    assert rt.put(f"/api/tests/{a['id']}/blue", json={"outcome": "alerted"}).status_code == 403
    # once the blue team has a result, the red team cannot change its own test
    analyst.put(
        f"/api/tests/{t['id']}/red", json={"exec_status": "executed", "executed_at": iso(0, 8)}
    )
    analyst.put(f"/api/tests/{t['id']}/blue", json={"outcome": "not_detected"})
    assert (
        rt.put(f"/api/tests/{t['id']}", json={"title": "late", "technique": "T1003"}).status_code
        == 403
    )


def test_ak35_36_blue_result_hidden_until_closed(admin, analyst, app, scopes):  # AK-35, AK-36
    rid, rt = red_user(admin, app)
    c = campaign(analyst, "mine", [rid])
    analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "running"})
    t = analyst.post(
        f"/api/campaigns/{c['id']}/tests",
        json={
            "title": "t",
            "technique": "T1059.001",
            "links": [{"l3_code": RULE, "scopes": ["Windows"]}],
        },
    ).json()
    analyst.put(
        f"/api/tests/{t['id']}/red", json={"exec_status": "executed", "executed_at": iso(0, 9)}
    )
    analyst.put(
        f"/api/tests/{t['id']}/blue",
        json={"outcome": "alerted", "detected_at": iso(0, 10), "blue_notes": "secret"},
    )
    seen = rt.get(f"/api/tests/{t['id']}").json()
    assert seen["outcome"] is None and seen["blue_notes"] is None and seen["links"] == []
    assert rt.get("/api/campaigns").json()[0]["outcomes"] is None
    analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "closed"})
    seen = rt.get(f"/api/tests/{t['id']}").json()
    assert seen["outcome"] == "alerted" and seen["blue_notes"] == "secret"


def test_ak69_blue_attachments_hidden_from_red_team(admin, analyst, app, scopes):  # AK-66, AK-69
    rid, rt = red_user(admin, app)
    c = campaign(analyst, "mine", [rid])
    analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "running"})
    t = analyst.post(
        f"/api/campaigns/{c['id']}/tests", json={"title": "t", "technique": "T1059.001"}
    ).json()
    pdf = b"%PDF-1.4\n%x\n"
    a = analyst.post(
        f"/api/tests/{t['id']}/attachments", files={"file": ("shot.pdf", pdf, "application/pdf")}
    )
    assert a.status_code == 201 and a.json()["side"] == "blue"
    b = rt.post(
        f"/api/tests/{t['id']}/attachments", files={"file": ("proof.pdf", pdf, "application/pdf")}
    )
    assert b.status_code == 201 and b.json()["side"] == "red"
    assert [x["filename"] for x in rt.get(f"/api/tests/{t['id']}").json()["attachments"]] == [
        "proof.pdf"
    ]
    assert rt.get(f"/api/test-attachments/{a.json()['id']}/content").status_code == 404
    assert (
        analyst.delete(f"/api/test-attachments/{b.json()['id']}").status_code == 403
    )  # not their own
    assert rt.delete(f"/api/test-attachments/{b.json()['id']}").status_code == 204
    bad = analyst.post(
        f"/api/tests/{t['id']}/attachments", files={"file": ("x.pdf", b"nope", "application/pdf")}
    )
    assert bad.status_code == 422


def test_ak75_conflict_on_the_same_part(analyst):  # AK-75, AK-76
    t = quick(
        analyst, exec_status="not_run", executed_at=None, outcome=None, detected_at=None, links=[]
    )
    ok = analyst.put(
        f"/api/tests/{t['id']}/blue",
        json={"outcome": None, "blue_notes": "a", "expected_version": t["blue_version"]},
    )
    assert ok.status_code == 200
    stale = analyst.put(
        f"/api/tests/{t['id']}/blue",
        json={"outcome": None, "blue_notes": "b", "expected_version": t["blue_version"]},
    )
    assert stale.status_code == 409 and "reload" in stale.text
    # the red part has its own version
    assert (
        analyst.put(
            f"/api/tests/{t['id']}/red",
            json={"exec_status": "not_run", "expected_version": t["red_version"]},
        ).status_code
        == 200
    )


# ------------------------------------------------------------------ accounts


def test_ak57_58_59_expiry_follows_the_campaign(admin, analyst, app):  # AK-57..59
    r = admin.post(
        "/api/users", json={"username": "rt2", "role": "red_team", "password": "red-password-1234"}
    )
    assert r.status_code == 422  # a date is required
    r = admin.post(
        "/api/users",
        json={
            "username": "rt2",
            "role": "red_team",
            "password": "red-password-1234",
            "expiry_follows_campaign": True,
            "expires_at": iso(-3),
        },
    )
    uid = r.json()["id"]
    assert r.json()["effective_expires_at"] is not None
    c = campaign(analyst, "c1", [uid])
    users = {u["username"]: u for u in admin.get("/api/users").json()}
    assert users["rt2"]["effective_expires_at"].startswith("2026-12-15")
    # moves with the campaign
    analyst.put(
        f"/api/campaigns/{c['id']}",
        json={
            "name": "c1",
            "planned_start": "2026-11-01",
            "planned_end": "2027-01-20",
            "account_ids": [uid],
        },
    )
    users = {u["username"]: u for u in admin.get("/api/users").json()}
    assert users["rt2"]["effective_expires_at"].startswith("2027-01-20")
    # a fixed date does not move
    admin.patch(
        f"/api/users/{uid}",
        json={"expiry_follows_campaign": False, "expires_at": "2027-03-01T00:00:00+00:00"},
    )
    analyst.put(
        f"/api/campaigns/{c['id']}",
        json={
            "name": "c1",
            "planned_start": "2026-11-01",
            "planned_end": "2027-02-01",
            "account_ids": [uid],
        },
    )
    users = {u["username"]: u for u in admin.get("/api/users").json()}
    assert users["rt2"]["effective_expires_at"].startswith("2027-03-01")


def test_ak61_63_65_expired_account_and_deletion(admin, analyst, app):  # AK-61, AK-63, AK-65
    uid, rt = red_user(admin, app, "rt3")
    admin.patch(f"/api/users/{uid}", json={"expires_at": iso(2)})  # in the past
    assert rt.get("/api/campaigns").status_code == 401  # the session stops working
    fresh = TestClient(app)
    assert (
        fresh.post(
            "/api/auth/login", json={"username": "rt3", "password": "red-password-1234"}
        ).status_code
        == 401
    )
    admin.patch(f"/api/users/{uid}", json={"expires_at": iso(-10)})  # extended
    login(fresh, "rt3", "red-password-1234")
    c = campaign(analyst, "c2", [uid])
    analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "running"})
    fresh.post(f"/api/campaigns/{c['id']}/tests", json={"title": "x", "technique": "T1003"})
    assert admin.delete(f"/api/users/{uid}").status_code == 409  # has entries: lock instead


def test_assigning_a_normal_account_is_refused(analyst):
    r = analyst.post(
        "/api/campaigns",
        json={
            "name": "z",
            "planned_start": "2026-11-01",
            "planned_end": "2026-12-01",
            "account_ids": [1],
        },
    )
    assert r.status_code == 422


def test_audit_log_records_test_actions(admin, analyst, scopes):  # AK-74
    quick(analyst)
    entries = admin.get("/api/audit").json()
    rows = entries["items"] if isinstance(entries, dict) else entries
    assert any(e["entity"] == "quick_test" for e in rows)


def test_description_is_kept_and_copied_to_the_library(analyst, scopes):
    t = quick(analyst, description="## Goal\n\n- run **encoded** commands")
    assert t["description"].startswith("## Goal")
    got = analyst.get(f"/api/tests/{t['id']}").json()
    assert "**encoded**" in got["description"]
    tpl = analyst.post(f"/api/tests/{t['id']}/library").json()
    assert tpl["description"] == t["description"]
    r = analyst.put(
        f"/api/tests/{t['id']}",
        json={
            "title": t["title"],
            "technique": t["technique"],
            "description": "changed",
            "links": [],
            "expected_version": t["version"],
        },
    )
    assert r.json()["description"] == "changed"
    assert analyst.get("/api/library", params={"q": "encoded"}).json()[0]["id"] == tpl["id"]
