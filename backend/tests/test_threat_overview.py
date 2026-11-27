"""Threat modelling overview: risk coverage per threat and L2 or L3 use case selection.

An analyst can tie a whole L2 use case or a single L3 rule to the threats of an interview.
`view.risks` (interview) and `risks` (system) list every applying threat with the use cases
that address it and its coverage: covered | partial | gap | below (under the threshold, nothing
linked) | unrated.
"""

import pytest

from tests.test_interviews import (
    codes,
    complete,
    component,
    l2_id,
    log_source_id,
    new_system,
    save,
    start,
    threat,
)


def l3_id(client, code: str) -> int:
    r = client.get(f"/api/l3/{code}")
    assert r.status_code == 200, r.text
    return r.json()["id"]


def no_proposals(client) -> list[dict]:
    """Remove every mapped L2 so only hand-picked use cases are accepted."""
    cats = client.get("/api/stride-mapping").json()["categories"]
    ids = {x["l2_id"] for c in cats for x in c["l2s"]}
    return [{"l2_id": i, "reason": ""} for i in sorted(ids)]


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


@pytest.fixture(autouse=True)
def no_log_source_filter(admin):
    r = admin.put("/api/stride-mapping/log-source-filter", json={"enabled": False})
    assert r.status_code == 200, r.text


WEB_SPOOF = {"component": "web", "category": "spoofing"}


def test_l3_rule_can_be_added_to_a_threat(analyst):
    s = new_system(analyst)
    rule = l3_id(analyst, "AO-ACC-01")
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing"), threat("tampering", likelihood=1)])],
        removed=no_proposals(analyst),
        added=[{"l3_id": rule, "threats": [WEB_SPOOF]}],
    )
    v = iv["view"]
    assert v["added"] == [{"l3_id": rule, "threats": [WEB_SPOOF]}]
    (p,) = v["proposals"]
    assert (p["level"], p["code"], p["l2_code"], p["manual"]) == ("L3", "AO-ACC-01", "AO-ACC", True)
    assert p["l3_id"] == rule and p["l2_id"] == l2_id(analyst, "AO-ACC")
    assert [r["code"] for r in p["rules"]] == ["AO-ACC-01"]
    risks = {r["category"]: r for r in v["risks"]}
    assert [u["code"] for u in risks["spoofing"]["use_cases"]] == ["AO-ACC-01"]
    assert risks["spoofing"]["use_cases"][0]["level"] == "L3"
    # tampering 1 x 4 = 4 is below the threshold and nothing addresses it: accepted risk
    assert risks["tampering"]["coverage"] == "below"
    assert risks["tampering"]["use_cases"] == []


def test_l2_and_l3_of_the_same_use_case_can_be_chosen_together(analyst):
    s = new_system(analyst)
    acc = l2_id(analyst, "AO-ACC")
    rule = l3_id(analyst, "AO-ACC-02")
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing")])],
        removed=[r for r in no_proposals(analyst) if r["l2_id"] != acc],
        added=[
            {"l2_id": acc, "threats": [WEB_SPOOF]},
            {"l3_id": rule, "threats": [WEB_SPOOF]},
        ],
    )
    assert sorted(codes(iv["view"]["proposals"])) == ["AO-ACC", "AO-ACC-02"]
    complete(analyst, iv)
    d = analyst.get(f"/api/systems/{s['id']}").json()
    links = {x["code"]: x for x in d["links"]}
    assert set(links) == {"AO-ACC", "AO-ACC-02"}
    assert (links["AO-ACC-02"]["level"], links["AO-ACC-02"]["l2_code"]) == ("L3", "AO-ACC")
    assert links["AO-ACC"]["level"] == "L2"
    # the use case filter finds the L2 of a linked rule
    assert "AO-ACC" in codes(analyst.get(f"/api/l2?system={s['id']}").json())


def test_added_entry_needs_exactly_one_level(analyst):
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    comps = [component(threats=[threat("spoofing")])]
    acc, rule = l2_id(analyst, "AO-ACC"), l3_id(analyst, "AO-ACC-01")
    for added in (
        [{"l2_id": acc, "l3_id": rule, "threats": [WEB_SPOOF]}],
        [{"threats": [WEB_SPOOF]}],
    ):
        save(analyst, iv, 422, components=comps, added=added)
    r = save(analyst, iv, 422, components=comps, added=[{"l3_id": 999999, "threats": [WEB_SPOOF]}])
    assert "Unknown L3 rule" in r["detail"]
    twice = [{"l3_id": rule, "threats": [WEB_SPOOF]}] * 2
    assert "added twice" in save(analyst, iv, 422, components=comps, added=twice)["detail"]
    nothing = [{"l3_id": rule, "threats": []}]
    save(analyst, iv, 422, components=comps, added=nothing)
    off = [{"l3_id": rule, "threats": [{"component": "web", "category": "repudiation"}]}]
    save(analyst, iv, 422, components=comps, added=off)


def test_l3_link_counts_its_own_weight(analyst):
    s = new_system(analyst)
    rule = l3_id(analyst, "AO-ACC-01")
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing")])],
        removed=no_proposals(analyst),
        added=[{"l3_id": rule, "threats": [WEB_SPOOF]}],
    )
    complete(analyst, iv)
    d = analyst.get(f"/api/systems/{s['id']}").json()
    weight = analyst.get("/api/l3/AO-ACC-01").json()["weight"]
    assert d["links"][0]["weight"] == weight
    assert d["coverage"] == round(weight or 0.0, 4)


def test_l3_link_raises_only_that_rules_priority(analyst):
    analyst.patch("/api/l3/AO-ACC-01", json={"risk_level": 1})
    analyst.patch("/api/l3/AO-ACC-02", json={"risk_level": 1})
    s = new_system(analyst)
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing", likelihood=4, impact=4)])],
        removed=no_proposals(analyst),
        added=[{"l3_id": l3_id(analyst, "AO-ACC-01"), "threats": [WEB_SPOOF]}],
    )
    complete(analyst, iv)
    one = analyst.get("/api/l3/AO-ACC-01").json()
    two = analyst.get("/api/l3/AO-ACC-02").json()
    assert (one["effective_risk"], one["risk_source"], one["risk_system"]) == (
        4,
        "system",
        "Online banking",
    )
    assert (two["effective_risk"], two["risk_source"]) == (1, "rule")


def test_risk_coverage_states(analyst):
    """covered: an active rule gets its log sources; gap: nothing above the threshold."""
    db_log = log_source_id(analyst, "Database log")
    analyst.patch("/api/l3/AO-ACC-01", json={"log_sources": ["Database log"]})
    rule = analyst.get("/api/l3/AO-ACC-01").json()
    s = new_system(analyst)
    comps = [
        component(threats=[threat("spoofing"), threat("repudiation")], log_source_ids=[db_log])
    ]
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=comps,
        removed=no_proposals(analyst),
        added=[{"l3_id": rule["id"], "threats": [WEB_SPOOF]}],
        requests=[
            {"key": "r", "text": "Log viewer", "threat": {**WEB_SPOOF, "category": "repudiation"}}
        ],
    )
    risks = {r["category"]: r for r in iv["view"]["risks"]}
    active = rule["lifecycle_status"] in ("onboarding", "operational", "maintenance")
    assert risks["spoofing"]["coverage"] == ("covered" if active else "gap")
    assert risks["spoofing"]["score"] == 12 and risks["spoofing"]["level"] == 3
    assert risks["repudiation"]["coverage"] == "gap"
    assert [(r["title"], r["status"]) for r in risks["repudiation"]["requests"]] == [
        ("Log viewer", "open")
    ]
    # the system page shows the same overview from the links
    complete(analyst, iv)
    d = analyst.get(f"/api/systems/{s['id']}").json()
    assert d["threshold"] == 8
    sys_risks = {r["category"]: r for r in d["risks"]}
    assert sys_risks["spoofing"]["coverage"] == risks["spoofing"]["coverage"]
    assert sys_risks["spoofing"]["use_cases"][0]["weight"] == d["links"][0]["weight"]
    assert sys_risks["repudiation"]["coverage"] == "gap"


def test_completed_interview_has_risks_and_marks_deleted_rules(analyst, admin):
    s = new_system(analyst)
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing")])],
        removed=no_proposals(analyst),
        added=[{"l3_id": l3_id(analyst, "AO-ACC-03"), "threats": [WEB_SPOOF]}],
    )
    done = complete(analyst, iv)
    assert done["view"]["risks"][0]["use_cases"][0]["code"] == "AO-ACC-03"
    # a rule linked to a system is deleted only on confirmation (audit L7)
    r = admin.delete("/api/l3/AO-ACC-03")
    assert r.status_code == 409 and r.json()["systems"]
    assert admin.delete("/api/l3/AO-ACC-03?confirm=true").status_code == 204
    again = analyst.get(f"/api/interviews/{iv['id']}").json()
    (p,) = again["view"]["proposals"]
    assert p["deleted"] is True
    uc = again["view"]["risks"][0]["use_cases"][0]
    assert (uc["deleted"], uc["state"]) == (True, "gap")
    # the link went with the rule
    assert analyst.get(f"/api/systems/{s['id']}").json()["links"] == []


def test_reinterview_keeps_l3_choice(analyst):
    s = new_system(analyst)
    rule = l3_id(analyst, "AO-ACC-01")
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing")])],
        removed=no_proposals(analyst),
        added=[{"l3_id": rule, "threats": [WEB_SPOOF]}],
    )
    complete(analyst, iv)
    nxt = start(analyst, s["id"])
    assert nxt["view"]["added"] == [{"l3_id": rule, "threats": [WEB_SPOOF]}]
    assert codes(nxt["view"]["proposals"]) == ["AO-ACC-01"]
