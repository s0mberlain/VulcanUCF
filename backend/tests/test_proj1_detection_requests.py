"""PROJ-1: detection requests with title, description and implementation status.

Test names carry the acceptance criterion (AK-n) or edge case (EC-n) of features/PROJ-1.
"""

import pytest

from app import interviews as ivmod
from tests.test_interviews import (
    complete,
    component,
    l2_id,
    new_system,
    save,
    start,
    threat,
)

REF = {"component": "web", "category": "spoofing"}


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


@pytest.fixture(autouse=True)
def no_log_source_filter(admin):
    assert (
        admin.put("/api/stride-mapping/log-source-filter", json={"enabled": False}).status_code
        == 200
    )


def req(key="r1", title="Alert on bulk transfers", description="", threat_ref=REF):
    return {"key": key, "title": title, "description": description, "threat": threat_ref}


def draft(analyst, requests):
    s = new_system(analyst)
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing")])],
        requests=requests,
    )
    return s, iv


def status(client, system_id, key, expect=200, **body):
    r = client.put(f"/api/systems/{system_id}/detection-requests/{key}/status", json=body)
    assert r.status_code == expect, r.text
    return r.json()


def by_key(view, key):
    return next(r for r in view["requests"] if r["key"] == key)


def test_ak1_new_request_is_open_with_title_and_description(analyst):
    _, iv = draft(analyst, [req(description="Line 1\nLine 2")])
    r = by_key(iv["view"], "r1")
    assert (r["title"], r["description"]) == ("Alert on bulk transfers", "Line 1\nLine 2")
    assert r["status"] == "open" and r["link"] is None and r["status_by"] is None


def test_ak2_ak3_title_rules(analyst):
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    comps = [component(threats=[threat("spoofing")])]
    save(analyst, iv, 422, components=comps, requests=[req(title="   ")])
    save(analyst, iv, 422, components=comps, requests=[req(title="x" * 201)])
    save(analyst, iv, 422, components=comps, requests=[req(description="x" * 10_001)])
    save(analyst, iv, 200, components=comps, requests=[req(title="x" * 200)])


def test_request_needs_an_applying_threat_and_a_unique_key(analyst):
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    comps = [component(threats=[threat("spoofing")])]
    other = {"component": "web", "category": "tampering"}
    save(analyst, iv, 422, components=comps, requests=[req(threat_ref=other)])
    save(analyst, iv, 422, components=comps, requests=[req(), req()])


def test_ak5_draft_save_keeps_status(analyst):
    s, iv = draft(analyst, [req()])
    status(analyst, s["id"], "r1", status="in_progress", note="started")
    # the draft was opened before: saving it must not reset the status
    iv = save(
        analyst,
        iv | {"version": analyst.get(f"/api/interviews/{iv['id']}").json()["version"]},
        requests=[req(title="Renamed")],
    )
    r = by_key(iv["view"], "r1")
    assert (
        r["title"] == "Renamed" and r["status"] == "in_progress" and r["status_note"] == "started"
    )


def test_ak7_ak8_ak9_statuses_and_reasons(analyst):
    s, _ = draft(analyst, [req()])
    for st in ("open", "in_progress", "implemented"):
        assert status(analyst, s["id"], "r1", status=st)["status"] == st
    for st in ("rejected", "not_feasible"):
        status(analyst, s["id"], "r1", 422, status=st)
        status(analyst, s["id"], "r1", 422, status=st, note="   ")
        assert status(analyst, s["id"], "r1", status=st, note="no log source")["status"] == st
    status(analyst, s["id"], "r1", 422, status="done")
    status(analyst, s["id"], "nope", 404, status="open")


def test_ak10_link_for_implemented_only(analyst):
    s, _ = draft(analyst, [req()])
    uc = l2_id(analyst, "AO-ACC")
    out = status(analyst, s["id"], "r1", status="implemented", l2_id=uc)
    assert (
        out["link"]["code"] == "AO-ACC"
        and out["link"]["l2_id"] == uc
        and not out["link"]["deleted"]
    )
    rule = analyst.get("/api/l3/AO-ACC-02").json()
    out = status(analyst, s["id"], "r1", status="implemented", l3_id=rule["id"])
    assert out["link"]["code"] == "AO-ACC-02" and out["link"]["l3_id"] == rule["id"]
    status(analyst, s["id"], "r1", 422, status="implemented", l2_id=999999)
    # a link makes no sense for another status
    assert status(analyst, s["id"], "r1", status="in_progress", l2_id=uc)["link"] is None


def test_ak11_ak12_status_after_completion_keeps_frozen_content(analyst):
    s, iv = draft(analyst, [req(description="why")])
    done = complete(analyst, iv)
    frozen = by_key(done["view"], "r1")
    status(analyst, s["id"], "r1", status="implemented")
    after = by_key(analyst.get(f"/api/interviews/{done['id']}").json()["view"], "r1")
    assert after["status"] == "implemented" and after["status_by"] == "analyst1"
    assert after["status_at"] is not None
    assert (after["title"], after["description"]) == (frozen["title"], frozen["description"])
    # content of a completed interview cannot be changed
    save(analyst, done, 409, requests=[req(title="x")])


def test_ak13_auditor_cannot_change_status(analyst, make_user):
    s, _ = draft(analyst, [req()])
    auditor = make_user("auditor")
    status(auditor, s["id"], "r1", 403, status="implemented")


def test_ak14_requests_from_before_the_feature():
    assert ivmod.split_text("Short one") == ("Short one", "")
    long = "a" * 250
    assert ivmod.split_text(long) == ("a" * 200, long)
    multi = "First line\nsecond line"
    assert ivmod.split_text(multi) == ("First line", multi)
    old = [
        {"key": "", "text": "Same", "threat": REF},
        {"key": "", "text": "Same", "threat": REF},
        {"key": "k", "text": "Keyed", "threat": REF},
    ]
    up = ivmod.upgrade_requests(old)
    assert [r["title"] for r in up] == ["Same", "Same", "Keyed"]
    assert len({r["key"] for r in up}) == 3
    # the same text on the same threat gets the same key in every interview
    assert ivmod.upgrade_requests(old)[0]["key"] == up[0]["key"]
    # an older client sending a single text
    assert "text" not in up[0]


def test_ak14_older_client_with_text(analyst):
    s = new_system(analyst)
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing")])],
        requests=[{"key": "", "text": "Old style request", "threat": REF}],
    )
    (r,) = iv["view"]["requests"]
    assert r["title"] == "Old style request" and r["description"] == "" and r["key"]
    assert r["status"] == "open"


def test_ak16_ak18_system_detail_lists_requests_with_status(analyst):
    s, iv = draft(analyst, [req(), req("r2", "Second")])
    complete(analyst, iv)
    status(analyst, s["id"], "r2", status="rejected", note="out of scope")
    d = analyst.get(f"/api/systems/{s['id']}").json()
    got = {g["key"]: g for g in d["gap_requests"]}
    assert got["r1"]["status"] == "open" and got["r2"]["status"] == "rejected"
    assert got["r2"]["status_note"] == "out of scope" and got["r2"]["title"] == "Second"
    # only requests still to do count as gaps
    open_requests = sum(g["status"] in ("open", "in_progress") for g in d["gap_requests"])
    blind = sum(g["blind"] for g in d["gap_log_sources"])
    assert d["gaps"] == open_requests + len(d["gap_risks"]) + len(d["gap_no_rules"]) + blind
    assert open_requests == 1
    # ak19: the risk row shows the status next to the request, coverage is unchanged
    row = next(r for r in d["risks"] if r["category"] == "spoofing")
    assert [(q["key"], q["status"]) for q in row["requests"]] == [
        ("r1", "open"),
        ("r2", "rejected"),
    ]


def test_ak25_ak26_reinterview_copies_all_requests_with_one_status(analyst):
    s, iv = draft(analyst, [req(), req("r2", "Second"), req("r3", "Third")])
    complete(analyst, iv)
    status(analyst, s["id"], "r1", status="implemented")
    status(analyst, s["id"], "r2", status="rejected", note="no")
    status(analyst, s["id"], "r3", status="not_feasible", note="no source")
    second = start(analyst, s["id"])
    view = second["view"]
    assert {r["key"]: r["status"] for r in view["requests"]} == {
        "r1": "implemented",
        "r2": "rejected",
        "r3": "not_feasible",
    }
    # one status for the request in both interviews
    status(analyst, s["id"], "r1", status="in_progress")
    first = analyst.get(f"/api/interviews/{iv['id']}").json()["view"]
    assert by_key(first, "r1")["status"] == "in_progress"
    assert (
        by_key(analyst.get(f"/api/interviews/{second['id']}").json()["view"], "r1")["status"]
        == "in_progress"
    )
    # and the system page lists it once
    complete(analyst, analyst.get(f"/api/interviews/{second['id']}").json())
    d = analyst.get(f"/api/systems/{s['id']}").json()
    assert sorted(g["key"] for g in d["gap_requests"]) == ["r1", "r2", "r3"]


def test_ak29_last_write_wins(analyst, make_user):
    s, _ = draft(analyst, [req()])
    other = make_user("analyst", "analyst2")
    status(analyst, s["id"], "r1", status="in_progress")
    status(other, s["id"], "r1", status="implemented")
    d = analyst.get(f"/api/systems/{s['id']}").json()
    iv = analyst.get(f"/api/interviews/{d['draft_id']}").json()
    r = by_key(iv["view"], "r1")
    assert r["status"] == "implemented" and r["status_by"] == "analyst2"


def test_ec2_link_to_a_deleted_use_case_shows_as_deleted(analyst, admin):
    s, _ = draft(analyst, [req()])
    rule = analyst.get("/api/l3/AO-ACC-02").json()
    status(analyst, s["id"], "r1", status="implemented", l3_id=rule["id"])
    assert admin.delete("/api/l3/AO-ACC-02").status_code in (200, 204)
    draft_id = analyst.get(f"/api/systems/{s['id']}").json()["draft_id"]
    d = analyst.get(f"/api/interviews/{draft_id}").json()
    link = by_key(d["view"], "r1")["link"]
    assert link["deleted"] is True and link["code"] == "AO-ACC-02"


def test_ak20_report_contains_status(analyst):
    s, iv = draft(analyst, [req(description="Because")])
    done = complete(analyst, iv)
    status(analyst, s["id"], "r1", status="rejected", note="Not needed")
    r = analyst.get(f"/api/interviews/{done['id']}/pdf?lang=de")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


def test_audit_log_records_status_change(analyst, admin):
    s, _ = draft(analyst, [req()])
    status(analyst, s["id"], "r1", status="in_progress")
    rows = admin.get("/api/audit", params={"entity": "detection_request"}).json()
    assert len(rows) == 1 and rows[0]["username"] == "analyst1"


# ---------------------------------------------------------------- PROJ-2: overview


def overview(client) -> list[dict]:
    r = client.get("/api/detection-requests")
    assert r.status_code == 200, r.text
    return r.json()["requests"]


def test_proj2_ak4_ak5_ak6_current_state_only(analyst):
    # no completed interview: nothing
    s, iv = draft(analyst, [req(), req("r2", "Second")])
    assert overview(analyst) == []
    complete(analyst, iv)
    rows = overview(analyst)
    assert {r["key"] for r in rows} == {"r1", "r2"}
    row = next(r for r in rows if r["key"] == "r1")
    assert row["system_name"] == s["name"] and row["system_id"] == s["id"]
    assert row["component"] == "Web front end" and row["category"] == "spoofing"
    assert row["risk_score"] == 12 and row["status"] == "open" and row["archived"] is False
    # a draft with new requests does not show
    second = start(analyst, s["id"])
    save(analyst, second, requests=[req(), req("r2", "Second"), req("r9", "Only in draft")])
    assert {r["key"] for r in overview(analyst)} == {"r1", "r2"}


def test_proj2_ak7_ak8_removed_and_carried_over(analyst):
    s, iv = draft(analyst, [req(), req("r2", "Second")])
    complete(analyst, iv)
    status(analyst, s["id"], "r2", status="implemented")
    second = start(analyst, s["id"])
    second = save(analyst, second, requests=[req("r2", "Second")])
    complete(analyst, second)
    rows = overview(analyst)
    # r1 was removed in the re-interview; r2 appears once with its status
    assert [(r["key"], r["status"]) for r in rows] == [("r2", "implemented")]


def test_proj2_status_and_archive_in_overview(analyst, make_user):
    s, iv = draft(analyst, [req()])
    complete(analyst, iv)
    status(analyst, s["id"], "r1", status="rejected", note="no")
    (row,) = overview(analyst)
    assert row["status"] == "rejected" and row["status_note"] == "no"
    assert row["status_by"] == "analyst1"
    body = {k: s[k] for k in ("name", "owner_name", "criticality")} | {"archived": True}
    assert analyst.patch(f"/api/systems/{s['id']}", json=body).status_code == 200
    (row,) = overview(analyst)
    assert row["archived"] is True
    # every role can read it
    assert len(overview(make_user("auditor"))) == 1


def test_proj2_unrated_threat_has_no_risk_score(analyst):
    s = new_system(analyst)
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[
            component(threats=[threat("spoofing", state="does_not_apply"), threat("tampering")])
        ],
        requests=[req(threat_ref={"component": "web", "category": "tampering"})],
    )
    complete(analyst, iv)
    (row,) = overview(analyst)
    assert row["risk_score"] == 12
