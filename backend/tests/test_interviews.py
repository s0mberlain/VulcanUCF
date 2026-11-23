"""Business owner interviews (issue #17): systems, STRIDE interviews, proposals, links, effects.

Test names carry the acceptance criterion (AK-n) or edge case (EC-n) of the issue they cover.
"""

from datetime import date, timedelta

import pytest

TODAY = date.today()


def l2_id(client, code: str) -> int:
    r = client.get(f"/api/l2/{code}")
    assert r.status_code == 200, r.text
    return r.json()["id"]


def log_source_id(client, name: str) -> int:
    items = client.get("/api/references/log_source").json()
    return next(i["id"] for i in items if i["name"] == name)


def new_system(client, name="Online banking", **extra) -> dict:
    body = {"name": name, "owner_name": "J. Jansen", "criticality": 4} | extra
    r = client.post("/api/systems", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def start(client, system_id: int) -> dict:
    r = client.post(f"/api/systems/{system_id}/interviews")
    assert r.status_code == 201, r.text
    return r.json()


def threat(category, state="applies", likelihood=3, impact=4, description="x"):
    return {
        "category": category,
        "state": state,
        "likelihood": likelihood,
        "impact": impact,
        "description": description,
    }


def component(key="web", name="Web front end", threats=(), log_source_ids=()):
    return {
        "key": key,
        "name": name,
        "description": "",
        "log_source_ids": list(log_source_ids),
        "threats": list(threats),
    }


def save(client, iv: dict, expect: int = 200, **changes) -> dict:
    stored = iv["view"]
    body = {
        "expected_version": iv["version"],
        "interview_date": iv["interview_date"],
        "participants": iv["participants"],
        "notes": iv["notes"],
        "components": [
            {
                "key": c["key"],
                "name": c["name"],
                "description": c["description"],
                "log_source_ids": [s["id"] for s in c["log_sources"]],
                "threats": [
                    {k: t[k] for k in ("category", "state", "description", "likelihood", "impact")}
                    for t in c["threats"]
                    if not t.get("custom")
                ],
                "custom_threats": [
                    {"key": t["category"].removeprefix("custom:")}
                    | {
                        k: t[k]
                        for k in ("title", "description", "techniques", "likelihood", "impact")
                    }
                    for t in c["threats"]
                    if t.get("custom")
                ],
            }
            for c in stored["components"]
        ],
        "added": stored["added"],
        "removed": [
            {"l2_id": r["l2_id"], "reason": r["reason"]}
            | (
                {
                    "threats": [
                        {"component": x["component"], "category": x["category"]}
                        for x in r["threats"]
                    ]
                }
                if r.get("threats")
                else {}
            )
            for r in stored["removed"]
        ],
        "requests": [
            {
                "key": r["key"],
                "title": r["title"],
                "description": r["description"],
                "threat": {"component": r["component"], "category": r["category"]},
            }
            for r in stored["requests"]
        ],
    } | changes
    r = client.put(f"/api/interviews/{iv['id']}", json=body)
    assert r.status_code == expect, r.text
    return r.json()


def complete(client, iv: dict, expect: int = 200) -> dict:
    r = client.post(
        f"/api/interviews/{iv['id']}/complete", json={"expected_version": iv["version"]}
    )
    assert r.status_code == expect, r.text
    return r.json()


def codes(items) -> list[str]:
    return [x["code"] for x in items]


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


@pytest.fixture(autouse=True)
def no_log_source_filter(admin):
    """These tests cover #17 itself; the log source filter (#36) is tested in
    test_issues_32_36.py."""
    r = admin.put("/api/stride-mapping/log-source-filter", json={"enabled": False})
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------- systems


def test_create_system_defaults_and_audit(analyst, admin):
    """AK-1, AK-5"""
    s = new_system(analyst)
    assert s["review_interval_months"] == 12
    assert s["state"] == "none"
    assert s["can_delete"] is True
    rows = analyst.get("/api/systems").json()
    assert [r["name"] for r in rows] == ["Online banking"]
    assert analyst.delete(f"/api/systems/{s['id']}").status_code == 204
    assert analyst.get("/api/systems").json() == []
    log = admin.get("/api/audit?limit=20").json()
    assert {(e["action"], e["entity"]) for e in log} >= {("create", "system"), ("delete", "system")}


def test_system_name_unique_ignoring_case(analyst):
    """AK-2"""
    new_system(analyst)
    r = analyst.post(
        "/api/systems", json={"name": "online Banking", "owner_name": "x", "criticality": 1}
    )
    assert r.status_code == 409
    assert "exists" in r.json()["detail"]


@pytest.mark.parametrize(
    "body",
    [
        {"owner_name": "x", "criticality": 3},
        {"name": "A", "criticality": 3},
        {"name": "A", "owner_name": "x"},
        {"name": "A", "owner_name": "x", "criticality": 3, "owner_email": "not-an-address"},
        {"name": "A", "owner_name": "x", "criticality": 6},
        {"name": "A", "owner_name": "x", "criticality": 3, "review_interval_months": 61},
        {"name": "A", "owner_name": "x", "criticality": 3, "description": "y" * 10_001},
    ],
)
def test_system_validation(analyst, body):
    """AK-3, EC-13"""
    assert analyst.post("/api/systems", json=body).status_code == 422


def test_blank_email_is_allowed(analyst):
    s = new_system(analyst, owner_email="  ")
    assert s["owner_email"] is None


def test_archive_hides_and_unarchive(analyst):
    """AK-6"""
    s = new_system(analyst)
    body = {k: s[k] for k in ("name", "owner_name", "criticality")} | {"archived": True}
    assert analyst.patch(f"/api/systems/{s['id']}", json=body).status_code == 200
    assert analyst.get("/api/systems").json() == []
    shown = analyst.get("/api/systems?archived=true").json()
    assert shown[0]["archived"] is True
    body["archived"] = False
    assert analyst.patch(f"/api/systems/{s['id']}", json=body).status_code == 200
    assert len(analyst.get("/api/systems").json()) == 1


def test_auditor_is_read_only(analyst, make_user):
    """AK-7, AK-52"""
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    auditor = make_user("auditor")
    assert auditor.get("/api/systems").status_code == 200
    assert auditor.get(f"/api/systems/{s['id']}").status_code == 200
    assert auditor.get(f"/api/interviews/{iv['id']}").status_code == 200
    assert auditor.get("/api/stride-mapping").status_code == 200
    body = {"name": "B", "owner_name": "x", "criticality": 2}
    assert auditor.post("/api/systems", json=body).status_code == 403
    assert auditor.patch(f"/api/systems/{s['id']}", json=body).status_code == 403
    assert auditor.delete(f"/api/systems/{s['id']}").status_code == 403
    assert auditor.post(f"/api/systems/{s['id']}/interviews").status_code == 403
    assert auditor.delete(f"/api/interviews/{iv['id']}").status_code == 403
    # analysts see the mapping but cannot change it
    assert analyst.put("/api/stride-mapping/spoofing", json={"l2_ids": []}).status_code == 403
    r = analyst.put("/api/stride-mapping/threshold", json={"proposal_threshold": 5})
    assert r.status_code == 403


# ---------------------------------------------------------------- interview capture


def test_start_interview_prefills_and_single_draft(analyst):
    """AK-8, AK-16"""
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    assert iv["status"] == "draft"
    assert iv["interview_date"] == TODAY.isoformat()
    assert iv["participants"] == "J. Jansen"
    assert analyst.post(f"/api/systems/{s['id']}/interviews").status_code == 409
    assert analyst.get(f"/api/systems/{s['id']}").json()["draft_id"] == iv["id"]


def test_future_date_and_duplicate_component_are_rejected(analyst):
    """AK-9, AK-11"""
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    save(analyst, iv, 422, interview_date=(TODAY + timedelta(days=5)).isoformat())
    dup = [component("a", "API"), component("b", "api")]
    r = save(analyst, iv, 422, components=dup)
    assert "already a component" in r["detail"]


def test_draft_keeps_input_and_marks_incomplete_threats(analyst):
    """AK-12, AK-13, AK-15"""
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    comps = [
        component(
            threats=[
                threat("spoofing", likelihood=3, impact=4),
                threat("tampering", likelihood=None, impact=2, description=""),
            ]
        )
    ]
    saved = save(analyst, iv, components=comps, notes="first notes")
    again = analyst.get(f"/api/interviews/{iv['id']}").json()
    assert again["notes"] == "first notes"
    threats = {t["category"]: t for t in again["view"]["components"][0]["threats"]}
    assert threats["spoofing"]["score"] == 12
    assert threats["tampering"]["complete"] is False
    assert threats["repudiation"]["state"] == "not_discussed"
    assert again["view"]["incomplete"] == [{"component": "Web front end", "category": "tampering"}]
    assert saved["version"] == iv["version"] + 1


def test_inline_log_source_and_removed_log_source(analyst, admin):
    """AK-14, EC-4"""
    r = analyst.post("/api/references/log_source", json={"name": "Azure AD sign-in"})
    assert r.status_code == 201
    new_id = r.json()["id"]
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    iv = save(analyst, iv, components=[component(log_source_ids=[new_id])])
    assert iv["view"]["components"][0]["log_sources"] == [
        {"id": new_id, "name": "Azure AD sign-in"}
    ]
    names = [i["name"] for i in analyst.get("/api/references/log_source").json()]
    assert "Azure AD sign-in" in names
    # issue #39: the interview counts as a user of the log source
    items = {i["id"]: i for i in analyst.get("/api/references/log_source").json()}
    assert items[new_id]["used_by_systems"] == [s["name"]]
    r = admin.delete(f"/api/references/log_source/{new_id}")
    assert r.status_code == 409 and r.json()["used_by_systems"] == [s["name"]]
    assert admin.delete(f"/api/references/log_source/{new_id}?confirm=true").status_code == 204
    again = analyst.get(f"/api/interviews/{iv['id']}").json()
    assert again["view"]["components"][0]["log_sources"] == []


def test_concurrent_save_is_rejected(analyst, make_user):
    """EC-5"""
    other = make_user("analyst", "analyst2")
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    save(other, iv, notes="from analyst2")
    r = save(analyst, iv, 409, notes="mine")
    assert r["detail"] == "This draft was changed by analyst2; reload to see the changes"


# ---------------------------------------------------------------- proposals


def test_proposals_from_mapping_and_threshold(analyst):
    """AK-17, AK-18, AK-19"""
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    comps = [
        component(
            "web",
            threats=[
                threat("spoofing", likelihood=3, impact=4),  # 12 >= 8
                threat("repudiation", likelihood=2, impact=3),  # 6 < 8
            ],
        ),
        component(
            "db",
            "Database",
            threats=[
                threat("tampering", likelihood=3, impact=3),  # 9
                threat("information_disclosure", likelihood=4, impact=4),  # 16
            ],
        ),
    ]
    iv = save(analyst, iv, components=comps)
    view = iv["view"]
    proposed = {p["code"]: p for p in view["proposals"]}
    assert {"AO-ACC", "AO-CRE"} <= set(proposed)
    assert [r["code"] for r in proposed["AO-ACC"]["rules"]] == [
        "AO-ACC-01",
        "AO-ACC-02",
        "AO-ACC-03",
    ]
    assert "lifecycle_status" in proposed["AO-ACC"]["rules"][0]
    # repudiation (score 6) is below the threshold
    assert "AO-EVA" not in proposed
    below = view["below_threshold"]
    assert [(b["category"], b["score"]) for b in below] == [("repudiation", 6)]
    assert {"AO-EVA", "PV-ACC"} <= set(codes(below[0]["l2s"]))
    # AO-DBC from tampering (9) and information disclosure (16): once, highest score
    assert codes(view["proposals"]).count("AO-DBC") == 1
    dbc = proposed["AO-DBC"]
    assert dbc["risk_score"] == 16
    assert {x["category"] for x in dbc["sources"]} == {"tampering", "information_disclosure"}


def test_log_source_missing_and_unknown(analyst):
    """AK-20, AK-21"""
    db_log = log_source_id(analyst, "Database log")
    os_log = log_source_id(analyst, "OS logging")
    r = analyst.patch("/api/l3/AO-ACC-01", json={"log_sources": ["Database log", "OS logging"]})
    assert r.status_code == 200, r.text
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    comps = [component(threats=[threat("spoofing")], log_source_ids=[os_log])]
    rules = {
        r["code"]: r
        for p in save(analyst, iv, components=comps)["view"]["proposals"]
        if p["code"] == "AO-ACC"
        for r in p["rules"]
    }
    assert rules["AO-ACC-01"]["missing"] == ["Database log"]
    assert rules["AO-ACC-02"]["unknown"] is True
    assert db_log != os_log


def test_remove_add_and_detection_requests(analyst):
    """AK-22, AK-23, AK-24"""
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    comps = [component(threats=[threat("spoofing")])]
    acc, pri = l2_id(analyst, "AO-ACC"), l2_id(analyst, "AO-PRI")
    ref = {"component": "web", "category": "spoofing"}
    # adding by hand needs at least one threat
    save(analyst, iv, 422, components=comps, added=[{"l2_id": pri, "threats": []}])
    # and the threat must apply
    bad = [{"l2_id": pri, "threats": [{"component": "web", "category": "tampering"}]}]
    save(analyst, iv, 422, components=comps, added=bad)
    iv = save(
        analyst,
        iv,
        components=comps,
        added=[{"l2_id": pri, "threats": [ref]}],
        removed=[{"l2_id": acc, "reason": "covered elsewhere"}],
        requests=[{"key": "r1", "text": "Erkennung von Massen-Überweisungen", "threat": ref}],
    )
    view = iv["view"]
    assert "AO-ACC" not in codes(view["proposals"])
    removed = {r["code"]: r for r in view["removed"]}
    assert removed["AO-ACC"]["reason"] == "covered elsewhere"
    pri_view = next(p for p in view["proposals"] if p["code"] == "AO-PRI")
    assert pri_view["manual"] is True and pri_view["auto"] is False
    assert len(view["requests"]) == 1
    assert view["requests"][0] | {"status_at": None} == {
        "key": "r1",
        "title": "Erkennung von Massen-Überweisungen",
        "description": "",
        "component": "web",
        "component_name": "Web front end",
        "category": "spoofing",
        "status": "open",
        "status_note": "",
        "link": None,
        "status_by": None,
        "status_at": None,
    }


def test_not_applicable_l1_is_not_proposed(admin, analyst):
    """AK-25: FE-CEO is mapped to spoofing; its L1 FE is set to "not applicable"."""
    assert admin.patch("/api/l1/FE", json={"applicable": False}).status_code == 200
    s = new_system(analyst)
    iv = save(
        analyst, start(analyst, s["id"]), components=[component(threats=[threat("spoofing")])]
    )
    assert "AO-ACC" in codes(iv["view"]["proposals"])
    assert "FE-CEO" not in codes(iv["view"]["proposals"])
    added = [
        {
            "l2_id": l2_id(analyst, "FE-CEO"),
            "threats": [{"component": "web", "category": "spoofing"}],
        }
    ]
    iv = save(analyst, iv, added=added)
    p = next(p for p in iv["view"]["proposals"] if p["code"] == "FE-CEO")
    assert p["l1_applicable"] is False


def test_empty_mapping_and_no_threats(admin, analyst):
    """EC-7, EC-8"""
    for cat in admin.get("/api/stride-mapping").json()["categories"]:
        admin.put(f"/api/stride-mapping/{cat['category']}", json={"l2_ids": []})
    s = new_system(analyst)
    iv = save(
        analyst, start(analyst, s["id"]), components=[component(threats=[threat("spoofing")])]
    )
    assert iv["view"]["mapping_empty"] is True
    assert iv["view"]["proposals"] == []


# ---------------------------------------------------------------- complete, confirm, delete


def test_complete_requires_component_and_complete_threats(analyst):
    """AK-10, AK-26"""
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    r = complete(analyst, iv, 422)
    assert "at least one component" in r["detail"]
    iv = save(analyst, iv, components=[component(threats=[threat("spoofing", description="")])])
    r = complete(analyst, iv, 422)
    assert "Web front end / spoofing" in r["detail"]


def test_complete_links_and_read_only(analyst, admin):
    """AK-27, AK-32, AK-4, AK-56"""
    s = new_system(analyst)
    iv = start(analyst, s["id"])
    keep = {l2_id(analyst, "AO-ACC"), l2_id(analyst, "AO-CRE")}
    mapped = admin.get("/api/stride-mapping").json()["categories"][0]["l2s"]
    removed = [{"l2_id": x["l2_id"], "reason": ""} for x in mapped if x["l2_id"] not in keep]
    iv = save(analyst, iv, components=[component(threats=[threat("spoofing")])], removed=removed)
    done = complete(analyst, iv)
    assert done["status"] == "completed"
    detail = analyst.get(f"/api/systems/{s['id']}").json()
    assert sorted(codes(detail["links"])) == ["AO-ACC", "AO-CRE"]
    assert detail["links"][0]["sources"] == [
        {"component": "Web front end", "category": "spoofing", "score": 12}
    ]
    assert detail["state"] == "ok"
    assert detail["last_interview"] == TODAY.isoformat()
    assert detail["can_delete"] is False
    # read-only now
    save(analyst, done, 409, notes="change")
    assert analyst.delete(f"/api/interviews/{iv['id']}").status_code == 409
    assert analyst.delete(f"/api/systems/{s['id']}").status_code == 409
    entries = admin.get("/api/audit?limit=50").json()
    entry = next(e for e in entries if e["action"] == "complete")
    assert entry["username"] == "analyst1"
    assert entry["entity"] == "interview"
    assert entry["changes"]["system"] == "Online banking"


def test_complete_without_use_cases(analyst):
    """AK-28, EC-7"""
    s = new_system(analyst)
    comps = [component(threats=[threat("spoofing", state="does_not_apply")])]
    iv = save(analyst, start(analyst, s["id"]), components=comps)
    assert iv["view"]["proposals"] == []
    done = complete(analyst, iv)
    assert done["status"] == "completed"
    assert analyst.get(f"/api/systems/{s['id']}").json()["links"] == []


def test_confirm_and_unconfirm(analyst, admin):
    """AK-29, AK-30, AK-31"""
    s = new_system(analyst)
    past = (TODAY - timedelta(days=10)).isoformat()
    iv = save(analyst, start(analyst, s["id"]), components=[component()], interview_date=past)
    iv = complete(analyst, iv)
    url = f"/api/interviews/{iv['id']}/confirmation"
    early = (TODAY - timedelta(days=11)).isoformat()
    r = analyst.put(url, json={"confirmed_by": "J. Jansen", "confirmed_at": early})
    assert r.status_code == 422
    r = analyst.put(url, json={"confirmed_by": "J. Jansen", "confirmed_at": TODAY.isoformat()})
    assert r.status_code == 200
    assert r.json()["status"] == "confirmed"
    row = analyst.get(f"/api/systems/{s['id']}").json()["interviews"][0]
    assert (row["confirmed_by"], row["confirmed_at"]) == ("J. Jansen", TODAY.isoformat())
    # issue #42: no silent overwrite, removal needs a reason and keeps the old values
    r = analyst.put(url, json={"confirmed_by": "Mallory", "confirmed_at": TODAY.isoformat()})
    assert r.status_code == 409
    assert analyst.request("DELETE", url, json={"reason": " "}).status_code == 422
    r = analyst.request("DELETE", url, json={"reason": "Wrong person recorded"})
    assert r.status_code == 200
    assert r.json()["status"] == "completed"
    log = admin.get("/api/audit?limit=20").json()
    actions = [e["action"] for e in log]
    assert "unconfirm" in actions and "confirm" in actions
    un = next(e for e in log if e["action"] == "unconfirm")
    assert un["changes"]["confirmed_by"] == "J. Jansen"
    assert un["changes"]["reason"] == "Wrong person recorded"


def test_delete_draft_keeps_links(analyst):
    """AK-33"""
    s = new_system(analyst)
    iv = save(
        analyst, start(analyst, s["id"]), components=[component(threats=[threat("spoofing")])]
    )
    complete(analyst, iv)
    before = codes(analyst.get(f"/api/systems/{s['id']}").json()["links"])
    draft = start(analyst, s["id"])
    assert analyst.delete(f"/api/interviews/{draft['id']}").status_code == 204
    assert codes(analyst.get(f"/api/systems/{s['id']}").json()["links"]) == before


# ---------------------------------------------------------------- re-interview, comparison, due


def test_reinterview_copies_replaces_links_and_compares(analyst):
    """AK-34, AK-35, AK-36, EC-14, EC-15"""
    s = new_system(analyst)
    acc, cre, pri = (l2_id(analyst, c) for c in ("AO-ACC", "AO-CRE", "AO-PRI"))
    first_date = (TODAY - timedelta(days=30)).isoformat()
    ref = {"component": "web", "category": "spoofing"}
    comps = [
        component(threats=[threat("spoofing"), threat("tampering", likelihood=1, impact=2)]),
        component("api", "API", threats=[threat("repudiation", likelihood=1, impact=1)]),
    ]
    iv = start(analyst, s["id"])
    mapping = {
        c["category"]: [x["l2_id"] for x in c["l2s"]]
        for c in analyst.get("/api/stride-mapping").json()["categories"]
    }
    # keep only AO-ACC and AO-CRE from the spoofing proposals
    rm = [{"l2_id": i, "reason": ""} for i in mapping["spoofing"] if i not in (acc, cre)]
    iv = save(
        analyst,
        iv,
        interview_date=first_date,
        notes="first",
        components=comps,
        removed=rm,
        requests=[{"key": "r", "text": "Bulk transfers", "threat": ref}],
    )
    first = complete(analyst, iv)
    assert sorted(codes(first["view"]["proposals"])) == ["AO-ACC", "AO-CRE"]

    second = start(analyst, s["id"])
    assert second["notes"] == ""
    assert second["previous_id"] == first["id"]
    v = second["view"]
    assert [c["name"] for c in v["components"]] == ["Web front end", "API"]
    assert sum(t["state"] == "applies" for c in v["components"] for t in c["threats"]) == 3
    assert [r["title"] for r in v["requests"]] == ["Bulk transfers"]
    # not before the previous interview (EC-15)
    early = (TODAY - timedelta(days=31)).isoformat()
    save(analyst, second, 422, interview_date=early)
    # change: AO-CRE removed, AO-PRI added; API component dropped; spoofing re-rated
    comps2 = [component(threats=[threat("spoofing", likelihood=4, impact=4)])]
    rm2 = rm + [{"l2_id": cre, "reason": "not needed"}]
    second = save(
        analyst,
        second,
        components=comps2,
        removed=rm2,
        added=[{"l2_id": pri, "threats": [ref]}],
        requests=[],
    )
    done = complete(analyst, second)
    assert sorted(codes(done["view"]["proposals"])) == ["AO-ACC", "AO-PRI"]
    detail = analyst.get(f"/api/systems/{s['id']}").json()
    assert sorted(codes(detail["links"])) == ["AO-ACC", "AO-PRI"]
    assert [i["status"] for i in detail["interviews"]] == ["completed", "completed"]
    cmp_ = analyst.get(f"/api/interviews/{done['id']}/compare").json()
    assert cmp_["use_cases_added"] == [
        {"code": "AO-PRI", "name": cmp_["use_cases_added"][0]["name"]}
    ]
    assert codes(cmp_["use_cases_removed"]) == ["AO-CRE"]
    assert cmp_["components_removed"] == ["API"]
    assert cmp_["threats_rerated"] == [
        {"component": "Web front end", "category": "spoofing", "old_score": 12, "new_score": 16}
    ]
    assert {"component": "API", "category": "repudiation"} in cmp_["threats_removed"]
    # the first interview has no predecessor
    assert analyst.get(f"/api/interviews/{first['id']}/compare").status_code == 404


def test_interview_due_and_dashboard_count(analyst):
    """AK-37, AK-38, AK-39, EC-10"""
    a = new_system(analyst, "A")
    new_system(analyst, "B")  # no interview
    c = new_system(analyst, "C")
    old = (TODAY - timedelta(days=410)).isoformat()  # more than 12 months ago
    for s in (a, c):
        iv = save(analyst, start(analyst, s["id"]), components=[component()], interview_date=old)
        complete(analyst, iv)
    recent = new_system(analyst, "D")
    complete(analyst, save(analyst, start(analyst, recent["id"]), components=[component()]))
    rows = {r["name"]: r["state"] for r in analyst.get("/api/systems").json()}
    assert rows == {"A": "due", "B": "none", "C": "due", "D": "ok"}
    assert analyst.get("/api/systems/due-count").json() == {"due": 3}
    assert {r["name"] for r in analyst.get("/api/systems?due=true").json()} == {"A", "B", "C"}
    # archived systems do not count
    body = {k: c[k] for k in ("name", "owner_name", "criticality")} | {"archived": True}
    analyst.patch(f"/api/systems/{c['id']}", json=body)
    assert analyst.get("/api/systems/due-count").json() == {"due": 2}
    # a longer review interval is applied immediately
    body = {k: a[k] for k in ("name", "owner_name", "criticality")} | {"review_interval_months": 24}
    analyst.patch(f"/api/systems/{a['id']}", json=body)
    assert analyst.get("/api/systems/due-count").json() == {"due": 1}


def test_add_months_clamps_day():
    from app.interviews import add_months, risk_level

    assert add_months(date(2025, 1, 31), 1) == date(2025, 2, 28)
    assert add_months(date(2025, 10, 1), 12) == date(2026, 10, 1)
    assert [risk_level(x) for x in (0, 1, 5, 6, 10, 11, 15, 16, 20, 21, 25)] == [
        None, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5,
    ]  # fmt: skip


# ---------------------------------------------------------------- system page


def test_coverage_and_gaps(analyst):
    """AK-40, AK-41, AK-42, AK-43, PD-11"""
    s = new_system(analyst)
    empty = analyst.get(f"/api/systems/{s['id']}").json()
    assert empty["coverage"] is None and empty["links"] == []
    analyst.patch("/api/l3/AO-ACC-01", json={"log_sources": ["Database log"]})
    dbc, acc = l2_id(analyst, "AO-DBC"), l2_id(analyst, "AO-ACC")
    ref = {"component": "web", "category": "spoofing"}
    mapped = analyst.get("/api/stride-mapping").json()["categories"][0]["l2s"]
    rm = [{"l2_id": x["l2_id"], "reason": ""} for x in mapped if x["l2_id"] != acc]
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing")])],
        removed=rm,
        added=[{"l2_id": dbc, "threats": [ref]}],
        requests=[{"key": "r", "text": "Bulk transfers", "threat": ref}],
    )
    complete(analyst, iv)
    d = analyst.get(f"/api/systems/{s['id']}").json()
    assert sorted(codes(d["links"])) == ["AO-ACC", "AO-DBC"]
    weights = {x["code"]: x["weight"] for x in analyst.get("/api/scores").json()["l2"]}
    expected = round(((weights["AO-ACC"] or 0) + (weights["AO-DBC"] or 0)) / 2, 4)
    assert d["coverage"] == expected
    assert d["gap_no_rules"] == [{"code": "AO-DBC", "name": d["gap_no_rules"][0]["name"]}]
    # issue #41: grouped per L2; AO-ACC is blind (its only logged rule gets nothing)
    assert [g["l2_code"] for g in d["gap_log_sources"]] == ["AO-ACC"]
    g = d["gap_log_sources"][0]
    assert g["blind"] is True
    assert [r["rule_code"] for r in g["rules"]] == ["AO-ACC-01"]
    assert g["rules"][0]["missing"] == ["Database log"] and g["rules"][0]["partial"] is False
    assert [
        (g["title"], g["component"], g["category"], g["status"]) for g in d["gap_requests"]
    ] == [("Bulk transfers", "Web front end", "spoofing", "open")]
    assert d["gaps"] == 3


def test_coverage_counts_unscored_as_zero():
    """AK-40: the same average rule as the drivers page (weights 0.6 and none -> 0.3)."""
    weights = [0.6, None]
    vals = [w or 0.0 for w in weights]
    assert round(sum(vals) / len(vals), 4) == 0.3


# ---------------------------------------------------------------- effects elsewhere


def _link(analyst, name: str, likelihood: int, impact: int, archived=False) -> dict:
    s = new_system(analyst, name)
    comps = [component(threats=[threat("spoofing", likelihood=likelihood, impact=impact)])]
    complete(analyst, save(analyst, start(analyst, s["id"]), components=comps))
    if archived:
        body = {k: s[k] for k in ("name", "owner_name", "criticality")} | {"archived": True}
        analyst.patch(f"/api/systems/{s['id']}", json=body)
    return s


def test_use_case_filter_and_needed_by(analyst):
    """AK-44, AK-45"""
    s = _link(analyst, "Online banking", 3, 4)
    linked = analyst.get(f"/api/l2?system={s['id']}").json()
    assert "AO-ACC" in codes(linked)
    assert "DE-PHI" not in codes(linked)
    acc = analyst.get("/api/l2/AO-ACC").json()
    assert acc["systems"] == [{"id": s["id"], "name": "Online banking", "archived": False}]


def test_priorities_use_system_risk(analyst, admin):
    """AK-46, AK-47, EC-9, EC-11"""
    analyst.patch("/api/l3/AO-ACC-01", json={"risk_level": 2})
    analyst.patch("/api/l3/AO-ACC-02", json={"risk_level": 5})
    _link(analyst, "Low", 2, 3)  # score 6 -> level 2
    _link(analyst, "Online banking", 4, 4)  # score 16 -> level 4: the highest system wins
    _link(analyst, "Archived", 5, 5, archived=True)  # level 5 but archived: no effect
    rows = {r["code"]: r for r in analyst.get("/api/growth/gaps").json()["rows"]}
    r1 = rows["AO-ACC-01"]
    assert (r1["risk"], r1["risk_source"], r1["risk_system"]) == (4, "system", "Online banking")
    r2 = rows["AO-ACC-02"]
    assert (r2["risk"], r2["risk_source"], r2["risk_system"]) == (5, "rule", None)
    rule = analyst.get("/api/l3/AO-ACC-01").json()
    assert (rule["effective_risk"], rule["risk_source"]) == (4, "system")


def test_scores_do_not_change(analyst):
    """AK-48"""
    before = analyst.get("/api/scores").json()
    _link(analyst, "Online banking", 5, 5)
    after = analyst.get("/api/scores").json()
    assert before["overall"] == after["overall"]
    assert before["kpis"] == after["kpis"]


# ---------------------------------------------------------------- STRIDE mapping


def test_default_mapping_on_install(admin):
    """AK-49"""
    m = admin.get("/api/stride-mapping").json()
    assert m["threshold"] == 8
    cats = {c["category"]: codes(c["l2s"]) for c in m["categories"]}
    assert cats["elevation_of_privilege"] == ["AO-PER", "AO-PRI", "EX-APP", "IN-RAT", "PV-ACC"]
    assert cats["spoofing"] == sorted(
        ["RE-BRU", "EX-BRU", "AO-BRU", "AO-CRE", "AO-ACC", "AO-CSC", "PH-AAT", "FE-CEO"]
    )


def test_mapping_change_affects_drafts_only(admin, analyst):
    """AK-50, AK-51, EC-16"""
    s = new_system(analyst)
    comps = [component(threats=[threat("spoofing")])]
    done = complete(analyst, save(analyst, start(analyst, s["id"]), components=comps))
    assert "AO-CRE" in codes(done["view"]["proposals"])
    draft = save(analyst, start(analyst, s["id"]), components=comps)
    spoof = admin.get("/api/stride-mapping").json()["categories"][0]
    ids = [x["l2_id"] for x in spoof["l2s"] if x["code"] != "AO-CRE"] + [l2_id(admin, "DE-PHI")]
    r = admin.put("/api/stride-mapping/spoofing", json={"l2_ids": ids})
    assert r.status_code == 200
    draft = analyst.get(f"/api/interviews/{draft['id']}").json()
    assert "DE-PHI" in codes(draft["view"]["proposals"])
    assert "AO-CRE" not in codes(draft["view"]["proposals"])
    # completed interview and system links unchanged
    old = analyst.get(f"/api/interviews/{done['id']}").json()
    assert "AO-CRE" in codes(old["view"]["proposals"])
    assert "AO-CRE" in codes(analyst.get(f"/api/systems/{s['id']}").json()["links"])
    # threshold raised: the spoofing threat (12) is now below it
    admin.put("/api/stride-mapping/threshold", json={"proposal_threshold": 13})
    draft = analyst.get(f"/api/interviews/{draft['id']}").json()
    assert draft["view"]["proposals"] == []
    assert draft["view"]["below_threshold"][0]["score"] == 12
    actions = {(e["action"], e["entity"]) for e in admin.get("/api/audit?limit=50").json()}
    assert ("update", "stride_mapping") in actions


@pytest.mark.parametrize("value", [0, 26])
def test_threshold_range(admin, value):
    """AK-53"""
    r = admin.put("/api/stride-mapping/threshold", json={"proposal_threshold": value})
    assert r.status_code == 422


def test_empty_mapping_is_not_refilled(admin, app):
    """An admin who empties the mapping keeps it empty after a restart."""
    from app.interviews import ensure_default_mapping

    for cat in admin.get("/api/stride-mapping").json()["categories"]:
        admin.put(f"/api/stride-mapping/{cat['category']}", json={"l2_ids": []})
    with app.state.sessionmaker() as db:
        ensure_default_mapping(db)
    assert all(not c["l2s"] for c in admin.get("/api/stride-mapping").json()["categories"])
    r = admin.post("/api/stride-mapping/reset")
    assert r.status_code == 200
    assert any(c["l2s"] for c in r.json()["categories"])


# ---------------------------------------------------------------- deleted use cases


def test_deleted_l2_disappears_from_links(admin, analyst):
    """EC-1, EC-2"""
    assert admin.post("/api/l2", json={"code": "AO-ZZZ", "name": "Temp"}).status_code == 201
    tmp = l2_id(admin, "AO-ZZZ")
    s = new_system(analyst)
    ref = {"component": "web", "category": "spoofing"}
    comps = [component(threats=[threat("spoofing")])]
    done = complete(
        analyst,
        save(
            analyst,
            start(analyst, s["id"]),
            components=comps,
            added=[{"l2_id": tmp, "threats": [ref]}],
        ),
    )
    assert "AO-ZZZ" in codes(analyst.get(f"/api/systems/{s['id']}").json()["links"])
    # issue #48: the linked systems are named first
    r = admin.delete("/api/l2/AO-ZZZ")
    assert r.status_code == 409 and r.json()["systems"] == [s["name"]]
    assert admin.delete("/api/l2/AO-ZZZ?confirm=true").status_code == 204
    log = admin.get("/api/audit?limit=10").json()
    assert any(e["action"] == "unlink" and e["entity_key"] == s["name"] for e in log)
    assert "AO-ZZZ" not in codes(analyst.get(f"/api/systems/{s['id']}").json()["links"])
    view = analyst.get(f"/api/interviews/{done['id']}").json()["view"]
    zzz = next(p for p in view["proposals"] if p["code"] == "AO-ZZZ")
    assert zzz["deleted"] is True and zzz["name"] == "Temp"


# ---------------------------------------------------------------- PDF, export


@pytest.mark.parametrize("lang", ["en", "de", "nl"])
def test_pdf_export(analyst, lang):
    """AK-54, AK-55, AK-58"""
    s = new_system(analyst, owner_email="j.jansen@example.org")
    ref = {"component": "web", "category": "spoofing"}
    analyst.patch("/api/l3/AO-ACC-01", json={"log_sources": ["Database log"]})
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[component(threats=[threat("spoofing", description="Phishing ä ö ü – €")])],
        requests=[{"key": "r", "text": "Massen-Überweisungen", "threat": ref}],
        notes="Notes",
    )
    r = analyst.get(f"/api/interviews/{iv['id']}/pdf?lang={lang}")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    done = complete(analyst, iv)
    r = analyst.get(f"/api/interviews/{done['id']}/pdf?lang={lang}")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


def test_pdf_watermark_only_on_draft(analyst):
    """AK-55: the draft PDF carries the watermark text, the completed one does not."""
    from app import interview_report
    from app.api.systems import InterviewOut

    s = new_system(analyst)
    iv = save(
        analyst, start(analyst, s["id"]), components=[component(threats=[threat("spoofing")])]
    )

    class Sys:
        owner_name, owner_department, owner_email = "J. Jansen", "", None
        criticality, internet_facing, data_classification, description = 4, False, "internal", ""

    calls = []
    orig = interview_report._Pdf.__init__

    def spy(self, title, watermark, page_word):
        calls.append(watermark)
        orig(self, title, watermark, page_word)

    interview_report._Pdf.__init__ = spy
    try:
        interview_report.build(InterviewOut(**iv), Sys, "de", "MaGMa")
        interview_report.build(InterviewOut(**(iv | {"status": "completed"})), Sys, "en", "MaGMa")
    finally:
        interview_report._Pdf.__init__ = orig
    assert calls == ["ENTWURF", None]


def test_json_export_contains_systems(analyst, admin):
    """AK-57 (export part; the database itself is backed up and restored with db-copy)"""
    s = new_system(analyst)
    iv = save(
        analyst, start(analyst, s["id"]), components=[component(threats=[threat("spoofing")])]
    )
    done = complete(analyst, iv)
    analyst.put(
        f"/api/interviews/{done['id']}/confirmation",
        json={"confirmed_by": "J. Jansen", "confirmed_at": TODAY.isoformat()},
    )
    data = admin.get("/api/export/json").json()
    assert data["version"] == 3
    sysx = data["systems"][0]
    assert sysx["name"] == "Online banking"
    assert sysx["interviews"][0]["status"] == "confirmed"
    assert sysx["interviews"][0]["confirmed_by"] == "J. Jansen"
    assert "AO-ACC" in [x["l2"] for x in sysx["links"]]
    assert {"category": "spoofing", "l2": "AO-ACC"} in data["stride_mapping"]
    assert data["interview_settings"] == {"proposal_threshold": 8, "log_source_filter": False}


def test_reinterview_on_the_same_day(analyst):
    """Two interviews completed on the same day: the later one holds the links."""
    s = new_system(analyst)
    comps = [component(threats=[threat("spoofing")])]
    first = complete(analyst, save(analyst, start(analyst, s["id"]), components=comps))
    second = start(analyst, s["id"])
    rm = [{"l2_id": p["l2_id"], "reason": ""} for p in first["view"]["proposals"]]
    rm = [r for r in rm if r["l2_id"] != l2_id(analyst, "AO-ACC")]
    done = complete(analyst, save(analyst, second, removed=rm))
    assert codes(done["view"]["proposals"]) == ["AO-ACC"]
    assert codes(analyst.get(f"/api/systems/{s['id']}").json()["links"]) == ["AO-ACC"]
    cmp_ = analyst.get(f"/api/interviews/{done['id']}/compare").json()
    assert "AO-CRE" in codes(cmp_["use_cases_removed"])
