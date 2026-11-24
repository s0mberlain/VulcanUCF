from app import priorities


def test_parse_risk_targets():
    t = priorities.parse_risk_targets("5=0.95, 3=bad, 9=0.1")
    assert t[5] == 0.95 and t[3] == 0.6 and 9 not in t


def test_rule_inherits_risk_and_target(admin):
    admin.patch("/api/l2/AO-CRE", json={"risk_level": 4})
    admin.patch(
        "/api/l3/AO-CRE-01",
        json={
            "effectiveness": 0.9,
            "implementation": 0.5,
            "coverage": 1,
            "lifecycle_status": "operational",
        },
    )
    r = admin.get("/api/l3/AO-CRE-01").json()
    assert r["effective_risk"] == 4 and r["risk_source"] == "l2"
    assert r["effective_target"] == 0.75 and r["target_source"] == "risk"
    assert abs(r["implementation_gap"] - 0.25) < 1e-9
    assert abs(r["priority"] - 0.25 * 4 / 5) < 1e-9  # gap to target x risk / 5

    admin.patch("/api/l2/AO-CRE", json={"target_implementation": 0.6})
    admin.patch("/api/l3/AO-CRE-01", json={"risk_level": 5, "target_implementation": 0.4})
    r = admin.get("/api/l3/AO-CRE-01").json()
    assert (r["effective_risk"], r["risk_source"]) == (5, "rule")
    assert (r["effective_target"], r["target_source"]) == (0.4, "rule")
    assert r["implementation_gap"] == 0


def test_gap_view(admin, make_user):
    auditor = make_user("auditor")
    admin.patch("/api/l2/AO-CRE", json={"risk_level": 5})
    admin.patch(
        "/api/l3/AO-CRE-01",
        json={
            "effectiveness": 0.9,
            "implementation": 0.2,
            "coverage": 0.5,
            "lifecycle_status": "operational",
        },
    )
    admin.patch(
        "/api/l3/AO-CRE-02",
        json={
            "effectiveness": 0.5,
            "implementation": 0.95,
            "coverage": 0.9,
            "lifecycle_status": "operational",
        },
    )
    g = auditor.get("/api/growth/gaps?l1=AO&below_target=true").json()
    codes = [x["code"] for x in g["rows"]]
    assert "AO-CRE-01" in codes and "AO-CRE-02" not in codes
    prios = [x["priority"] or 0 for x in g["rows"]]
    assert prios == sorted(prios, reverse=True)
    assert g["summary"]["by_risk"]["5"]["below_target"] >= 1
    assert g["summary"]["risk_targets"]["5"] == 0.9
    only_high = auditor.get("/api/growth/gaps?min_risk=5").json()["rows"]
    assert all(x["risk"] == 5 for x in only_high)


def test_priority_follows_gap_to_target(admin):
    """A rule that meets its target has nothing to gain; an unassessed rule counts its whole
    target as gap instead of dropping to the bottom of the list."""
    admin.patch("/api/l2/AO-CRE", json={"risk_level": 5})  # target 0.9
    done = {"effectiveness": 1, "implementation": 0.95, "coverage": 0.2}  # big potential
    admin.patch("/api/l3/AO-CRE-01", json=done | {"lifecycle_status": "onboarding"})
    admin.patch(
        "/api/l3/AO-CRE-02",
        json={"effectiveness": None, "implementation": None, "lifecycle_status": "onboarding"},
    )
    met = admin.get("/api/l3/AO-CRE-01").json()
    assert met["implementation_gap"] == 0 and met["priority"] == 0
    new = admin.get("/api/l3/AO-CRE-02").json()
    assert abs(new["priority"] - 0.9) < 1e-9
    rows = admin.get("/api/growth/gaps?l1=AO").json()["rows"]
    codes = [r["code"] for r in rows]
    assert codes.index("AO-CRE-02") < codes.index("AO-CRE-01")
