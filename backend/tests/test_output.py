from app.dates import months_back


def test_put_validate_and_list(admin, make_user):
    auditor = make_user("auditor")
    this, last = months_back(2)[1], months_back(2)[0]
    body = {"alerts": 40, "incidents": 3, "false_positives": 30, "note": "tuned"}
    url = f"/api/l3/AO-CRE-01/output-metrics/{this:%Y-%m}"
    assert auditor.put(url, json=body).status_code == 403
    r = admin.put(url, json=body)
    assert r.status_code == 200, r.text
    assert r.json()["fp_rate"] == 0.75 and r.json()["source"] == "manual"
    bad = admin.put(
        f"/api/l3/AO-CRE-01/output-metrics/{last:%Y-%m}", json={"alerts": 1, "false_positives": 2}
    )
    assert bad.status_code == 422
    assert admin.put("/api/l3/AO-CRE-01/output-metrics/2026-13", json=body).status_code == 422
    assert admin.put("/api/l3/AO-CRE-01/output-metrics/2999-01", json=body).status_code == 422
    # second PUT for the same month updates in place
    admin.put(f"/api/l3/AO-CRE-01/output-metrics/{this:%Y-%m}", json=body | {"alerts": 50})
    rows = auditor.get("/api/l3/AO-CRE-01/output-metrics").json()
    assert len(rows) == 1 and rows[0]["alerts"] == 50
    s = auditor.get("/api/output-metrics/summary").json()
    assert s["rules_reporting"] == 1 and s["totals"]["alerts"] == 50
    assert s["rules"][0]["code"] == "AO-CRE-01" and len(s["months"]) == 12
    assert admin.delete(f"/api/l3/AO-CRE-01/output-metrics/{this:%Y-%m}").status_code == 204
    assert auditor.get("/api/l3/AO-CRE-01/output-metrics").json() == []


def test_csv_import_dry_run_errors_and_export(admin, make_user):
    a, b = months_back(2)
    good = (
        "Rule;Month;Alerts;Incidents;FP;FN;Note\n"
        f"AO-CRE-01;{a:%Y-%m};10;1;5;;first\n"
        f"ao-cre-02;{b:%Y-%m};20;2;10;1;\n"
    )

    def post(text, dry):
        return admin.post(
            "/api/import/output-metrics",
            files={"file": ("m.csv", text.encode(), "text/csv")},
            data={"dry_run": str(dry).lower()},
        )

    r = post(good, True).json()
    assert (r["rows"], r["created"], r["errors"]) == (2, 2, [])
    assert admin.get("/api/output-metrics/summary").json()["rules_reporting"] == 0

    broken = good + "XX-NOPE-01;2025-01;1;0;0;;\n" + f"AO-CRE-01;{a:%Y-%m};5;0;9;;\n"
    r = post(broken, False).json()
    assert len(r["errors"]) == 2 and "unknown rule" in r["errors"][0]
    assert admin.get("/api/output-metrics/summary").json()["rules_reporting"] == 0

    r = post(good, False).json()
    assert r["created"] == 2 and not r["errors"]
    r = post(good, False).json()
    assert r["updated"] == 2

    analyst = make_user("analyst")
    csv = analyst.get("/api/export/output-metrics.csv").text.splitlines()
    assert csv[0].startswith("rule,period,alerts")
    assert csv[1] == f"AO-CRE-01,{a:%Y-%m},10,1,5,,first"
    assert post("foo,bar\n1,2\n", False).status_code == 422


def test_demo_output_and_report(admin, make_user):
    admin.post("/api/admin/demo-data", json={"seed": 5})
    s = admin.get("/api/output-metrics/summary").json()
    assert s["rules_reporting"] > 10 and s["totals"]["alerts"] > 0
    rules = s["rules"]
    assert rules == sorted(rules, key=lambda r: -r["false_positives"])
    auditor = make_user("auditor")
    r = auditor.get("/api/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert r.headers["content-type"] == "application/pdf"
    assert len(r.content) > 5000


def test_report_on_empty_catalogue(admin):
    r = admin.get("/api/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
