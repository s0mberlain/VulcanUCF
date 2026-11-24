"""Output metrics from a Sentinel / Defender XDR incident export (CSV, one row per incident)."""

from app.dates import months_back

URL = "/api/import/output-metrics/incidents"
HEAD = (
    "Name,Case ID,Incident ID,Status,Priority score,Created on,Assigned to,Severity,"
    "Classification,Determination,Tags,Active alerts,Associated threats,Impacted assets,"
    "Last updated on,Last updated by,Last activity,First activity,Category,Detection sources,"
    "Service sources\n"
)


def row(name, iid, created, classification="unknown"):
    # synthetic values only; the layout is that of the real export
    return (
        f'"{name}",{iid + 1000},{iid},Closed,10,{created}T08:00:00.12+00:00,analyst@example.org,'
        f"low,{classification},unknown,,0 / 1,Associated threat,1 Host,"
        f"{created}T09:00:00+00:00,someone,{created}T07:59:00+00:00,{created}T07:58:00+00:00,"
        "InitialAccess,Scheduled detection,Microsoft Sentinel\n"
    )


def post(client, text, dry):
    return client.post(
        URL,
        files={"file": ("incidents.csv", text.encode("utf-8-sig"), "text/csv")},
        data={"dry_run": str(dry).lower()},
    )


def metrics(client, code):
    return {m["period"]: m for m in client.get(f"/api/l3/{code}/output-metrics").json()}


def test_preview_apply_and_idempotent(admin, make_user):
    a, b = months_back(2)
    pa, pb = f"{a:%Y-%m}", f"{b:%Y-%m}"
    da, db_ = f"{a:%Y-%m}-03", f"{b:%Y-%m}-05"
    text = HEAD + "".join(
        [
            row("ACME:AO-CRE-01:Credential dumping", 1, da, "truePositive"),
            row("ACME:AO-CRE-01:Credential dumping", 2, da, "falsePositive"),
            row("ion:AO-CRE-01: Credential dumping involving one user", 3, da, "benignPositive"),
            row("ion:AO-CRE-01: Credential dumping", 4, db_),
            row("ion:AO-BRU-01: Brute force involving one user", 5, db_, "FalsePositive"),
            row("User requested to release an email from Quarantine", 6, db_, "falsePositive"),
            row("User requested to release an email from Quarantine", 7, db_),
            row("ACME:XX-NOPE-01:Rule that is not in the app", 8, db_),
            row("ACME:AO-CRE-01:Credential dumping", 1, da, "truePositive"),  # same id again
        ]
    )
    auditor = make_user("auditor")
    assert post(auditor, text, True).status_code == 403

    r = post(admin, text, True)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["dry_run"] and rep["rows"] == 9 and rep["duplicate_rows"] == 1
    assert (rep["matched_rows"], rep["ignored_rows"], rep["new_incidents"]) == (5, 3, 5)
    assert rep["ignored"][0] == {
        "name": "User requested to release an email from Quarantine",
        "count": 2,
    }
    assert (rep["created"], rep["updated"]) == (3, 0)
    by = {(c["code"], c["period"]): c for c in rep["changes"]}
    assert by[("AO-CRE-01", pa)]["after"] == {"alerts": 3, "incidents": 1, "false_positives": 1}
    assert by[("AO-CRE-01", pa)]["before"] is None
    assert by[("AO-BRU-01", pb)]["after"] == {"alerts": 1, "incidents": 0, "false_positives": 1}
    assert metrics(admin, "AO-CRE-01") == {}  # dry run wrote nothing

    rep = post(admin, text, False).json()
    assert (rep["created"], rep["new_incidents"]) == (3, 5)
    m = metrics(auditor, "AO-CRE-01")
    assert (m[pa]["alerts"], m[pa]["incidents"], m[pa]["false_positives"]) == (3, 1, 1)
    assert m[pa]["source"] == "incidents" and m[pb]["alerts"] == 1

    # the same file again counts nothing twice
    rep = post(admin, text, False).json()
    assert (rep["new_incidents"], rep["unchanged_incidents"], rep["created"], rep["updated"]) == (
        0,
        5,
        0,
        0,
    )
    assert metrics(admin, "AO-CRE-01")[pa]["alerts"] == 3

    # a later export: incident 4 classified, one new incident; other months stay as they are
    later = (
        HEAD
        + row("ion:AO-CRE-01: Credential dumping", 4, db_, "truePositive")
        + row("ion:AO-CRE-01: Credential dumping", 9, db_, "falsePositive")
    )
    rep = post(admin, later, False).json()
    assert (rep["new_incidents"], rep["updated_incidents"], rep["updated"]) == (1, 1, 1)
    m = metrics(admin, "AO-CRE-01")
    assert (m[pb]["alerts"], m[pb]["incidents"], m[pb]["false_positives"]) == (2, 1, 1)
    assert m[pa]["alerts"] == 3

    audit = admin.get("/api/audit").json()
    assert any(e["action"] == "import_incidents" for e in audit)


def test_keeps_false_negatives_and_note(admin):
    a = months_back(1)[0]
    admin.put(
        f"/api/l3/AO-CRE-01/output-metrics/{a:%Y-%m}",
        json={
            "alerts": 40,
            "incidents": 2,
            "false_positives": 10,
            "false_negatives": 1,
            "note": "x",
        },
    )
    text = HEAD + row("AO-CRE-01", 1, f"{a:%Y-%m}-02", "falsePositive")
    rep = post(admin, text, False).json()
    c = rep["changes"][0]
    assert c["before"] == {"alerts": 40, "incidents": 2, "false_positives": 10}
    assert c["after"] == {"alerts": 1, "incidents": 0, "false_positives": 1} and c["changed"]
    m = metrics(admin, "AO-CRE-01")[f"{a:%Y-%m}"]
    assert (m["alerts"], m["false_negatives"], m["note"]) == (1, 1, "x")


def test_matching_by_siem_id_and_siem_name(admin):
    a = months_back(1)[0]
    d = f"{a:%Y-%m}-01"
    admin.patch("/api/l3/AO-ACC-01", json={"siem_rule_ids": ["CC-CK"]})
    admin.put("/api/settings/rule-name", json={"format": "$ucName", "variables": []})
    text = HEAD + "".join(
        [
            row("FESTO:CC-CK:ClickFix - PowerShell download", 1, d),
            row("Detect Brute Force Attack involving one user", 2, d),
            row("Detect Brute Force Attacks everywhere", 3, d),  # not the whole word: ignored
            row("cc-ck", 4, d),
        ]
    )
    rep = post(admin, text, True).json()
    assert rep["matched_rows"] == 3 and rep["ignored_rows"] == 1
    assert {c["code"]: c["after"]["alerts"] for c in rep["changes"]} == {
        "AO-ACC-01": 2,
        "AO-BRU-01": 1,
    }


def test_bad_files_and_rows(admin):
    assert post(admin, "", True).status_code == 422
    r = post(admin, "rule,period,alerts\nAO-CRE-01,2026-01,3\n", True)
    assert r.status_code == 422 and "Incident ID" in r.json()["detail"]
    a = months_back(1)[0]
    text = (
        HEAD
        + row("AO-CRE-01", 1, "not-a-date")
        + row("AO-CRE-01", 2, "2999-01-01")
        + row("AO-CRE-01", 3, f"{a:%Y-%m}-01")
    )
    rep = post(admin, text, False).json()
    assert rep["matched_rows"] == 1 and len(rep["problems"]) == 2
    # semicolon separated, re-saved by a spreadsheet with day-first dates
    semi = (
        "Name;Incident ID;Created on;Classification\n"
        f"AO-CRE-01;77;02.{a:%m.%Y} 10:00;TruePositive\n"
    )
    rep = post(admin, semi, False).json()
    assert rep["matched_rows"] == 1, rep
    assert metrics(admin, "AO-CRE-01")[f"{a:%Y-%m}"]["incidents"] == 1
