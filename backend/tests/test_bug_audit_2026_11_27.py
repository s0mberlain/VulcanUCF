"""Fixes from the bug audit of 2026-11-27 (M2, M3, M4 and the CSV field limit)."""

from urllib.parse import unquote

import pytest

from app.dates import months_back
from app.incidents import date_order, parse_created
from tests.test_interviews import new_system, start
from tests.test_output_incidents import metrics, post


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


@pytest.mark.parametrize("name", ["Платёжный шлюз", "Łódź gateway", "Zahlungsverkehr Süd"])
def test_interview_pdf_with_non_latin_system_name(analyst, name):
    s = new_system(analyst, name=name)
    iv = start(analyst, s["id"])
    r = analyst.get(f"/api/interviews/{iv['id']}/pdf?lang=en")
    assert r.status_code == 200, r.text
    disp = r.headers["content-disposition"]
    disp.encode("latin-1")  # a valid header
    assert 'filename="interview-' in disp
    full = unquote(disp.split("filename*=UTF-8''", 1)[1])
    assert full.startswith("interview-" + name.replace(" ", "-"))


def test_task_with_inactive_assignee_can_still_be_edited(admin, analyst, make_user):
    other = make_user("analyst", "leaver")
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["username"] == "leaver")
    t = analyst.post("/api/l2/AO-ACC/tasks", json={"title": "Tune", "assignee": "leaver"}).json()
    assert admin.patch(f"/api/users/{uid}", json={"active": False}).status_code == 200
    other.close()

    # the dialog sends every field, the assignee unchanged
    body = {"kind": "tune", "title": "Tune more", "body": "", "due_date": None}
    r = analyst.patch(f"/api/tasks/{t['id']}", json=body | {"assignee": "leaver"})
    assert r.status_code == 200, r.text
    assert r.json()["title"] == "Tune more" and r.json()["assignee"] == "leaver"
    # assigning to the inactive person anew is still refused, removing works
    t2 = analyst.post("/api/l2/AO-ACC/tasks", json={"title": "Other"}).json()
    assert analyst.patch(f"/api/tasks/{t2['id']}", json={"assignee": "leaver"}).status_code == 422
    r = analyst.patch(f"/api/tasks/{t['id']}", json={"assignee": None})
    assert r.status_code == 200 and r.json()["assignee"] is None


def test_date_order_of_incident_exports():
    assert date_order(["18/09/2026", "05/09/2026"]) == "dmy"
    assert date_order(["9/18/2026 1:00 PM", "9/5/2026 9:00 AM"]) == "mdy"
    assert date_order(["9/5/2026 10:14:00 AM"]) == "mdy"  # US time format
    assert date_order(["05.09.2026 10:00"]) == "dmy"
    assert date_order(["2026-09-05T10:00:00Z"]) == "dmy"
    assert parse_created("9/5/2026 10:14 AM", "mdy").isoformat() == "2026-09-05"
    assert parse_created("05.09.2026", "dmy").isoformat() == "2026-09-05"
    assert parse_created("2026-09-05T10:00:00Z", "mdy").isoformat() == "2026-09-05"


def test_incident_import_us_dates(admin):
    a = months_back(2)[0]  # last month: day 5 and 18 are in the past
    text = (
        "Name,Incident ID,Created on,Classification\n"
        f"AO-CRE-01,901,{a.month}/5/{a.year} 10:14:00 AM,TruePositive\n"
        f"AO-CRE-01,902,{a.month}/18/{a.year} 1:00:00 PM,FalsePositive\n"
    )
    rep = post(admin, text, False).json()
    assert rep["matched_rows"] == 2 and not rep["problems"], rep
    m = metrics(admin, "AO-CRE-01")[f"{a:%Y-%m}"]
    assert m["incidents"] == 1 and m["false_positives"] == 1


def test_csv_field_too_long_is_a_clean_error(admin):
    big = '"' + "A" * 140_000 + '"'
    text = f"Name,Incident ID,Created on\n{big},1,2026-01-01\n"
    r = post(admin, text, True)
    assert r.status_code == 422 and "CSV" in r.json()["detail"]
    r = admin.post(
        "/api/import/output-metrics",
        files={"file": ("m.csv", f"rule,period,alerts,note\nAO-CRE-01,2026-01,1,{big}\n")},
        data={"dry_run": "true"},
    )
    assert r.status_code == 422 and "CSV" in r.json()["detail"]
