# ruff: noqa: E501
"""PROJ-4: rounds, comments and the history of a test, collaboration of a campaign.

Test names carry the acceptance criterion (AK-n) or edge case (EC-n) of features/PROJ-4.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.conftest import login
from tests.test_proj3_tests import RULE, campaign, history, iso, red_user, rule_state  # noqa: F401


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


@pytest.fixture
def auditor(make_user):
    return make_user("auditor")


@pytest.fixture
def scopes(admin):
    for n in ("Windows", "Linux"):
        admin.post("/api/references/scope", json={"name": n})
    admin.patch(
        f"/api/l3/{RULE}",
        json={
            "scopes": ["Windows", "Linux"],
            "attack_techniques": ["T1059.001"],
            "lifecycle_status": "operational",
            "verification_interval_days": 60,
        },
    )


@pytest.fixture
def setup(admin, analyst, app, scopes):
    """A running campaign with one test (linked to the rule, both scopes) and a red team account."""
    rid, rt = red_user(admin, app)
    c = campaign(analyst, "purple", [rid])
    analyst.post(f"/api/campaigns/{c['id']}/status", json={"status": "running"})
    t = analyst.post(
        f"/api/campaigns/{c['id']}/tests",
        json={
            "title": "PowerShell",
            "technique": "T1059.001",
            "links": [{"l3_code": RULE, "scopes": ["Windows", "Linux"]}],
        },
    ).json()
    return {"c": c, "t": t, "rt": rt, "rid": rid}


def red(client, tid, n, status="executed", start=None, **extra):
    body = {
        "exec_status": status,
        "started_at": start if start is not None else iso(3),
        "red_notes": "n",
        "executed_what": "v1",
    } | extra
    r = client.put(f"/api/tests/{tid}/rounds/{n}/red", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def blue(client, tid, n, outcome="alerted", detected=None, **extra):
    body = {"outcome": outcome, "detected_at": detected, "blue_notes": "b"} | extra
    r = client.put(f"/api/tests/{tid}/rounds/{n}/blue", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def detail(client, tid):
    r = client.get(f"/api/tests/{tid}")
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------ rounds


def test_ak1_new_test_has_one_open_round(setup):  # AK-1
    d = detail(setup["rt"], setup["t"]["id"])
    assert d["round_count"] == 1 and d["rounds"][0]["state"] == "open" and d["status"] == "open"


def test_ak3_4_5_new_round_only_after_the_last_is_done(analyst, setup):  # AK-3, AK-4, AK-5
    tid = setup["t"]["id"]
    r = analyst.post(f"/api/tests/{tid}/rounds")
    assert r.status_code == 409 and "Round 1 is still open" in r.text
    red(analyst, tid, 1)
    assert analyst.post(f"/api/tests/{tid}/rounds").status_code == 409  # waiting for blue
    assert detail(analyst, tid)["status"] == "waiting"
    blue(analyst, tid, 1, "not_detected")
    d = analyst.post(f"/api/tests/{tid}/rounds").json()
    assert d["round_count"] == 2 and d["rounds"][1]["state"] == "open"
    assert d["rounds"][1]["executed_what"] == "v1"  # carried over
    assert d["rounds"][1]["exec_status"] == "not_run" and d["rounds"][1]["outcome"] is None


def test_ak19_a_later_successful_round_closes_the_gap(analyst, setup):  # AK-19
    tid = setup["t"]["id"]
    red(analyst, tid, 1, start=iso(5))
    blue(analyst, tid, 1, "not_detected")
    assert len(analyst.get("/api/test-gaps").json()) == 2
    assert rule_state(analyst)["state"] == "issues"
    analyst.post(f"/api/tests/{tid}/rounds")
    red(analyst, tid, 2, start=iso(2))
    # an unfinished round changes nothing (AK-18)
    assert len(analyst.get("/api/test-gaps").json()) == 2
    blue(analyst, tid, 2, "alerted", detected=iso(2, 11))
    assert analyst.get("/api/test-gaps").json() == []
    assert rule_state(analyst)["state"] == "verified"
    d = detail(analyst, tid)
    assert d["outcome"] == "alerted" and d["round_count"] == 2


def test_ak20_a_later_failure_removes_the_verification(analyst, setup):  # AK-20
    tid = setup["t"]["id"]
    red(analyst, tid, 1, start=iso(5))
    blue(analyst, tid, 1, "alerted")
    assert rule_state(analyst)["state"] == "verified"
    analyst.post(f"/api/tests/{tid}/rounds")
    red(analyst, tid, 2, start=iso(1))
    blue(analyst, tid, 2, "logged")
    assert rule_state(analyst)["state"] == "issues"
    assert len(analyst.get("/api/test-gaps").json()) == 2


def test_ak21_acceptance_is_for_one_result(analyst, setup):  # AK-21
    tid = setup["t"]["id"]
    red(analyst, tid, 1, start=iso(5))
    blue(analyst, tid, 1, "not_detected")
    for g in analyst.get("/api/test-gaps").json():
        analyst.post(
            "/api/test-gaps/accept",
            json={
                "l3_code": g["l3_code"],
                "technique": g["technique"],
                "scope": g["scope"],
                "test_id": g["test_id"],
                "reason": "ok for now",
            },
        )
    assert analyst.get("/api/test-gaps/count").json() == {"open": 0}
    analyst.post(f"/api/tests/{tid}/rounds")
    red(analyst, tid, 2, start=iso(1))
    blue(analyst, tid, 2, "logged")
    assert analyst.get("/api/test-gaps/count").json()["open"] == 2  # a new result, a new gap


def test_ak6_ak7_round_limit_and_deleting_an_empty_round(analyst, setup):  # AK-6, AK-7
    tid = setup["t"]["id"]
    red(analyst, tid, 1, status="not_executable")  # done without a result
    d = analyst.post(f"/api/tests/{tid}/rounds").json()
    assert d["rounds"][1]["can_delete"] is True
    assert (
        analyst.delete(f"/api/tests/{tid}/rounds/1").status_code == 409
    )  # not the latest, has entries
    assert analyst.delete(f"/api/tests/{tid}/rounds/2").json()["round_count"] == 1
    for n in range(2, 21):
        analyst.post(f"/api/tests/{tid}/rounds")
        red(analyst, tid, n, status="not_executable")
    r = analyst.post(f"/api/tests/{tid}/rounds")
    assert r.status_code == 409 and "at most 20" in r.text


def test_ak8_rounds_only_while_running(analyst, setup):  # AK-8
    tid, cid = setup["t"]["id"], setup["c"]["id"]
    red(analyst, tid, 1)
    blue(analyst, tid, 1, "alerted")
    analyst.post(f"/api/campaigns/{cid}/status", json={"status": "closed"})
    assert analyst.post(f"/api/tests/{tid}/rounds").status_code == 409
    assert (
        analyst.put(f"/api/tests/{tid}/rounds/1/blue", json={"outcome": "logged"}).status_code
        == 409
    )
    assert analyst.post(f"/api/tests/{tid}/comments", json={"text": "late"}).status_code == 409


def test_ak9_ak11_ak12_ak16_validation(analyst, setup):  # AK-9, AK-11, AK-12, AK-16
    tid = setup["t"]["id"]
    bad = analyst.put(f"/api/tests/{tid}/rounds/1/red", json={"exec_status": "executed"})
    assert bad.status_code == 422 and "started" in bad.text
    bad = analyst.put(
        f"/api/tests/{tid}/rounds/1/red",
        json={"exec_status": "executed", "started_at": iso(2, 12), "ended_at": iso(2, 9)},
    )
    assert bad.status_code == 422
    red(analyst, tid, 1, start=iso(2, 12))
    bad = analyst.put(
        f"/api/tests/{tid}/rounds/1/blue", json={"outcome": "alerted", "detected_at": iso(2, 9)}
    )
    assert bad.status_code == 422
    blue(analyst, tid, 1, "alerted")
    analyst.post(f"/api/tests/{tid}/rounds")
    early = analyst.put(
        f"/api/tests/{tid}/rounds/2/red", json={"exec_status": "executed", "started_at": iso(3)}
    )
    assert early.status_code == 422 and "previous round" in early.text


def test_ak15_result_needs_an_executed_round(analyst, setup):  # AK-15
    tid = setup["t"]["id"]
    assert (
        analyst.put(f"/api/tests/{tid}/rounds/1/blue", json={"outcome": "alerted"}).status_code
        == 422
    )


def test_ak2_existing_test_becomes_one_round(analyst, setup):  # AK-2 (the data of a quick test)
    r = analyst.post(
        "/api/quick-tests",
        json={
            "title": "q",
            "technique": "T1059.001",
            "links": [{"l3_code": RULE, "scopes": ["Windows", "Linux"]}],
            "exec_status": "executed",
            "executed_at": iso(2),
            "outcome": "alerted",
        },
    )
    assert r.status_code == 201
    d = detail(analyst, r.json()["id"])
    assert d["round_count"] == 1 and d["rounds"][0]["outcome"] == "alerted"
    assert rule_state(analyst)["state"] == "verified"


def test_migration_turns_a_test_into_one_round(tmp_path):  # AK-2
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text

    url = f"sqlite:///{tmp_path}/m.db"
    cfg = Config()
    cfg.set_main_option(
        "script_location",
        str(__import__("pathlib").Path(__import__("app").__file__).parent / "migrations"),
    )
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "0022")
    eng = create_engine(url)
    now = datetime.now(UTC).isoformat(sep=" ")
    with eng.begin() as c:
        c.execute(
            text(
                "INSERT INTO test_cases (id, title, technique, description, procedure, tools, prerequisites, expected_detection, created_by, created_by_red_team, created_at, updated_at, exec_status, executed_at, red_notes, red_by, outcome, blue_notes, blue_by, version, red_version, blue_version) VALUES (1, 'old', 'T1003', '', '', '', '', '', 'ann', 0, :n, :n, 'executed', :n, 'rn', 'ann', 'alerted', 'bn', 'ann', 1, 3, 4)"
            ),
            {"n": now},
        )
        c.execute(
            text(
                "INSERT INTO test_attachments (test_id, side, filename, content_type, size, sha256, data, uploaded_by, uploaded_at) VALUES (1, 'red', 'a.pdf', 'application/pdf', 1, 'x', X'00', 'ann', :n)"
            ),
            {"n": now},
        )
    command.upgrade(cfg, "head")
    with eng.connect() as c:
        row = c.execute(
            text(
                "SELECT number, outcome, red_notes, blue_notes, red_version, blue_version, started_at FROM test_rounds WHERE test_id = 1"
            )
        ).one()
        assert (
            row[0] == 1
            and row[1] == "alerted"
            and row[2] == "rn"
            and row[3] == "bn"
            and (row[4], row[5]) == (3, 4)
            and row[6] is not None
        )
        att = c.execute(text("SELECT round_id FROM test_attachments")).scalar()
        assert att is not None


# ------------------------------------------------------------------ detections


def test_ak14a_b_c_detected_by_comes_from_the_reference_list(admin, analyst, setup):  # AK-14a..c
    tid = setup["t"]["id"]
    red(analyst, tid, 1)
    bad = analyst.put(
        f"/api/tests/{tid}/rounds/1/blue",
        json={"outcome": "alerted", "detected_by": ["Made-up tool"]},
    )
    assert bad.status_code == 422 and "Unknown detection technology" in bad.text
    item = analyst.post(
        "/api/references/detection_technology", json={"name": "EDR One", "description": ""}
    ).json()
    d = blue(analyst, tid, 1, "alerted", detected_by=["EDR One"])
    assert d["rounds"][0]["detected_by"] == [{"name": "EDR One", "item_id": item["id"]}]
    analyst.patch(
        f"/api/references/detection_technology/{item['id']}",
        json={"name": "EDR Two", "description": ""},
    )
    assert detail(analyst, tid)["rounds"][0]["detected_by"][0]["name"] == "EDR Two"
    r = admin.delete(f"/api/references/detection_technology/{item['id']}", params={"confirm": True})
    assert r.status_code == 204
    after = detail(analyst, tid)["rounds"][0]["detected_by"]
    assert after == [{"name": "EDR One", "item_id": None}] or after[0]["item_id"] is None


# ------------------------------------------------------------------ comments and history


def test_ak24_25_26_28_30_comments(admin, analyst, auditor, setup):  # AK-24..28, AK-30
    tid, rt = setup["t"]["id"], setup["rt"]
    r = rt.post(f"/api/tests/{tid}/comments", json={"text": "Starting **now**", "round_number": 1})
    assert r.status_code == 201
    e = [x for x in r.json()["events"] if x["kind"] == "comment"][0]
    assert e["side"] == "red" and e["round_number"] == 1 and e["author"] == "rt1"
    analyst.post(f"/api/tests/{tid}/comments", json={"text": "Seen it"})
    assert auditor.post(f"/api/tests/{tid}/comments", json={"text": "x"}).status_code == 403
    assert analyst.post(f"/api/tests/{tid}/comments", json={"text": "   "}).status_code == 422
    assert analyst.post(f"/api/tests/{tid}/comments", json={"text": "x" * 10001}).status_code == 422
    assert auditor.get(f"/api/tests/{tid}").json()["can_comment"] is False
    assert analyst.delete(f"/api/tests/{tid}/comments/{e['id']}").status_code == 403
    d = admin.delete(f"/api/tests/{tid}/comments/{e['id']}").json()
    gone = [x for x in d["events"] if x["id"] == e["id"]][0]
    assert gone["removed"] is True and gone["text"] == "" and gone["removed_by"] == "admin"


def test_ak29_automatic_entries_in_the_history(analyst, setup):  # AK-29
    tid, cid = setup["t"]["id"], setup["c"]["id"]
    red(analyst, tid, 1)
    blue(analyst, tid, 1, "alerted")
    blue(analyst, tid, 1, "logged")  # AK-17
    analyst.post(f"/api/campaigns/{cid}/collaboration", json={"collaboration": "open"})
    kinds = [e["kind"] for e in detail(analyst, tid)["events"]]
    assert kinds[0] == "round_opened"
    for k in ("execution", "result", "result_changed", "collaboration"):
        assert k in kinds
    changed = [e for e in detail(analyst, tid)["events"] if e["kind"] == "result_changed"][0]
    assert changed["data"] == {"old": "alerted", "new": "logged"}


def test_ak27_quick_tests_can_be_commented(analyst):  # AK-27
    t = analyst.post(
        "/api/quick-tests", json={"title": "q", "technique": "T1003", "exec_status": "not_run"}
    ).json()
    assert analyst.post(f"/api/tests/{t['id']}/comments", json={"text": "note"}).status_code == 201
    assert analyst.post(f"/api/tests/{t['id']}/rounds").status_code == 409  # round 1 still open


def test_ak47_two_comments_both_appear(analyst, setup):  # AK-47
    tid, rt = setup["t"]["id"], setup["rt"]
    analyst.post(f"/api/tests/{tid}/comments", json={"text": "one"})
    rt.post(f"/api/tests/{tid}/comments", json={"text": "two"})
    texts = [e["text"] for e in detail(analyst, tid)["events"] if e["kind"] == "comment"]
    assert texts == ["one", "two"]


# ------------------------------------------------------------------ collaboration


def test_ak31_32_hidden_is_the_default_and_hides_the_blue_side(analyst, setup):  # AK-31, AK-32
    tid, rt = setup["t"]["id"], setup["rt"]
    assert setup["c"]["collaboration"] == "hidden"
    red(analyst, tid, 1)
    item = analyst.post(
        "/api/references/detection_technology", json={"name": "SIEM Z", "description": ""}
    ).json()
    blue(analyst, tid, 1, "alerted", detected_by=["SIEM Z"], blue_notes="secret")
    analyst.post(f"/api/tests/{tid}/comments", json={"text": "blue only"})
    rt.post(f"/api/tests/{tid}/comments", json={"text": "red remark"})
    seen = detail(rt, tid)
    r1 = seen["rounds"][0]
    assert (
        r1["blue_hidden"] is True
        and r1["outcome"] is None
        and r1["detected_by"] == []
        and r1["blue_notes"] is None
    )
    assert seen["outcome"] is None
    kinds = {(e["kind"], e["side"]) for e in seen["events"]}
    assert ("comment", "red") in kinds and ("comment", "blue") not in kinds
    assert not any(e["kind"] in ("result", "result_changed") for e in seen["events"])
    assert "secret" not in rt.get(f"/api/tests/{tid}").text and item["id"]


def test_ak33_34_open_shows_everything_and_can_switch_back(analyst, setup):  # AK-33, AK-34
    tid, cid, rt = setup["t"]["id"], setup["c"]["id"], setup["rt"]
    red(analyst, tid, 1)
    blue(analyst, tid, 1, "alerted", blue_notes="visible now")
    analyst.post(f"/api/tests/{tid}/comments", json={"text": "blue comment"})
    assert (
        analyst.post(
            f"/api/campaigns/{cid}/collaboration", json={"collaboration": "open"}
        ).status_code
        == 200
    )
    seen = detail(rt, tid)
    assert (
        seen["rounds"][0]["outcome"] == "alerted"
        and seen["rounds"][0]["blue_notes"] == "visible now"
    )
    assert any(e["kind"] == "comment" and e["side"] == "blue" for e in seen["events"])
    assert rt.get("/api/campaigns").json()[0]["outcomes"] is not None  # AK-37
    analyst.post(f"/api/campaigns/{cid}/collaboration", json={"collaboration": "hidden"})
    assert detail(rt, tid)["rounds"][0]["outcome"] is None
    assert (
        rt.post(f"/api/campaigns/{cid}/collaboration", json={"collaboration": "open"}).status_code
        == 403
    )


def test_ak35_36_closed_shows_the_blue_side(analyst, setup):  # AK-35, AK-36
    tid, cid, rt = setup["t"]["id"], setup["c"]["id"], setup["rt"]
    red(analyst, tid, 1)
    blue(analyst, tid, 1, "logged")
    analyst.post(f"/api/tests/{tid}/comments", json={"text": "debrief"})
    analyst.post(f"/api/campaigns/{cid}/status", json={"status": "closed"})
    seen = detail(rt, tid)
    assert seen["rounds"][0]["outcome"] == "logged"
    assert any(e["kind"] == "comment" and e["side"] == "blue" for e in seen["events"])


def test_ak13_red_cannot_change_the_blue_side(setup, analyst):  # AK-13
    tid, rt = setup["t"]["id"], setup["rt"]
    red(rt, tid, 1)
    assert rt.put(f"/api/tests/{tid}/rounds/1/blue", json={"outcome": "alerted"}).status_code == 403


def test_ak44_attachments_belong_to_a_round(analyst, setup):  # AK-44
    tid, rt = setup["t"]["id"], setup["rt"]
    red(analyst, tid, 1)
    blue(analyst, tid, 1, "not_detected")
    analyst.post(f"/api/tests/{tid}/rounds")
    pdf = b"%PDF-1.4\n%x\n"
    a = rt.post(
        f"/api/tests/{tid}/attachments",
        params={"round": 2},
        files={"file": ("p.pdf", pdf, "application/pdf")},
    )
    assert a.status_code == 201 and a.json()["round"] == 2
    d = detail(analyst, tid)
    assert [x["filename"] for x in d["rounds"][1]["attachments"]] == ["p.pdf"] and d["rounds"][0][
        "attachments"
    ] == []
    assert any(e["kind"] == "file_added" and e["round_number"] == 2 for e in d["events"])


def test_ak46_conflict_per_round_part(analyst, setup):  # AK-46
    tid = setup["t"]["id"]
    d = red(analyst, tid, 1)
    stale = d["rounds"][0]["red_version"] - 1
    r = analyst.put(
        f"/api/tests/{tid}/rounds/1/red",
        json={"exec_status": "executed", "started_at": iso(3), "expected_version": stale},
    )
    assert r.status_code == 409 and "reload" in r.text
    b = analyst.put(
        f"/api/tests/{tid}/rounds/1/blue",
        json={"outcome": "alerted", "expected_version": d["rounds"][0]["blue_version"]},
    )
    assert b.status_code == 200  # the blue part has its own version


def test_ak22_closing_names_the_open_round(analyst, setup):  # AK-22
    tid, cid = setup["t"]["id"], setup["c"]["id"]
    red(analyst, tid, 1)
    blue(analyst, tid, 1, "logged")
    analyst.post(f"/api/tests/{tid}/rounds")
    r = analyst.post(f"/api/campaigns/{cid}/status", json={"status": "closed"})
    assert r.status_code == 409 and "round 2" in r.text


def test_audit_log_has_round_actions(admin, analyst, setup):  # AK-45
    tid = setup["t"]["id"]
    red(analyst, tid, 1)
    analyst.post(f"/api/tests/{tid}/comments", json={"text": "hi"})
    entries = admin.get("/api/audit").json()
    rows = entries["items"] if isinstance(entries, dict) else entries
    actions = {e["action"] for e in rows}
    assert {"execute", "comment"} <= actions


_ = (TestClient, login, timedelta, history)
