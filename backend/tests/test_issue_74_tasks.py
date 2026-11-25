"""Issue #74: tasks on L2 use cases and L3 rules, with a central list."""

from datetime import date, timedelta

import pytest


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


def test_add_list_close_and_reopen(admin, analyst):
    r = analyst.post(
        "/api/l3/AO-ACC-01/tasks",
        json={
            "kind": "tune",
            "title": "Lower the threshold",
            "body": "**5** instead of 10",
            "assignee": "admin",
        },
    )
    assert r.status_code == 201, r.text
    task = r.json()
    assert task["level"] == "l3" and task["code"] == "AO-ACC-01"
    assert task["created_by"] == "analyst1" and task["status"] == "open"
    assert task["assignee"] == "admin" and task["due_date"] is None and not task["overdue"]

    past = (date.today() - timedelta(days=1)).isoformat()
    r = analyst.post(
        "/api/l2/AO-ACC/tasks", json={"kind": "review", "title": "Yearly review", "due_date": past}
    )
    assert r.status_code == 201
    l2_task = r.json()
    assert l2_task["level"] == "l2" and l2_task["overdue"]

    # central list: open tasks, overdue first
    all_open = analyst.get("/api/tasks").json()
    assert [x["id"] for x in all_open] == [l2_task["id"], task["id"]]
    assert [x["id"] for x in analyst.get("/api/tasks?overdue=true").json()] == [l2_task["id"]]
    assert [x["id"] for x in analyst.get("/api/tasks?assignee=admin").json()] == [task["id"]]
    assert [x["id"] for x in analyst.get("/api/tasks?assignee=-").json()] == [l2_task["id"]]
    assert [x["id"] for x in analyst.get("/api/l3/AO-ACC-01/tasks").json()] == [task["id"]]

    r = analyst.patch(f"/api/tasks/{task['id']}", json={"status": "done"})
    assert r.status_code == 200 and r.json()["done_by"] == "analyst1"
    assert [x["id"] for x in analyst.get("/api/tasks").json()] == [l2_task["id"]]
    assert len(analyst.get("/api/tasks?status=all").json()) == 2
    r = analyst.patch(f"/api/tasks/{task['id']}", json={"status": "open", "assignee": None})
    assert r.json()["done_by"] is None and r.json()["assignee"] is None

    log = admin.get("/api/audit?entity=task").json()
    assert {e["action"] for e in log} == {"create", "update"}


def test_permissions_and_validation(admin, analyst, make_user):
    auditor = make_user("auditor")
    body = {"title": "Check"}
    assert auditor.post("/api/l2/AO-ACC/tasks", json=body).status_code == 403
    assert analyst.post("/api/l2/NOPE/tasks", json=body).status_code == 404
    assert analyst.post("/api/l2/AO-ACC/tasks", json={"title": " "}).status_code == 422
    # only active admins and analysts can be assigned
    r = analyst.post("/api/l2/AO-ACC/tasks", json=body | {"assignee": "auditor1"})
    assert r.status_code == 422
    names = [u["username"] for u in auditor.get("/api/tasks/assignees").json()]
    assert names == ["admin", "analyst1"]

    tid = admin.post("/api/l2/AO-ACC/tasks", json=body).json()["id"]
    assert auditor.get("/api/tasks").status_code == 200
    # the creator or an admin may delete
    assert analyst.delete(f"/api/tasks/{tid}").status_code == 403
    assert admin.delete(f"/api/tasks/{tid}").status_code == 204
    assert analyst.patch(f"/api/tasks/{tid}", json={"status": "done"}).status_code == 404


def test_tasks_go_with_their_rule(admin):
    r = admin.post("/api/l3", json={"code": "AO-ACC-77", "name": "Temporary rule"})
    assert r.status_code == 201, r.text
    admin.post("/api/l3/AO-ACC-77/tasks", json={"title": "Tune"})
    assert len(admin.get("/api/tasks").json()) == 1
    assert admin.delete("/api/l3/AO-ACC-77").status_code == 204
    assert admin.get("/api/tasks").json() == []
