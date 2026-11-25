"""Tasks on L2 use cases and L3 rules (issue #74, PROJ-5).

Analysts and admins add tasks (review, tune, update settings ...) with a Markdown text, an
optional due date and an optional assignee; everyone who can read the catalogue sees them. The
central list (/api/tasks) shows all tasks, open ones by default. Tasks go with their use case or
rule: deleting it deletes its tasks.
"""

from datetime import UTC, date, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from app import audit
from app.api.deps import DB
from app.models import L2UseCase, L3UseCase, Role, Task, TaskKind, TaskStatus, User
from app.schemas import TEXT_MAX
from app.security import Editor, Reader

router = APIRouter(tags=["tasks"])

Title = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
Body = Annotated[str, StringConstraints(max_length=TEXT_MAX)]


class TaskIn(BaseModel):
    kind: TaskKind = TaskKind.other
    title: Title
    body: Body = ""
    due_date: date | None = None
    assignee: Annotated[str, Field(max_length=64)] | None = None


class TaskPatch(BaseModel):
    kind: TaskKind | None = None
    title: Title | None = None
    body: Body | None = None
    due_date: date | None = None
    assignee: Annotated[str, Field(max_length=64)] | None = None
    status: TaskStatus | None = None


class TaskOut(BaseModel):
    id: int
    level: Literal["l2", "l3"]
    code: str
    name: str
    kind: TaskKind
    title: str
    body: str
    status: TaskStatus
    created_by: str
    created_at: datetime
    due_date: date | None
    overdue: bool
    assignee: str | None
    done_by: str | None
    done_at: datetime | None


class AssigneeOut(BaseModel):
    username: str
    display_name: str


def task_out(t: Task, today: date | None = None) -> TaskOut:
    owner = t.l3 if t.l3_id else t.l2
    today = today or date.today()
    return TaskOut(
        id=t.id,
        level="l3" if t.l3_id else "l2",
        code=owner.code,
        name=owner.name,
        kind=t.kind,
        title=t.title,
        body=t.body,
        status=t.status,
        created_by=t.created_by,
        created_at=t.created_at,
        due_date=t.due_date,
        overdue=t.status == TaskStatus.open and t.due_date is not None and t.due_date < today,
        assignee=t.assignee,
        done_by=t.done_by,
        done_at=t.done_at,
    )


def _query():
    return select(Task).options(selectinload(Task.l2), selectinload(Task.l3))


def _owner(db: Session, level: str, code: str):
    model = {"l2": L2UseCase, "l3": L3UseCase}[level]
    obj = db.scalar(select(model).where(model.code == code))
    if obj is None:
        raise HTTPException(404, f"{level.upper()} use case not found")
    return obj


def _assignable(db: Session, username: str | None) -> str | None:
    """Tasks go to people who can work on use cases: active admins and analysts."""
    if not username:
        return None
    u = db.scalar(select(User).where(User.username == username))
    if u is None or not u.active or u.role not in (Role.admin, Role.analyst):
        raise HTTPException(422, f"Cannot assign a task to {username}")
    return u.username


def _get(db: Session, task_id: int) -> Task:
    t = db.scalar(_query().where(Task.id == task_id))
    if t is None:
        raise HTTPException(404, "Task not found")
    return t


def _label(t: Task) -> str:
    owner = t.l3 if t.l3_id else t.l2
    return f"{owner.code}#{t.id}"


@router.get("/tasks", response_model=list[TaskOut])
def list_tasks(
    _: Reader,
    db: DB,
    status: Literal["open", "done", "all"] = "open",
    assignee: str | None = Query(None, description="Username; '-' for unassigned"),
    kind: TaskKind | None = None,
    overdue: bool = False,
    limit: int = Query(500, ge=1, le=2000),
) -> list[TaskOut]:
    q = _query()
    if status != "all":
        q = q.where(Task.status == status)
    if assignee == "-":
        q = q.where(Task.assignee.is_(None))
    elif assignee:
        q = q.where(Task.assignee == assignee)
    if kind:
        q = q.where(Task.kind == kind)
    if overdue:
        q = q.where(Task.status == TaskStatus.open, Task.due_date < date.today())
    # due first (oldest due date first), then the newest without a due date
    q = q.order_by(Task.due_date.is_(None), Task.due_date, Task.created_at.desc(), Task.id.desc())
    today = date.today()
    return [task_out(t, today) for t in db.scalars(q.limit(limit))]


@router.get("/tasks/assignees", response_model=list[AssigneeOut])
def assignees(_: Reader, db: DB) -> list[AssigneeOut]:
    users = db.scalars(
        select(User)
        .where(User.active, or_(User.role == Role.admin, User.role == Role.analyst))
        .order_by(User.username)
    )
    return [AssigneeOut(username=u.username, display_name=u.display_name or "") for u in users]


for _level in ("l2", "l3"):

    def _make(level: str) -> None:
        @router.get(f"/{level}/{{code}}/tasks", response_model=list[TaskOut])
        def owner_tasks(code: str, _: Reader, db: DB) -> list[TaskOut]:
            obj = _owner(db, level, code)
            col = Task.l2_id if level == "l2" else Task.l3_id
            q = _query().where(col == obj.id)
            q = q.order_by(Task.status, Task.due_date.is_(None), Task.due_date, Task.id.desc())
            return [task_out(t) for t in db.scalars(q)]

        @router.post(f"/{level}/{{code}}/tasks", response_model=TaskOut, status_code=201)
        def add_task(code: str, body: TaskIn, user: Editor, db: DB) -> TaskOut:
            obj = _owner(db, level, code)
            t = Task(
                kind=body.kind,
                title=body.title,
                body=body.body,
                due_date=body.due_date,
                assignee=_assignable(db, body.assignee),
                status=TaskStatus.open,
                created_by=user.username,
            )
            setattr(t, level, obj)
            db.add(t)
            db.flush()
            audit.record(
                db,
                user,
                "create",
                "task",
                _label(t),
                body.model_dump(mode="json") | {"assignee": t.assignee},
            )
            db.commit()
            return task_out(_get(db, t.id))

    _make(_level)


@router.patch("/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: int, body: TaskPatch, user: Editor, db: DB) -> TaskOut:
    t = _get(db, task_id)
    data = body.model_dump(exclude_unset=True)
    for k in ("kind", "title", "body", "status"):
        if k in data and data[k] is None:
            raise HTTPException(422, f"{k} cannot be empty")
    if "assignee" in data:
        data["assignee"] = _assignable(db, data["assignee"])
    before = {k: getattr(t, k) for k in data}
    new_status = data.pop("status", None)
    for k, v in data.items():
        setattr(t, k, v)
    if new_status is not None and new_status != t.status:
        t.status = new_status
        if new_status == TaskStatus.done:
            t.done_by, t.done_at = user.username, datetime.now(UTC)
        else:
            t.done_by = t.done_at = None
    after = data | ({"status": new_status} if new_status is not None else {})
    changes = audit.diff(before, after)
    if changes:
        audit.record(db, user, "update", "task", _label(t), changes)
    db.commit()
    return task_out(_get(db, t.id))


@router.delete("/tasks/{task_id}", status_code=204)
def delete_task(task_id: int, user: Editor, db: DB) -> Response:
    t = _get(db, task_id)
    if user.role != Role.admin and t.created_by != user.username:
        raise HTTPException(403, "Only the creator or an admin can delete a task")
    audit.record(db, user, "delete", "task", _label(t), {"title": t.title})
    db.delete(t)
    db.commit()
    return Response(status_code=204)
