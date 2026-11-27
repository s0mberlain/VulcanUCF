import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, type Level, type Task, type TaskKind } from "../api";
import { useAuth } from "../auth";
import { fmtDate } from "../lib/format";
import { Markdown, MarkdownField } from "./Markdown";
import { confirmDialog, ErrorNote, Modal, useLoad } from "./ui";
import { t } from "../i18n";

/** Tasks on L2 use cases and L3 rules (issue #74). */
export const TASK_KINDS: TaskKind[] = ["review", "tune", "update_settings", "other"];
export const TASK_KIND_LABEL: Record<TaskKind, string> = {
  review: t("Review"),
  tune: t("Tune"),
  update_settings: t("Update settings"),
  other: t("Other"),
};

/** Where a task belongs: the rule page or the L2 view of the use case page. */
export function taskOwnerLink(task: Pick<Task, "level" | "code">): string {
  return task.level === "l3" ? `/usecases/l3/${task.code}` : `/usecases?l2=${encodeURIComponent(task.code)}`;
}

export function DueText({ task }: { task: Task }) {
  if (!task.due_date) return <span className="muted">–</span>;
  return (
    <span className={task.overdue ? "due-overdue" : undefined}>
      {fmtDate(task.due_date)}
      {task.overdue && ` · ${t("overdue")}`}
    </span>
  );
}

/** Add or edit a task. */
export function TaskDialog({
  level,
  code,
  task,
  onClose,
  onSaved,
}: {
  level: Level;
  code: string;
  task?: Task;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { user } = useAuth();
  const people = useLoad(() => api.taskAssignees());
  const [kind, setKind] = useState<TaskKind>(task?.kind ?? "review");
  const [title, setTitle] = useState(task?.title ?? "");
  const [body, setBody] = useState(task?.body ?? "");
  const [due, setDue] = useState(task?.due_date ?? "");
  const [assignee, setAssignee] = useState(task?.assignee ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const data = { kind, title, body, due_date: due || null, assignee: assignee || null };
    try {
      // the assignee only when it changed: someone who left or changed role stays assigned
      if (task) await api.updateTask(task.id, (assignee || null) === task.assignee ? { ...data, assignee: undefined } : data);
      else await api.addTask(level, code, data);
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={task ? t("Edit task") : t("New task for {code}", { code })} open onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error ?? people.error} />
        <div className="form-grid">
          <label className="field">
            {t("Kind")}
            <select className="input" value={kind} onChange={(e) => setKind(e.target.value as TaskKind)}>
              {TASK_KINDS.map((k) => (
                <option key={k} value={k}>
                  {TASK_KIND_LABEL[k]}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            {t("Title")}
            <input className="input" required maxLength={255} value={title} onChange={(e) => setTitle(e.target.value)} />
          </label>
          <label className="field">
            {t("Due date (optional)")}
            <input className="input" type="date" value={due} onChange={(e) => setDue(e.target.value)} />
          </label>
          <label className="field">
            {t("Assignee")}
            <select className="input" value={assignee} onChange={(e) => setAssignee(e.target.value)}>
              <option value="">{t("Nobody")}</option>
              {task?.assignee && people.data && !people.data.some((p) => p.username === task.assignee) && (
                <option value={task.assignee}>{t("{user} (no longer assignable)", { user: task.assignee })}</option>
              )}
              {(people.data ?? []).map((p) => (
                <option key={p.username} value={p.username}>
                  {p.display_name ? `${p.display_name} (${p.username})` : p.username}
                  {p.username === user?.username ? ` · ${t("me")}` : ""}
                </option>
              ))}
            </select>
          </label>
        </div>
        <MarkdownField label={t("Description")} value={body} onChange={setBody} rows={5} />
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy || !title.trim()}>
            {busy ? t("Saving…") : task ? t("Save") : t("Add task")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** One task with its text and the actions on it. */
export function TaskItem({
  task,
  showOwner,
  onChanged,
  onEdit,
}: {
  task: Task;
  showOwner?: boolean;
  onChanged: () => void;
  onEdit: (t: Task) => void;
}) {
  const { user, can } = useAuth();
  const editor = can("admin", "analyst");
  const mayDelete = can("admin") || task.created_by === user?.username;
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const done = task.status === "done";

  async function run(call: () => Promise<unknown>) {
    setError(null);
    try {
      await call();
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <li className={"task-item" + (done ? " is-done" : "")}>
      <div className="task-head">
        {editor && (
          <input
            type="checkbox"
            className="task-check"
            checked={done}
            aria-label={done ? t("Reopen {title}", { title: task.title }) : t("Mark {title} as done", { title: task.title })}
            onChange={() => run(() => api.updateTask(task.id, { status: done ? "open" : "done" }))}
          />
        )}
        <button type="button" className="task-title link-btn" aria-expanded={open} onClick={() => setOpen((x) => !x)}>
          {task.title}
        </button>
        <span className="chip">{TASK_KIND_LABEL[task.kind]}</span>
      </div>
      <div className="task-meta small muted">
        {showOwner && (
          <>
            <Link to={taskOwnerLink(task)} className="mono">
              {task.code}
            </Link>{" "}
            ·{" "}
          </>
        )}
        {t("by {user} on {date}", { user: task.created_by, date: fmtDate(task.created_at) })}
        {task.assignee && ` · ${t("assigned to {user}", { user: task.assignee })}`}
        {task.due_date && (
          <>
            {" · "}
            {t("due")} <DueText task={task} />
          </>
        )}
        {done && task.done_by && ` · ${t("done by {user} on {date}", { user: task.done_by, date: fmtDate(task.done_at) })}`}
      </div>
      <ErrorNote error={error} />
      {open && (
        <div className="task-body">
          {task.body.trim() ? <Markdown text={task.body} /> : <p className="muted small">{t("No description.")}</p>}
          {editor && (
            <div className="row-actions start">
              <button type="button" className="btn btn-sm" onClick={() => onEdit(task)}>
                {t("Edit")}
              </button>
              {mayDelete && (
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  onClick={async () => {
                    if (await confirmDialog(t("Delete the task “{title}”?", { title: task.title }), { danger: true, confirmLabel: t("Delete") }))
                      void run(() => api.deleteTask(task.id));
                  }}
                >
                  {t("Delete")}
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </li>
  );
}

/** Tasks of one L2 use case or rule, shown on its page. */
export function TasksPanel({ level, code }: { level: Level; code: string }) {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const tasks = useLoad(() => api.ownerTasks(level, code), [level, code]);
  const [dialog, setDialog] = useState<Task | "new" | null>(null);
  const [showDone, setShowDone] = useState(false);
  const all = tasks.data ?? [];
  const open = all.filter((x) => x.status === "open");
  const done = all.filter((x) => x.status === "done");
  const shown = showDone ? all : open;

  return (
    <section className="card stack" aria-labelledby={`tasks-${code}`}>
      <div className="section-head">
        <h2 id={`tasks-${code}`}>
          {t("Tasks")}
          {open.length > 0 && <span className="pill task-count">{open.length}</span>}
        </h2>
        {editor && (
          <button type="button" className="btn btn-sm" onClick={() => setDialog("new")}>
            {t("+ Add task")}
          </button>
        )}
      </div>
      <ErrorNote error={tasks.error} />
      {tasks.data && !shown.length && <p className="muted small">{t("No open tasks.")}</p>}
      {shown.length > 0 && (
        <ul className="task-list">
          {shown.map((x) => (
            <TaskItem key={x.id} task={x} onChanged={() => void tasks.reload()} onEdit={setDialog} />
          ))}
        </ul>
      )}
      {done.length > 0 && (
        <button type="button" className="link-btn small" onClick={() => setShowDone((x) => !x)}>
          {showDone ? t("Hide done tasks") : t("Show {n} done tasks", { n: done.length })}
        </button>
      )}
      {dialog && (
        <TaskDialog
          level={level}
          code={code}
          task={dialog === "new" ? undefined : dialog}
          onClose={() => setDialog(null)}
          onSaved={() => void tasks.reload()}
        />
      )}
    </section>
  );
}
