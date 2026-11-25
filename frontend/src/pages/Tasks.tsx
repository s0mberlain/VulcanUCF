import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type Task, type TaskKind } from "../api";
import { useAuth } from "../auth";
import { DueText, TASK_KIND_LABEL, TASK_KINDS, TaskDialog, taskOwnerLink } from "../components/Tasks";
import { ErrorNote, SelectSearch, ShowMore, useLoad, useShowMore } from "../components/ui";
import { fmtDate } from "../lib/format";
import { t } from "../i18n";

type StatusFilter = "open" | "done" | "all";

/** Central list of tasks on use cases and rules (issue #74). Filters live in the URL. */
export default function Tasks() {
  const { user, can } = useAuth();
  const editor = can("admin", "analyst");
  const [params, setParams] = useSearchParams();
  const status = (params.get("status") as StatusFilter) || "open";
  const who = params.get("assignee") ?? "";
  const kind = params.get("kind") ?? "";
  const overdue = params.get("overdue") === "1";
  const [q, setQ] = useState("");
  const [editing, setEditing] = useState<Task | null>(null);
  const set = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setParams(next, { replace: true });
  };
  const tasks = useLoad(
    () => api.tasks({ status, assignee: who === "me" ? user?.username : who, kind, overdue }),
    [status, who, kind, overdue, user?.username],
  );
  const people = useLoad(() => api.taskAssignees());
  const counts = useLoad(() => api.tasks(), []);
  const openAll = counts.data ?? [];
  const mine = openAll.filter((x) => x.assignee === user?.username).length;
  const late = openAll.filter((x) => x.overdue).length;

  const needle = q.trim().toLowerCase();
  const rows = useMemo(
    () =>
      (tasks.data ?? []).filter(
        (x) =>
          !needle ||
          [x.title, x.code, x.name, x.body, x.created_by, x.assignee ?? ""].join(" ").toLowerCase().includes(needle),
      ),
    [tasks.data, needle],
  );
  const page = useShowMore(rows, 50);
  const reload = () => {
    void tasks.reload();
    void counts.reload();
  };

  async function toggle(task: Task) {
    await api.updateTask(task.id, { status: task.status === "done" ? "open" : "done" });
    reload();
  }

  const cards = [
    { key: "all", label: t("Open tasks"), value: openAll.length, sub: t("On use cases and rules"), on: !who && !overdue && status === "open", patch: { assignee: null, overdue: null, status: null } },
    { key: "mine", label: t("Assigned to me"), value: mine, sub: t("Open tasks for you"), on: who === "me" && !overdue, patch: { assignee: "me", overdue: null, status: null } },
    { key: "late", label: t("Overdue"), value: late, sub: t("Open, past the due date"), on: overdue && !who, patch: { overdue: "1", assignee: null, status: null } },
  ];

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Tasks")}</h1>
          <div className="subtitle">{t("Work to do on use cases and rules: reviews, tuning, settings")}</div>
        </div>
      </header>

      <section className="kpi-grid" aria-label={t("Task figures")}>
        {cards.map((c) => (
          <button
            key={c.key}
            type="button"
            className={"card kpi kpi-btn" + (c.on ? " active" : "")}
            aria-pressed={c.on}
            onClick={() => set(c.patch)}
          >
            <span className="kpi-label">{c.label}</span>
            <span className="kpi-value">{counts.data ? c.value : "–"}</span>
            <span className="kpi-sub">{c.sub}</span>
          </button>
        ))}
      </section>

      <div className="filter-bar">
        <div role="group" aria-label={t("Status")} className="chips">
          {(
            [
              ["open", t("Open")],
              ["done", t("Done")],
              ["all", t("All")],
            ] as const
          ).map(([v, label]) => (
            <button
              key={v}
              type="button"
              className={"filter-chip tap" + (status === v ? " active" : "")}
              aria-pressed={status === v}
              onClick={() => set({ status: v === "open" ? null : v, overdue: null })}
            >
              {label}
            </button>
          ))}
        </div>
        <SelectSearch
          label={t("Assignee")}
          allLabel={t("All assignees")}
          value={who}
          onChange={(v) => set({ assignee: v || null })}
          options={[
            { value: "me", label: t("Me") },
            { value: "-", label: t("Nobody") },
            ...(people.data ?? []).map((p) => ({ value: p.username, label: p.display_name || p.username })),
          ]}
        />
        <SelectSearch
          label={t("Kind")}
          allLabel={t("All kinds")}
          value={kind}
          onChange={(v) => set({ kind: v || null })}
          options={TASK_KINDS.map((k: TaskKind) => ({ value: k, label: TASK_KIND_LABEL[k] }))}
        />
        <input
          className="input filter-search tap"
          type="search"
          aria-label={t("Search tasks")}
          placeholder={t("Search tasks")}
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>

      <ErrorNote error={tasks.error ?? counts.error} />
      <div className="card table-card">
        <table className="table table-stack tasks-table">
          <thead>
            <tr>
              {editor && (
                <th>
                  <span className="sr-only">{t("Done")}</span>
                </th>
              )}
              <th>{t("Task")}</th>
              <th>{t("Use case")}</th>
              <th>{t("Kind")}</th>
              <th>{t("Assignee")}</th>
              <th>{t("Created")}</th>
              <th>{t("Due")}</th>
              {editor && (
                <th>
                  <span className="sr-only">{t("Actions")}</span>
                </th>
              )}
            </tr>
          </thead>
          <tbody>
            {page.shown.map((x) => (
              <tr key={x.id} className={x.status === "done" ? "is-done" : undefined}>
                {editor && (
                  <td className="cell-check">
                    <input
                      type="checkbox"
                      className="task-check"
                      checked={x.status === "done"}
                      aria-label={x.status === "done" ? t("Reopen {title}", { title: x.title }) : t("Mark {title} as done", { title: x.title })}
                      onChange={() => void toggle(x)}
                    />
                  </td>
                )}
                <td>
                  <span className="task-title">{x.title}</span>
                  {x.body && <div className="small muted clamp-2">{x.body.replace(/[*_`#>[\]]/g, "")}</div>}
                </td>
                <td data-label={t("Use case")}>
                  <Link to={taskOwnerLink(x)} className="rule-link">
                    <span className="mono small muted">{x.code}</span>
                    <span>{x.name}</span>
                  </Link>
                </td>
                <td data-label={t("Kind")}>
                  <span className="chip">{TASK_KIND_LABEL[x.kind]}</span>
                </td>
                <td data-label={t("Assignee")}>{x.assignee ?? <span className="muted">–</span>}</td>
                <td className="date" data-label={t("Created")}>
                  {fmtDate(x.created_at)}
                  <span className="muted"> · {x.created_by}</span>
                </td>
                <td className="date" data-label={t("Due")}>
                  <DueText task={x} />
                </td>
                {editor && (
                  <td className="num cell-action">
                    <button type="button" className="btn btn-sm tap" onClick={() => setEditing(x)}>
                      {t("Edit")}
                    </button>
                  </td>
                )}
              </tr>
            ))}
            {tasks.data && !rows.length && (
              <tr className="row-empty">
                <td colSpan={8} className="muted">
                  {tasks.data.length ? t("No task matches the filter.") : t("No tasks here. Add tasks on a use case or rule page.")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <ShowMore {...page} />
      </div>

      {editing && (
        <TaskDialog level={editing.level} code={editing.code} task={editing} onClose={() => setEditing(null)} onSaved={reload} />
      )}
    </>
  );
}
