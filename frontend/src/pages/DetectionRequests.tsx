import { Fragment, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, REQUEST_STATUSES, type OverviewRequest, type RequestStatus } from "../api";
import { useAuth } from "../auth";
import { isTodo, StatusChip, StatusDetails, StatusDialog, statusLabel } from "../components/RequestStatus";
import { Markdown } from "../components/Markdown";
import { ErrorNote, ShowMore, useLoad, useShowMore } from "../components/ui";
import { fmtTime } from "../lib/format";
import { threatLabel } from "../lib/stride";
import { t } from "../i18n";

/** All detection requests of all systems (PROJ-2): the work that is still to do at a glance. */

type SortKey = "title" | "system" | "risk" | "status" | "changed";
const SORT_KEYS: SortKey[] = ["title", "system", "risk", "status", "changed"];
const DEFAULT_STATUSES: RequestStatus[] = ["open", "in_progress"];
const NO_STATUS = "-"; // `status=-` in the address: no status chosen

const rowId = (r: OverviewRequest) => `${r.system_id}:${r.key}`;

export default function DetectionRequests() {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const list = useLoad(() => api.detectionRequests());
  const [params, setParams] = useSearchParams();
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<OverviewRequest | null>(null);
  // rows changed here stay in the list until the filters change or the page is loaded again
  const [changed, setChanged] = useState<Set<string>>(new Set());

  // ---- filters from the address; anything unknown falls back to the default
  const statusParam = params.get("status");
  const known = (statusParam ?? "").split(",").filter((x): x is RequestStatus => (REQUEST_STATUSES as string[]).includes(x));
  // no parameter, or only unknown values: the default; `-` means that no status is chosen
  const statuses: Set<RequestStatus> = new Set(statusParam === NO_STATUS ? [] : known.length ? known : DEFAULT_STATUSES);
  const q = params.get("q") ?? "";
  const showArchived = params.get("archived") === "1";
  const sortParam = params.get("sort") as SortKey | null;
  const sort: SortKey = sortParam && SORT_KEYS.includes(sortParam) ? sortParam : "risk";
  const desc = params.get("dir") ? params.get("dir") === "desc" : sort === "risk" || sort === "changed";
  const all = list.data?.requests ?? [];
  const systems = useMemo(
    () => [...new Map(all.map((r) => [r.system_id, r.system_name] as const)).entries()].sort((a, b) => a[1].localeCompare(b[1])),
    [all],
  );
  const systemParam = params.get("system");
  const systemId = systemParam && systems.some(([id]) => String(id) === systemParam) ? Number(systemParam) : null;
  const systemUnknown = !!systemParam && !!list.data && systemId === null;

  /** Change address parameters; a change of filters ends the "just changed" marks. */
  function setParam(patch: Record<string, string | null>) {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null) next.delete(k);
      else next.set(k, v);
    }
    setParams(next);
    setChanged(new Set());
  }
  const toggleStatus = (s: RequestStatus) => {
    const next = new Set(statuses);
    if (!next.delete(s)) next.add(s);
    const v = REQUEST_STATUSES.filter((x) => next.has(x)).join(",") || NO_STATUS;
    setParam({ status: v });
  };

  // ---- the rows: counters ignore the status filter, the list does not
  const base = all.filter(
    (r) =>
      (showArchived || !r.archived) &&
      (systemId === null || r.system_id === systemId) &&
      (!q.trim() || r.title.toLowerCase().includes(q.trim().toLowerCase())),
  );
  const counts = Object.fromEntries(REQUEST_STATUSES.map((s) => [s, base.filter((r) => r.status === s).length])) as Record<RequestStatus, number>;
  const rows = useMemo(() => {
    const val = (r: OverviewRequest): string | number => {
      if (sort === "title") return r.title.toLowerCase();
      if (sort === "system") return r.system_name.toLowerCase();
      if (sort === "status") return REQUEST_STATUSES.indexOf(r.status);
      if (sort === "changed") return r.status_at ?? "";
      return r.risk_score ?? 0;
    };
    const shown = base.filter((r) => statuses.has(r.status) || changed.has(rowId(r)));
    return shown.sort((a, b) => {
      // without a risk score a request goes to the end, whatever the direction
      if (sort === "risk" && (a.risk_score === null) !== (b.risk_score === null)) return a.risk_score === null ? 1 : -1;
      const x = val(a);
      const y = val(b);
      const c = x < y ? -1 : x > y ? 1 : a.system_name.localeCompare(b.system_name) || a.title.localeCompare(b.title);
      return desc && x !== y ? -c : c;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [base, sort, desc, changed, statusParam]);
  const page = useShowMore(rows, 50);

  const head = (key: SortKey, label: string, num = false) => (
    <th className={num ? "num" : undefined} aria-sort={sort === key ? (desc ? "descending" : "ascending") : "none"}>
      <button
        type="button"
        className="sort-btn"
        onClick={() => setParam({ sort: key, dir: sort === key ? (desc ? "asc" : "desc") : null })}
      >
        {label}
        {sort === key ? (desc ? " ↓" : " ↑") : ""}
      </button>
    </th>
  );
  const toggleOpen = (id: string) =>
    setOpen((x) => {
      const next = new Set(x);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  const reset = () => {
    setParams(new URLSearchParams());
    setChanged(new Set());
  };

  async function saved(r: OverviewRequest) {
    setChanged((x) => new Set(x).add(rowId(r)));
    await list.reload();
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Detection requests")}</h1>
          <div className="subtitle">
            {t("Detection needs from the threat modelling interviews of all systems. Open and in-progress requests are the work still to do.")}
          </div>
        </div>
      </header>
      <ErrorNote error={list.error} />
      {systemUnknown && <div className="note-box">{t("The system from the link was not found. All systems are shown.")}</div>}

      {list.data && !all.length ? (
        <section className="card empty-flat">
          <p className="muted">{t("There are no detection requests yet. They are created in the threat modelling interview of a system.")}</p>
          <Link className="btn" to="/systems">
            {t("Threat modelling")}
          </Link>
        </section>
      ) : (
        <>
          <section className="card uc-filters" aria-label={t("Filter detection requests")}>
            <label className="sr-only" htmlFor="req-q">
              {t("Search by title")}
            </label>
            <input
              id="req-q"
              className="input input-sm"
              style={{ minWidth: 220 }}
              placeholder={t("Search by title")}
              value={q}
              onChange={(e) => setParam({ q: e.target.value || null })}
            />
            <label className="sr-only" htmlFor="req-sys">
              {t("System")}
            </label>
            <select
              id="req-sys"
              className="input input-sm"
              value={systemId ?? ""}
              onChange={(e) => setParam({ system: e.target.value || null })}
            >
              <option value="">{t("All systems")}</option>
              {systems.map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                </option>
              ))}
            </select>
            <div className="req-statuses" role="group" aria-label={t("Show requests with status")}>
              {REQUEST_STATUSES.map((s) => (
                <button
                  key={s}
                  type="button"
                  className={"filter-chip" + (statuses.has(s) ? " active" : "")}
                  aria-pressed={statuses.has(s)}
                  onClick={() => toggleStatus(s)}
                >
                  {statusLabel(s)} ({counts[s]})
                </button>
              ))}
            </div>
            <span className="grow" />
            <label className="check small">
              <input type="checkbox" checked={showArchived} onChange={(e) => setParam({ archived: e.target.checked ? "1" : null })} />
              {t("Show archived systems")}
            </label>
          </section>

          <section className="card table-card" aria-label={t("Detection requests")}>
            <div className="scroll-x">
              <table className="table cards-sm">
                <thead>
                  <tr>
                    {head("title", t("Request"))}
                    {head("system", t("System"))}
                    <th>{t("Threat")}</th>
                    {head("risk", t("Risk score"), true)}
                    {head("status", t("Status"))}
                    {head("changed", t("Last changed"))}
                  </tr>
                </thead>
                <tbody>
                  {page.shown.map((r) => {
                    const id = rowId(r);
                    const expanded = open.has(id);
                    const todo = isTodo(r.status);
                    const justNow = changed.has(id);
                    return (
                      <Fragment key={id}>
                        <tr className={(r.archived ? "row-muted " : "") + (todo ? "" : "req-closed ") + (justNow ? "req-just" : "")}>
                          <td>
                            <button
                              type="button"
                              className="req-toggle"
                              aria-expanded={expanded}
                              aria-controls={`req-${id}`}
                              onClick={() => toggleOpen(id)}
                            >
                              <span aria-hidden="true">{expanded ? "▾" : "▸"}</span>
                              <span className="req-title">{r.title}</span>
                            </button>
                            {justNow && <span className="chip chip-info req-now">{t("just changed")}</span>}
                          </td>
                          <td data-label={t("System")}>
                            <Link className="strong-500" to={`/systems/${r.system_id}`}>
                              {r.system_name}
                            </Link>
                            {r.archived && <span className="chip chip-neutral" style={{ marginLeft: 8 }}>{t("Archived")}</span>}
                          </td>
                          <td data-label={t("Threat")}>
                            {r.component} / {threatLabel(r.category)}
                          </td>
                          <td className="num" data-label={t("Risk score")}>
                            {r.risk_score ?? <span className="muted">–</span>}
                          </td>
                          <td data-label={t("Status")}>
                            <StatusChip status={r.status} />
                          </td>
                          <td data-label={t("Last changed")}>
                            {r.status_at ? (
                              <>
                                {fmtTime(r.status_at)}
                                <span className="muted small"> · {r.status_by}</span>
                              </>
                            ) : (
                              <span className="muted">–</span>
                            )}
                          </td>
                        </tr>
                        {expanded && (
                          <tr id={`req-${id}`} className="req-detail">
                            <td colSpan={6}>
                              <div className="stack-sm">
                                {r.description ? <Markdown text={r.description} className="req-desc small" /> : <p className="muted small" style={{ margin: 0 }}>{t("No description.")}</p>}
                                <StatusDetails r={r} />
                                {editor && !r.archived && (
                                  <div className="row-actions start">
                                    <button type="button" className="btn btn-sm" onClick={() => setEditing(r)}>
                                      {t("Change status")}
                                    </button>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <ShowMore {...page} />
            {list.data && !rows.length && (
              <div className="empty-flat empty-action">
                <p className="muted">{t("No requests with these filters.")}</p>
                <button type="button" className="btn" onClick={reset}>
                  {t("Reset filters")}
                </button>
              </div>
            )}
          </section>
        </>
      )}

      {editing && (
        <StatusDialog
          systemId={editing.system_id}
          title={{ key: editing.key, title: editing.title }}
          current={editing}
          onClose={() => setEditing(null)}
          onSaved={() => void saved(editing)}
        />
      )}
    </>
  );
}
