import { useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  api,
  LOG_SOURCE_CHECKS,
  type CheckResult,
  type LogSourceCheck,
  type LogSourceState,
  type LogSourceStatus,
} from "../api";
import { useAuth } from "../auth";
import { Markdown, MarkdownField } from "../components/Markdown";
import { ErrorNote, Modal, ShowMore, useLoad, useShowMore } from "../components/ui";
import { fmtDate } from "../lib/format";
import { CHECK_HINT, CHECK_LABEL, STATE_CLASS, STATE_LABEL } from "../lib/logSources";
import { t } from "../i18n";

type Filter = "all" | "overdue" | "issues" | "due";

const WINDOWS = [
  { days: 30, label: t("Next 30 days") },
  { days: 90, label: t("Next 90 days") },
];

/** Overview of log source verification (issue #75): what is due, overdue or found issues. */
export default function LogSources() {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const [days, setDays] = useState(30);
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const [verifying, setVerifying] = useState<LogSourceStatus | null>(null);
  const [details, setDetails] = useState<LogSourceStatus | null>(null);
  const rows = useLoad(() => api.logSourceStatuses(days), [days]);
  const all = rows.data ?? [];
  const ready = !!rows.data;
  // never verified counts as overdue, like rules
  const isOverdue = (x: LogSourceStatus) => x.status === "overdue" || x.status === "never";
  const counts = {
    overdue: all.filter(isOverdue).length,
    issues: all.filter((x) => x.status === "issues").length,
    due: all.filter((x) => x.status === "due").length,
    verified: all.filter((x) => x.status === "ok" || x.status === "due").length,
  };
  const needle = q.trim().toLowerCase();
  const order: Record<LogSourceState, number> = { issues: 0, overdue: 1, never: 2, due: 3, ok: 4 };
  const shown = useMemo(
    () =>
      all
        .filter(
          (x) =>
            (filter === "all" ||
              (filter === "overdue" && isOverdue(x)) ||
              (filter === "issues" && x.status === "issues") ||
              (filter === "due" && x.status === "due")) &&
            (!needle || [x.name, x.owner, x.description].join(" ").toLowerCase().includes(needle)),
        )
        .sort((a, b) => order[a.status] - order[b.status] || (a.due ?? "").localeCompare(b.due ?? "") || a.name.localeCompare(b.name)),
    [all, filter, needle],
  );
  const page = useShowMore(shown, 50);
  const pick = (f: Filter) => setFilter((x) => (x === f ? "all" : f));
  const cards: { key: Filter | null; label: string; value: string; sub: string }[] = [
    {
      key: null,
      label: t("Log source health"),
      value: ready && all.length ? `${Math.round((counts.verified / all.length) * 100)} %` : "–",
      sub: t("{a} of {b} log sources verified in time", { a: counts.verified, b: all.length }),
    },
    { key: "overdue", label: t("Overdue"), value: ready ? String(counts.overdue) : "–", sub: t("Never verified or past the due date") },
    { key: "issues", label: t("Failed last check"), value: ready ? String(counts.issues) : "–", sub: t("Issues found; not verified until a check is OK") },
    { key: "due", label: t("Due in {n} days", { n: days }), value: ready ? String(counts.due) : "–", sub: t("Verified, due in the chosen window") },
  ];

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Log source verification")}</h1>
          <div className="subtitle">
            {t("Check log intake, configuration, filtering and responsibilities of each log source at regular intervals.")}
          </div>
        </div>
      </header>

      <section className="kpi-grid" aria-label={t("Verification figures")}>
        {cards.map((c) =>
          c.key ? (
            <button
              key={c.key}
              type="button"
              className={"card kpi kpi-btn" + (filter === c.key ? " active" : "")}
              aria-pressed={filter === c.key}
              onClick={() => pick(c.key as Filter)}
            >
              <span className="kpi-label">{c.label}</span>
              <span className="kpi-value">{c.value}</span>
              <span className="kpi-sub">{c.sub}</span>
            </button>
          ) : (
            <div key={c.label} className="card kpi">
              <span className="kpi-label">{c.label}</span>
              <span className="kpi-value">{c.value}</span>
              <span className="kpi-sub">{c.sub}</span>
            </div>
          ),
        )}
      </section>

      <div className="filter-bar">
        <div role="group" aria-label={t("Window")} className="chips">
          {WINDOWS.map((w) => (
            <button
              key={w.days}
              type="button"
              className={"filter-chip tap" + (days === w.days ? " active" : "")}
              aria-pressed={days === w.days}
              onClick={() => setDays(w.days)}
            >
              {w.label}
            </button>
          ))}
        </div>
        <input
          className="input filter-search tap"
          type="search"
          aria-label={t("Search log sources")}
          placeholder={t("Search log sources")}
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>

      <ErrorNote error={rows.error} />
      <div className="card table-card">
        <table className="table table-stack">
          <thead>
            <tr>
              <th>{t("Log source")}</th>
              <th>{t("Owner")}</th>
              <th>{t("Used by")}</th>
              <th>{t("Last verified")}</th>
              <th>{t("Due")}</th>
              <th>{t("State")}</th>
              <th>
                <span className="sr-only">{t("Actions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {page.shown.map((x) => (
              <tr key={x.id}>
                <td>
                  <button type="button" className="link-btn strong-500" onClick={() => setDetails(x)}>
                    {x.name}
                  </button>
                  {x.description && <div className="small muted clamp-2">{x.description}</div>}
                </td>
                <td data-label={t("Owner")}>{x.owner || <span className="muted">–</span>}</td>
                <td data-label={t("Used by")} className="small">
                  <Link to={`/usecases?view=table&ref_kind=log_source&ref=${encodeURIComponent(x.name)}`}>
                    {t("{n} L3 rules", { n: x.rules.length })}
                  </Link>
                  {x.systems.length > 0 && <span className="muted"> · {t("{n} systems", { n: x.systems.length })}</span>}
                </td>
                <td className="date" data-label={t("Last verified")}>
                  {fmtDate(x.last_verified_at)}
                  {x.last_verified_by && <span className="muted"> · {x.last_verified_by}</span>}
                </td>
                <td className="date" data-label={t("Due")}>
                  {fmtDate(x.due)}
                  {x.verification_interval_days && (
                    <div className="small muted">{t("every {n} days", { n: x.verification_interval_days })}</div>
                  )}
                </td>
                <td data-label={t("State")}>
                  <span className={STATE_CLASS[x.status]}>{STATE_LABEL[x.status]}</span>
                </td>
                <td className="num cell-action">
                  {editor ? (
                    <button type="button" className="btn btn-sm tap" onClick={() => setVerifying(x)}>
                      {t("Verify now")}
                    </button>
                  ) : (
                    <button type="button" className="btn btn-sm tap" onClick={() => setDetails(x)}>
                      {t("History")}
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {ready && !shown.length && (
              <tr className="row-empty">
                <td colSpan={7} className="muted">
                  {all.length ? t("No log source matches the filter.") : t("The log source list is empty. Add log sources under Reference lists.")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <ShowMore {...page} />
      </div>

      {verifying && (
        <VerifyLogSourceDialog source={verifying} onClose={() => setVerifying(null)} onSaved={() => void rows.reload()} />
      )}
      {details && (
        <LogSourceDialog
          source={details}
          editor={editor}
          onClose={() => setDetails(null)}
          onSaved={() => void rows.reload()}
          onVerify={() => {
            setVerifying(details);
            setDetails(null);
          }}
        />
      )}
    </>
  );
}

/** Record one check of a log source: four items, each OK / issues / not applicable. */
export function VerifyLogSourceDialog({
  source,
  onClose,
  onSaved,
}: {
  source: LogSourceStatus;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [checks, setChecks] = useState<Record<LogSourceCheck, { result: CheckResult; note: string }>>(
    () => Object.fromEntries(LOG_SOURCE_CHECKS.map((c) => [c, { result: "ok" as CheckResult, note: "" }])) as Record<
      LogSourceCheck,
      { result: CheckResult; note: string }
    >,
  );
  const [note, setNote] = useState("");
  const [when, setWhen] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const issues = LOG_SOURCE_CHECKS.some((c) => checks[c].result === "issues");
  const set = (c: LogSourceCheck, patch: Partial<{ result: CheckResult; note: string }>) =>
    setChecks((x) => ({ ...x, [c]: { ...x[c], ...patch } }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.verifyLogSource(source.id, { checks, note, ...(when ? { verified_at: when } : {}) });
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const results: [CheckResult, string][] = [
    ["ok", t("OK")],
    ["issues", t("Issues")],
    ["na", t("Not applicable")],
  ];
  return (
    <Modal title={t("Verify {name}", { name: source.name })} open onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error} />
        <div className="ls-checks">
          {LOG_SOURCE_CHECKS.map((c) => (
            <fieldset key={c} className="ls-check">
              <legend className="sr-only">{CHECK_LABEL[c]}</legend>
              <div>
                <div className="ls-check-title">{CHECK_LABEL[c]}</div>
                <div className="small muted">{CHECK_HINT[c]}</div>
              </div>
              <div className="radio-row">
                {results.map(([v, label]) => (
                  <label key={v}>
                    <input type="radio" name={`ls-${c}`} checked={checks[c].result === v} onChange={() => set(c, { result: v })} />{" "}
                    {label}
                  </label>
                ))}
              </div>
              <input
                className="input input-sm"
                placeholder={checks[c].result === "issues" ? t("What is wrong?") : t("Note (optional)")}
                aria-label={t("Note on {check}", { check: CHECK_LABEL[c] })}
                maxLength={2000}
                value={checks[c].note}
                onChange={(e) => set(c, { note: e.target.value })}
              />
            </fieldset>
          ))}
        </div>
        <MarkdownField label={t("Overall note")} value={note} onChange={setNote} rows={3} />
        <label className="field">
          {t("Date (leave empty for today)")}
          <input className="input" type="date" value={when} onChange={(e) => setWhen(e.target.value)} />
        </label>
        {issues && (
          <p className="form-notice">{t("A check with issues is recorded, but the log source does not count as verified until a check is OK.")}</p>
        )}
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? t("Saving…") : t("Save verification")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Owner, interval and the check history of one log source. */
function LogSourceDialog({
  source,
  editor,
  onClose,
  onSaved,
  onVerify,
}: {
  source: LogSourceStatus;
  editor: boolean;
  onClose: () => void;
  onSaved: () => void;
  onVerify: () => void;
}) {
  const history = useLoad(() => api.logSourceHistory(source.id), [source.id]);
  const [owner, setOwner] = useState(source.owner);
  const [interval, setIntervalDays] = useState(source.verification_interval_days?.toString() ?? "");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const dirty = owner !== source.owner || interval !== (source.verification_interval_days?.toString() ?? "");

  async function save(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.logSourceProfile(source.id, { owner, verification_interval_days: interval ? Number(interval) : null });
      setSaved(true);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const resultLabel: Record<CheckResult, string> = { ok: t("OK"), issues: t("Issues"), na: t("n/a") };
  return (
    <Modal title={source.name} open onClose={onClose}>
      <div className="stack">
        <p className="small muted" style={{ margin: 0 }}>
          <span className={STATE_CLASS[source.status]}>{STATE_LABEL[source.status]}</span>{" "}
          {source.due && t("Next check due {date}", { date: fmtDate(source.due) })}
        </p>
        <form className="stack-sm" onSubmit={save}>
          <ErrorNote error={error} />
          <div className="form-grid">
            <label className="field">
              {t("Owner")}
              <input
                className="input"
                disabled={!editor}
                maxLength={255}
                placeholder={t("Team or person responsible")}
                value={owner}
                onChange={(e) => {
                  setOwner(e.target.value);
                  setSaved(false);
                }}
              />
            </label>
            <label className="field">
              {t("Verify every (days)")}
              <input
                className="input"
                type="number"
                min={1}
                max={3650}
                disabled={!editor}
                placeholder={t("Default ({n})", { n: source.interval })}
                value={interval}
                onChange={(e) => {
                  setIntervalDays(e.target.value);
                  setSaved(false);
                }}
              />
            </label>
          </div>
          {editor && (
            <div className="row-actions start ls-profile-actions">
              <button type="submit" className="btn btn-sm" disabled={!dirty}>
                {t("Save")}
              </button>
              {saved && (
                <span className="saved-tick" role="status">
                  {t("Saved")}
                </span>
              )}
              <span className="grow" />
              <button type="button" className="btn btn-sm btn-primary" onClick={onVerify}>
                {t("Verify now")}
              </button>
            </div>
          )}
        </form>
        <h3 className="h-sm ls-history-head">{t("Check history")}</h3>
        <ErrorNote error={history.error} />
        {history.data && !history.data.length && <p className="muted small">{t("Not verified yet.")}</p>}
        <ul className="ls-history">
          {history.data?.map((v) => (
            <li key={v.id}>
              <div className="small">
                <span className={v.result === "ok" ? "pill pill-ok" : "pill pill-bad"}>
                  {v.result === "ok" ? t("OK") : t("Issues")}
                </span>{" "}
                {fmtDate(v.verified_at)} · {v.username}
              </div>
              <div className="ls-check-list small">
                {LOG_SOURCE_CHECKS.map((c) => (
                  <span
                    key={c}
                    className={"chip " + (v.checks[c]?.result === "issues" ? "chip-warn" : "chip-neutral")}
                    title={v.checks[c]?.note || undefined}
                  >
                    {CHECK_LABEL[c]}: {resultLabel[v.checks[c]?.result ?? "na"]}
                    {v.checks[c]?.note ? ` · ${v.checks[c].note}` : ""}
                  </span>
                ))}
              </div>
              {v.note && <Markdown text={v.note} className="small" />}
            </li>
          ))}
        </ul>
      </div>
    </Modal>
  );
}
