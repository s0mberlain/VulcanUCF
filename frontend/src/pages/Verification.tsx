import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type DueRule } from "../api";
import { useAuth } from "../auth";
import { ErrorNote, ShowMore, StatusPill, useLoad, useShowMore } from "../components/ui";
import { fmtDate } from "../lib/format";
import { isOverdue, matchesDue, urgency, type DueFilter } from "../lib/verification";
import { DueBadge } from "./Dashboard";
import { VerifyDialog } from "./UseCases";
import { t } from "../i18n";

const WINDOWS = [
  { days: 0, label: t("Overdue only") },
  { days: 30, label: t("Next 30 days") },
  { days: 90, label: t("Next 90 days") },
];

export default function Verification() {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const [days, setDays] = useState(30);
  const [filter, setFilter] = useState<DueFilter>("all");
  const [q, setQ] = useState("");
  const [verifying, setVerifying] = useState<string | null>(null);
  const due = useLoad<DueRule[]>(() => api.due(days), [days]);
  const scores = useLoad(() => api.scores());
  const k = scores.data?.kpis;
  // a rule whose last check found issues is always listed, whatever its due date
  const rows = useMemo(() => due.data?.filter((d) => days > 0 || d.overdue || d.issues_at) ?? [], [due.data, days]);
  const overdue = rows.filter(isOverdue).length;
  const failed = rows.filter((d) => d.issues_at).length;
  const soon = rows.filter((d) => matchesDue(d, "soon")).length;
  const needle = q.trim().toLowerCase();
  const shownRows = useMemo(
    () =>
      rows
        .filter((d) => matchesDue(d, filter) && (!needle || d.code.toLowerCase().includes(needle) || d.name.toLowerCase().includes(needle)))
        .sort((a, b) => urgency(a) - urgency(b)),
    [rows, filter, needle],
  );
  const page = useShowMore(shownRows, 50);
  const ready = !!due.data;
  const pick = (f: DueFilter) => setFilter((x) => (x === f ? "all" : f));

  const cards: { key: DueFilter | null; label: string; value: string; sub: string }[] = [
    {
      key: null,
      label: t("Verification health"),
      value: k?.verification_health == null ? "–" : `${Math.round(k.verification_health * 100)} %`,
      sub: k ? t("{a} of {b} rules verified in time", { a: k.verified_in_time, b: k.operational_rules }) : "…",
    },
    { key: "overdue", label: t("Overdue"), value: ready ? String(overdue) : "–", sub: t("Never verified or past the due date") },
    { key: "failed", label: t("Failed last check"), value: ready ? String(failed) : "–", sub: t("Issues found; not verified until a check is OK") },
    {
      key: "soon",
      label: days > 0 ? t("Due in {n} days", { n: days }) : t("Due soon"),
      value: ready ? String(soon) : "–",
      sub: t("Verified, due in the chosen window"),
    },
  ];

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Verification")}</h1>
          <div className="subtitle">
            {t("Operational and maintenance rules must be re-tested regularly")}
            {k && ` ${t("(default every {n} days, per-rule override on the rule page)", { n: k.default_verification_days })}`}.
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
              onClick={() => pick(c.key as DueFilter)}
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
          aria-label={t("Search rules")}
          placeholder={t("Search rules")}
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>

      <ErrorNote error={due.error} />
      <div className="card table-card">
        <table className="table table-stack">
          <thead>
            <tr>
              <th>{t("Rule")}</th>
              <th>{t("Status")}</th>
              <th>{t("Last verified")}</th>
              <th>{t("Due")}</th>
              <th>{t("State")}</th>
              {editor && (
                <th>
                  <span className="sr-only">{t("Actions")}</span>
                </th>
              )}
            </tr>
          </thead>
          <tbody>
            {page.shown.map((d) => (
              <tr key={d.code}>
                <td>
                  <Link to={`/usecases/l3/${d.code}`} className="rule-link">
                    <span className="mono small muted">{d.code}</span>
                    <span className="strong-500">{d.name}</span>
                  </Link>
                </td>
                <td data-label={t("Status")}>
                  <StatusPill status={d.lifecycle_status} />
                </td>
                <td className="date" data-label={t("Last verified")}>
                  {fmtDate(d.last_verified_at)}
                  {d.last_verified_by && <span className="muted"> · {d.last_verified_by}</span>}
                </td>
                <td className="date" data-label={t("Due")}>
                  {fmtDate(d.due)}
                </td>
                <td data-label={t("State")}>
                  <span className="chips">
                    <DueBadge d={d} />
                    {d.issues_at && (
                      <span className="badge-gap" title={t("The last check on {date} found issues", { date: fmtDate(d.issues_at) })}>
                        {t("Issues")}
                      </span>
                    )}
                  </span>
                </td>
                {editor && (
                  <td className="num cell-action">
                    <button type="button" className="btn btn-sm tap" onClick={() => setVerifying(d.code)}>
                      {t("Verify now")}
                    </button>
                  </td>
                )}
              </tr>
            ))}
            {ready && !shownRows.length && (
              <tr className="row-empty">
                <td colSpan={6} className="muted">
                  {rows.length
                    ? t("No rule matches the filter.")
                    : t("Nothing to verify in this window.")}{" "}
                  {!rows.length && (
                    <>
                      <Link to="/verification/campaigns">{t("Plan a campaign")}</Link> · <Link to="/verification/quick-tests">{t("Quick tests")}</Link>
                    </>
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <ShowMore {...page} />
      </div>

      {verifying && (
        <VerifyDialog
          level="l3"
          code={verifying}
          onClose={() => setVerifying(null)}
          onSaved={() => {
            void due.reload();
            void scores.reload();
          }}
        />
      )}
    </>
  );
}
