import { useState } from "react";
import { Link } from "react-router-dom";
import { api, type DueRule } from "../api";
import { useAuth } from "../auth";
import { BulkBar, BulkVerifyDialog, SelectAll, useSelection } from "../components/BulkActions";
import { CountUp, ErrorNote, ShowMore, StatusPill, useLoad, useShowMore } from "../components/ui";
import { fmtDate } from "../lib/format";
import { DueBadge } from "./Dashboard";
import { VerifyDialog } from "./UseCases";
import { t } from "../i18n";

const int = (v: number) => String(Math.round(v));

const WINDOWS = [
  { days: 0, label: t("Overdue only") },
  { days: 30, label: t("Next 30 days") },
  { days: 90, label: t("Next 90 days") },
];

export default function Verification() {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const [days, setDays] = useState(30);
  const [verifying, setVerifying] = useState<string | null>(null);
  const due = useLoad<DueRule[]>(() => api.due(days), [days]);
  const scores = useLoad(() => api.scores());
  const k = scores.data?.kpis;
  // a rule whose last check found issues is always listed, whatever its due date
  const rows = due.data?.filter((d) => days > 0 || d.overdue || d.issues_at) ?? [];
  const never = rows.filter((d) => !d.due).length;
  const overdue = rows.filter((d) => d.due && d.overdue).length;
  const failed = rows.filter((d) => d.issues_at).length;
  const soon = rows.filter((d) => d.due && !d.overdue && !d.issues_at).length;
  const page = useShowMore(rows, 50);
  const selection = useSelection();
  const [bulk, setBulk] = useState(false);
  const shownCodes = page.shown.map((d) => d.code);

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Verification")}</h1>
          <div className="subtitle">
            {t("Operational and maintenance rules must be re-tested regularly")}
            {k &&
              ` ${t("(default every {n} days, per-rule override on the rule page)", { n: k.default_verification_days })}`}
            .
          </div>
        </div>
      </header>

      <section className="kpi-grid" aria-label={t("Verification figures")}>
        <div className="card kpi">
          <span className="kpi-label">{t("Verification health")}</span>
          <CountUp className="kpi-value" value={k?.verification_health} format={(v) => `${Math.round(v * 100)} %`} />
          <span className="kpi-sub">
            {k ? t("{a} of {b} rules verified in time", { a: k.verified_in_time, b: k.operational_rules }) : "…"}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">{t("Never verified")}</span>
          <CountUp className="kpi-value" value={due.data ? never : null} format={int} />
          <span className="kpi-sub">{t("Count as overdue")}</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">{t("Overdue")}</span>
          <CountUp className="kpi-value" value={due.data ? overdue : null} format={int} />
          <span className="kpi-sub">{t("Past their due date")}</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">{t("Due soon")}</span>
          <CountUp className="kpi-value" value={due.data ? soon : null} format={int} />
          <span className="kpi-sub">{t("Within the chosen window")}</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">{t("Failed last check")}</span>
          <CountUp className="kpi-value" value={due.data ? failed : null} format={int} />
          <span className="kpi-sub">{t("Issues found, not verified until a check is OK")}</span>
        </div>
      </section>

      <div role="group" aria-label={t("Window")} className="chips">
        {WINDOWS.map((w) => (
          <button
            key={w.days}
            type="button"
            className={"filter-chip" + (days === w.days ? " active" : "")}
            aria-pressed={days === w.days}
            onClick={() => setDays(w.days)}
          >
            {w.label}
          </button>
        ))}
      </div>

      <ErrorNote error={due.error} />
      <div className="card table-card">
        <table className="table">
          <thead>
            <tr>
              {editor && (
                <th className="col-check">
                  <SelectAll codes={shownCodes} sel={selection.sel} setAll={selection.setAll} />
                </th>
              )}
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
              <tr key={d.code} className={selection.has(d.code) ? "is-selected" : undefined}>
                {editor && (
                  <td className="col-check">
                    <input
                      type="checkbox"
                      aria-label={t("Select {code}", { code: d.code })}
                      checked={selection.has(d.code)}
                      onChange={() => selection.toggle(d.code)}
                    />
                  </td>
                )}
                <td>
                  <Link to={`/usecases/l3/${d.code}`} className="rule-link">
                    <span className="mono small muted">{d.code}</span>
                    <span className="strong-500">{d.name}</span>
                  </Link>
                </td>
                <td>
                  <StatusPill status={d.lifecycle_status} />
                </td>
                <td className="date">
                  {fmtDate(d.last_verified_at)}
                  {d.last_verified_by && <span className="muted"> · {d.last_verified_by}</span>}
                </td>
                <td className="date">{fmtDate(d.due)}</td>
                <td>
                  <span className="chips">
                    <DueBadge d={d} />
                    {d.issues_at && (
                      <span
                        className="badge-gap"
                        title={t("The last check on {date} found issues", { date: fmtDate(d.issues_at) })}
                      >
                        {t("Issues")}
                      </span>
                    )}
                  </span>
                </td>
                {editor && (
                  <td className="num">
                    <button type="button" className="btn btn-sm" onClick={() => setVerifying(d.code)}>
                      {t("Verify now")}
                    </button>
                  </td>
                )}
              </tr>
            ))}
            {due.data && !rows.length && (
              <tr>
                <td colSpan={editor ? 7 : 6} className="muted">
                  {t("Nothing to verify in this window.")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <ShowMore {...page} />
      </div>
      {editor && (
        <BulkBar count={selection.sel.size} onClear={selection.clear}>
          <button type="button" className="btn btn-primary" onClick={() => setBulk(true)}>
            {t("Verify selected…")}
          </button>
        </BulkBar>
      )}
      {bulk && (
        <BulkVerifyDialog
          codes={[...selection.sel]}
          onClose={() => setBulk(false)}
          onDone={() => {
            selection.clear();
            void due.reload();
            void scores.reload();
          }}
        />
      )}

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
