import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, type CsvReport, type OutputSummary } from "../api";
import { useAuth } from "../auth";
import IncidentImportCard from "../components/IncidentImport";
import OutputChart, { OutputLegend, fmtCount } from "../components/OutputChart";
import { ErrorNote, useLoad } from "../components/ui";
import { pct } from "../lib/format";
import { t } from "../i18n";

export default function OutputPage() {
  const { can } = useAuth();
  const [months, setMonths] = useState(12);
  const sum = useLoad<OutputSummary>(() => api.outputSummary(months), [months]);
  const [limit, setLimit] = useState(15);
  const s = sum.data;
  const tt = s?.totals;
  const last = s?.months[s.months.length - 1];
  const prev = s?.months[s.months.length - 2];

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Output metrics")}</h1>
          <div className="subtitle">{t("Alerts, incidents and false positives per rule and month")}</div>
        </div>
        <div className="row-actions">
          <select
            className="input input-sm"
            aria-label={t("Period")}
            value={months}
            onChange={(e) => setMonths(Number(e.target.value))}
          >
            <option value={3}>{t("Last 3 months")}</option>
            <option value={6}>{t("Last 6 months")}</option>
            <option value={12}>{t("Last 12 months")}</option>
            <option value={24}>{t("Last 24 months")}</option>
          </select>
        </div>
      </header>
      <ErrorNote error={sum.error} />

      <section className="kpi-grid" aria-label={t("Totals")}>
        <div className="card kpi">
          <span className="kpi-label">{t("Alerts")}</span>
          <span className="kpi-value">{tt ? fmtCount(tt.alerts) : "–"}</span>
          <span className="kpi-sub">{s ? t("{n} rules reporting", { n: s.rules_reporting }) : "…"}</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">{t("Incidents")}</span>
          <span className="kpi-value">{tt ? fmtCount(tt.incidents) : "–"}</span>
          <span className="kpi-sub">
            {tt && tt.alerts ? t("{p} of alerts", { p: pct(tt.incidents / tt.alerts, 1) }) : "…"}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">{t("False positive rate")}</span>
          <span className="kpi-value">{tt ? pct(tt.fp_rate) : "–"}</span>
          <span className="kpi-sub">
            {last && prev && last.fp_rate !== null && prev.fp_rate !== null
              ? t("This month {a}, last month {b}", { a: pct(last.fp_rate), b: pct(prev.fp_rate) })
              : t("{n} false positives", { n: tt?.false_positives ?? 0 })}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">{t("False negatives")}</span>
          <span className="kpi-value">{tt ? tt.false_negatives : "–"}</span>
          <span className="kpi-sub">{t("Missed attacks found later (pentest, incident review)")}</span>
        </div>
      </section>

      <section className="card stack" aria-labelledby="mt">
        <div className="section-head">
          <h2 id="mt">{t("Alerts per month")}</h2>
          <OutputLegend />
        </div>
        {s && <OutputChart data={s.months} height={200} />}
      </section>

      <div className="split">
        <section className="card table-card split-main" aria-labelledby="nr">
          <div className="table-title filters">
            <h2 id="nr">{t("Rules by false positives")}</h2>
            <span className="grow" />
            <span className="small muted">{t("Tuning these first cuts the most noise")}</span>
          </div>
          <div className="scroll-x">
            <table className="table">
              <thead>
                <tr>
                  <th>{t("Rule")}</th>
                  <th className="num">{t("Months")}</th>
                  <th className="num">{t("Alerts")}</th>
                  <th className="num">{t("Incidents")}</th>
                  <th className="num">{t("False pos.")}</th>
                  <th style={{ width: "18%" }}>{t("FP rate")}</th>
                </tr>
              </thead>
              <tbody>
                {s?.rules.slice(0, limit).map((r) => (
                  <tr key={r.code}>
                    <td>
                      <Link className="rule-link" to={`/usecases/l3/${r.code}`}>
                        <span className="mono small muted">{r.code}</span>
                        <span>{r.name}</span>
                      </Link>
                    </td>
                    <td className="num">{r.months}</td>
                    <td className="num">{r.alerts.toLocaleString()}</td>
                    <td className="num">{r.incidents.toLocaleString()}</td>
                    <td className="num strong">{r.false_positives.toLocaleString()}</td>
                    <td>
                      <div className="fp-cell">
                        <div className="bar">
                          <div className="bar-fp" style={{ width: `${(r.fp_rate ?? 0) * 100}%` }} />
                        </div>
                        <span className="small num-cell">{pct(r.fp_rate)}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {s && !s.rules.length && (
            <p className="muted empty-flat">
              {t("No output metrics yet. Enter them on a rule's page or import a CSV file.")}
            </p>
          )}
          {s && s.rules.length > limit && (
            <div className="row-actions start" style={{ padding: "12px 16px" }}>
              <button type="button" className="btn btn-sm" onClick={() => setLimit((n) => n + 50)}>
                {t("Show more (")}
                {s.rules.length - limit} {t("left)")}
              </button>
            </div>
          )}
        </section>
        <div className="split-side stack-lg">
          {can("admin", "analyst") && <IncidentImportCard onImported={() => void sum.reload()} />}
          <CsvCard editor={can("admin", "analyst")} onImported={() => void sum.reload()} />
        </div>
      </div>
    </>
  );
}

export function CsvCard({ editor, onImported }: { editor: boolean; onImported?: () => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<CsvReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(dry: boolean) {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.importOutputCsv(file, dry);
      setReport(r);
      if (!dry && !r.errors.length) {
        setFile(null);
        if (input.current) input.current.value = "";
        onImported?.();
      }
    } catch (e) {
      setError((e as Error).message);
      setReport(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card stack" aria-labelledby="csv">
      <h2 id="csv">{t("CSV import and export")}</h2>
      <p className="small muted" style={{ margin: 0 }}>
        {t("One row per rule and month, for example exported from your SIEM or ticket system. Columns:")}{" "}
        <span className="mono">{t("rule, period, alerts, incidents, false_positives, false_negatives, note")}</span>
        {t(". Period is")} <span className="mono">YYYY-MM</span>
        {t("; comma or semicolon separated. Existing months are overwritten.")}
      </p>
      <div className="row-actions start">
        <a className="btn" href="/api/export/output-metrics.csv" download>
          {t("Export CSV")}
        </a>
      </div>
      {editor && (
        <>
          <label className="field">
            {t("File to import")}
            <input
              ref={input}
              className="input"
              type="file"
              accept=".csv,text/csv,text/plain"
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null);
                setReport(null);
              }}
            />
          </label>
          <div className="row-actions start">
            <button type="button" className="btn" disabled={!file || busy} onClick={() => void run(true)}>
              {t("Check")}
            </button>
            <button type="button" className="btn btn-primary" disabled={!file || busy} onClick={() => void run(false)}>
              {t("Import")}
            </button>
          </div>
        </>
      )}
      <ErrorNote error={error} />
      {report && (
        <div className={report.errors.length ? "form-error stack-xs" : "form-notice stack-xs"} role="status">
          <strong>
            {report.errors.length
              ? t("{n} row(s) have errors. Nothing was imported.", { n: report.errors.length })
              : report.dry_run
                ? t("Check passed: {created} new and {updated} updated months in {rows} rows.", {
                    created: report.created,
                    updated: report.updated,
                    rows: report.rows,
                  })
                : t("Imported: {created} new and {updated} updated months.", {
                    created: report.created,
                    updated: report.updated,
                  })}
          </strong>
          {report.errors.slice(0, 8).map((e) => (
            <span key={e} className="small">
              {e}
            </span>
          ))}
          {report.errors.length > 8 && (
            <span className="small">
              {t("… and")} {report.errors.length - 8} {t("more")}
            </span>
          )}
        </div>
      )}
    </section>
  );
}
