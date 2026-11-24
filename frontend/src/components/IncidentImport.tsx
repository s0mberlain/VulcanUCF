import { useRef, useState } from "react";
import { api, type IncidentReport, type MetricCounts } from "../api";
import { t } from "../i18n";
import { ErrorNote, Modal } from "./ui";

/** Output metrics from a Microsoft Sentinel / Defender XDR incident export (one row per incident).
 * Check shows what would change; Apply stores it. Incidents of unknown use cases are ignored. */
export default function IncidentImportCard({ onImported }: { onImported?: () => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<IncidentReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function check() {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      setPreview(await api.importIncidents(file, true));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function done() {
    setFile(null);
    if (input.current) input.current.value = "";
    onImported?.();
  }

  return (
    <section className="card stack" aria-labelledby="inc">
      <h2 id="inc">{t("Import incident export")}</h2>
      <p className="small muted" style={{ margin: 0 }}>
        {t(
          "The incident list exported from Microsoft Sentinel or Defender XDR, one row per incident. Each incident counts for the use case whose code or SIEM rule ID is in its name; incidents of use cases that are not in this app are ignored. Importing the same incidents again does not count them twice.",
        )}
      </p>
      <label className="field">
        {t("Incident export (CSV)")}
        <input
          ref={input}
          className="input"
          type="file"
          accept=".csv,text/csv,text/plain"
          onChange={(e) => {
            setFile(e.target.files?.[0] ?? null);
            setError(null);
          }}
        />
      </label>
      <div className="row-actions start">
        <button type="button" className="btn" disabled={!file || busy} onClick={() => void check()}>
          {busy ? t("Checking…") : t("Check and preview")}
        </button>
      </div>
      <ErrorNote error={error} />
      {preview && file && (
        <IncidentDialog file={file} preview={preview} onClose={() => setPreview(null)} onDone={done} />
      )}
    </section>
  );
}

function Counts({ c }: { c: MetricCounts | null }) {
  if (!c) return <span className="muted">–</span>;
  return (
    <span className="num-cell">
      {c.alerts} / {c.incidents} / {c.false_positives}
    </span>
  );
}

function IncidentDialog({
  file,
  preview,
  onClose,
  onDone,
}: {
  file: File;
  preview: IncidentReport;
  onClose: () => void;
  onDone: () => void;
}) {
  const [result, setResult] = useState<IncidentReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const p = result ?? preview;
  const changed = p.changes.filter((c) => c.changed);
  const rows = showAll ? p.changes : changed;
  const writes = p.created + p.updated;

  async function apply() {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.importIncidents(file, false));
      onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={t("Import incident export")} open onClose={onClose} wide>
      <div className="stack">
        <ErrorNote error={error} />
        <dl className="stat-grid">
          <div>
            <dt>{t("Incidents in file")}</dt>
            <dd>{p.rows}</dd>
          </div>
          <div>
            <dt>{t("Matched to a use case")}</dt>
            <dd>{p.matched_rows}</dd>
          </div>
          <div>
            <dt>{t("New or changed")}</dt>
            <dd>{p.new_incidents + p.updated_incidents}</dd>
          </div>
          <div>
            <dt>{t("Ignored")}</dt>
            <dd>{p.ignored_rows}</dd>
          </div>
        </dl>
        <p className={result ? "form-notice" : "ink-2"} style={{ margin: 0 }} role="status">
          {result
            ? t("Imported: {created} new and {updated} updated months. The import is in the audit log.", {
                created: p.created,
                updated: p.updated,
              })
            : writes
              ? t(
                  "{created} months will be added and {updated} updated. Alerts, incidents (true positives) and false positives are recounted from all imported incidents of that use case and month; false negatives and notes stay.",
                  { created: p.created, updated: p.updated },
                )
              : t("Nothing to change: all matched incidents are already imported.")}
        </p>
        {p.unchanged_incidents > 0 && (
          <p className="small muted" style={{ margin: 0 }}>
            {t("{n} incidents were imported before and are unchanged.", { n: p.unchanged_incidents })}
          </p>
        )}

        {p.changes.length > 0 && (
          <>
            <div className="section-head">
              <h3 style={{ margin: 0 }}>{t("Output metrics per use case and month")}</h3>
              <span className="grow" />
              {changed.length < p.changes.length && (
                <label className="small">
                  <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />{" "}
                  {t("Show unchanged months")}
                </label>
              )}
            </div>
            <div className="remap-list">
              <table className="table table-plain">
                <thead>
                  <tr>
                    <th>{t("Use case")}</th>
                    <th>{t("Month")}</th>
                    <th title={t("Alerts / incidents / false positives")}>{t("Before")}</th>
                    <th title={t("Alerts / incidents / false positives")}>{t("After")}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((c) => (
                    <tr key={`${c.code}-${c.period}`}>
                      <td>
                        <span className="mono small">{c.code}</span> <span className="small muted">{c.name}</span>
                      </td>
                      <td className="mono small">{c.period}</td>
                      <td className="small">
                        <Counts c={c.before} />
                      </td>
                      <td className={c.changed ? "small strong" : "small"}>
                        <Counts c={c.after} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="small muted" style={{ margin: 0 }}>
              {t("Numbers are alerts / incidents / false positives.")}
            </p>
          </>
        )}

        {p.ignored.length > 0 && (
          <details>
            <summary>
              {t("{n} incidents ignored: no matching use case", { n: p.ignored_rows })}
            </summary>
            <p className="small muted">
              {t("To count them, add the rule ID from the name (for example CC-CK) as a SIEM rule ID on the use case.")}
            </p>
            <ul className="small">
              {p.ignored.map((i) => (
                <li key={i.name}>
                  {i.name} <span className="muted">× {i.count}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
        {p.problems.length > 0 && (
          <details>
            <summary>{t("{n} rows could not be read and were skipped", { n: p.problems.length })}</summary>
            <ul className="small">
              {p.problems.map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
          </details>
        )}
        {p.duplicate_rows > 0 && (
          <p className="small muted" style={{ margin: 0 }}>
            {t("{n} rows repeat an incident ID and were counted once.", { n: p.duplicate_rows })}
          </p>
        )}

        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>
            {result ? t("Close") : t("Cancel")}
          </button>
          {!result && (
            <button type="button" className="btn btn-primary" disabled={busy || !writes} onClick={() => void apply()}>
              {t("Apply to {n} months", { n: writes })}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}
