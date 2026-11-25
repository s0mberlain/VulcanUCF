import { useEffect, useState, type FormEvent } from "react";
import { api, type RuleNameSettings } from "../api";
import { useAuth } from "../auth";
import { ErrorNote, useLoad, useUnsavedGuard } from "../components/ui";
import { fmtDate, fmtSize } from "../lib/format";
import { renderRuleName, RULE_NAME_BUILTINS, ruleNameValues, unknownNames, type RuleNameVariable } from "../lib/ruleName";
import { t } from "../i18n";

const EXAMPLE = { code: "IA-CMT-LOG-02", name: "Failed Login Monitoring", l2_code: "IA-CMT", l1_code: "IA" };

const BUILTIN_HINT: Record<(typeof RULE_NAME_BUILTINS)[number], string> = {
  ucID: t("Rule ID"),
  ucName: t("Rule name"),
  l2ID: t("ID of the L2 use case"),
  l1ID: t("ID of the L1 use case"),
};

export default function Settings() {
  const { can } = useAuth();
  const admin = can("admin");
  const saved = useLoad(() => api.ruleNameSettings());
  const [format, setFormat] = useState("");
  const [vars, setVars] = useState<RuleNameVariable[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!saved.data) return;
    setFormat(saved.data.format);
    setVars(saved.data.variables);
  }, [saved.data]);

  const dirty =
    !!saved.data &&
    (format !== saved.data.format || JSON.stringify(vars) !== JSON.stringify(saved.data.variables));
  useUnsavedGuard(dirty);

  if (saved.error) return <ErrorNote error={saved.error} />;
  if (!saved.data) return <p className="muted">{t("Loading…")}</p>;

  const values = ruleNameValues(EXAMPLE, vars.filter((v) => v.name.trim()));
  const unknown = unknownNames(format, values);
  const setVar = (i: number, patch: Partial<RuleNameVariable>) => {
    setNotice(null);
    setVars((vs) => vs.map((v, j) => (j === i ? { ...v, ...patch } : v)));
  };

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r: RuleNameSettings = await api.saveRuleNameSettings({
        format,
        variables: vars.filter((v) => v.name.trim() || v.value.trim()).map((v) => ({ ...v, name: v.name.trim() })),
      });
      saved.setData(r);
      setNotice(t("Saved."));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Settings")}</h1>
          <div className="subtitle">{t("Settings that apply to everyone using this app.")}</div>
        </div>
      </header>

      <form className="card stack" aria-labelledby="rn-h" onSubmit={save}>
        <div className="stack-xs">
          <h2 id="rn-h">{t("SIEM name of rules")}</h2>
          <span className="muted small">
            {t(
              "Each rule shows its name in this format, ready to copy into the SIEM. Use $ and a variable name; the variables below and the ones from the rule are replaced.",
            )}
          </span>
        </div>
        <ErrorNote error={error} />
        {notice && (
          <p className="form-notice" role="status">
            {notice}
          </p>
        )}

        <label className="field">
          {t("Format")}
          <input
            className="input mono"
            required
            maxLength={500}
            readOnly={!admin}
            value={format}
            placeholder="$companyName:$ucID:$ucName"
            onChange={(e) => {
              setNotice(null);
              setFormat(e.target.value);
            }}
          />
        </label>
        <div className="field">
          <span>{t("Example")}</span>
          <output className="input mono rule-name-preview">{renderRuleName(format, values) || " "}</output>
          {unknown.length > 0 && (
            <span className="small text-err">
              {t("Not defined, left as is: {names}", { names: unknown.map((n) => "$" + n).join(", ") })}
            </span>
          )}
        </div>

        <div className="stack-sm">
          <h3>{t("Variables from the rule")}</h3>
          <ul className="plain-list small">
            {RULE_NAME_BUILTINS.map((b) => (
              <li key={b}>
                <code>${b}</code> <span className="muted">{BUILTIN_HINT[b]}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="stack-sm">
          <h3>{t("Your variables")}</h3>
          {vars.length === 0 && <p className="muted small">{t("No variables yet.")}</p>}
          {vars.map((v, i) => (
            <div key={i} className="var-row">
              <label className="field">
                <span className="sr-only">{t("Variable name")}</span>
                <span className="var-name">
                  <span aria-hidden="true">$</span>
                  <input
                    className="input mono"
                    value={v.name}
                    readOnly={!admin}
                    required
                    maxLength={50}
                    pattern="[A-Za-z_][A-Za-z0-9_]*"
                    title={t("Letters, digits and _, not starting with a digit")}
                    placeholder="companyName"
                    onChange={(e) => setVar(i, { name: e.target.value })}
                  />
                </span>
              </label>
              <span aria-hidden="true">=</span>
              <label className="field grow">
                <span className="sr-only">{t("Value")}</span>
                <input
                  className="input"
                  value={v.value}
                  readOnly={!admin}
                  maxLength={200}
                  placeholder="MYCORP"
                  onChange={(e) => setVar(i, { value: e.target.value })}
                />
              </label>
              {admin && (
                <button
                  type="button"
                  className="btn btn-sm"
                  aria-label={t("Remove ${name}", { name: v.name })}
                  onClick={() => setVars((vs) => vs.filter((_, j) => j !== i))}
                >
                  {t("Remove")}
                </button>
              )}
            </div>
          ))}
          {admin && (
            <div className="row-actions start">
              <button type="button" className="btn btn-sm" onClick={() => setVars((vs) => [...vs, { name: "", value: "" }])}>
                {t("+ Add variable")}
              </button>
            </div>
          )}
        </div>

        <div className="row-actions">
          {saved.data.updated_by && (
            <span className="small muted grow">
              {t("Last changed by {user} on {date}", {
                user: saved.data.updated_by,
                date: fmtDate(saved.data.updated_at),
              })}
            </span>
          )}
          {admin && (
            <button type="submit" className="btn btn-primary" disabled={busy || !dirty}>
              {t("Save")}
            </button>
          )}
        </div>
      </form>

      <LogSourceIntervalCard />
      <EvidenceStorageCard />
    </>
  );
}

/** Space used by interview evidence files (#47). */
function EvidenceStorageCard() {
  const storage = useLoad(() => api.evidenceStorage());
  const s = storage.data;
  return (
    <section className="card stack-sm" aria-labelledby="ev-h">
      <h2 id="ev-h">{t("Evidence storage")}</h2>
      <ErrorNote error={storage.error} />
      {s && (
        <>
          <p style={{ margin: 0 }}>
            {s.limit_bytes
              ? t("{used} of {limit} used by {n} files.", { used: fmtSize(s.used_bytes), limit: fmtSize(s.limit_bytes), n: s.files })
              : t("{used} used by {n} files (no limit).", { used: fmtSize(s.used_bytes), n: s.files })}
          </p>
          {s.limit_bytes > 0 && (
            <div className="bar-track" aria-hidden="true">
              <div className="bar-fill" style={{ width: `${Math.min(100, (s.used_bytes / s.limit_bytes) * 100)}%` }} />
            </div>
          )}
          <p className="small muted" style={{ margin: 0 }}>
            {t("Evidence files are stored in the database. The JSON export lists them without content, so back up the database (or use magma db-copy) to keep them. The limit is set with EVIDENCE_MAX_TOTAL_MB.")}
          </p>
        </>
      )}
    </section>
  );
}

/** Default interval for log source checks (issue #75); a log source can override it. */
function LogSourceIntervalCard() {
  const current = useLoad(() => api.logSourceSettings());
  const [days, setDays] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const value = days ?? current.data?.default_days.toString() ?? "";

  async function save(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.putLogSourceSettings(Number(value));
      setSaved(true);
      void current.reload();
      setDays(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section className="card stack-sm" aria-labelledby="lsv-h">
      <h2 id="lsv-h">{t("Log source verification")}</h2>
      <ErrorNote error={error ?? current.error} />
      <form className="row-actions start" onSubmit={save}>
        <label className="field">
          {t("Verify log sources every (days)")}
          <input
            className="input"
            type="number"
            min={1}
            max={3650}
            required
            value={value}
            onChange={(e) => {
              setDays(e.target.value);
              setSaved(false);
            }}
          />
        </label>
        <button type="submit" className="btn" disabled={days === null}>
          {t("Save")}
        </button>
        {saved && (
          <span className="saved-tick" role="status">
            {t("Saved")}
          </span>
        )}
      </form>
      <p className="small muted" style={{ margin: 0 }}>
        {t("Default for all log sources; a log source can have its own interval on the log source verification page.")}
      </p>
    </section>
  );
}
