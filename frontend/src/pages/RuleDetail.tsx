import { useEffect, useRef, useState, type FormEvent } from "react";
import { flushSync } from "react-dom";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type L3, type RefItem, type RefKind } from "../api";
import { useAuth } from "../auth";
import ConfigPanel from "../components/ConfigPanel";
import LifecyclePanel from "../components/LifecyclePanel";
import { TasksPanel } from "../components/Tasks";
import { loadLogSourceMap, logSourceWarning } from "../lib/logSources";
import { DriverBlock } from "../components/Drivers";
import { MarkdownField } from "../components/Markdown";
import OutputPanel from "../components/OutputPanel";
import {
  Chips,
  confirmDialog,
  DraftRestoreBanner,
  ErrorNote,
  MultiSelect,
  StatusPill,
  useDraftBackup,
  useLoad,
  useUnsavedGuard,
} from "../components/ui";
import { fmtDate, num, pct, refHref } from "../lib/format";
import { renderRuleName, ruleNameValues } from "../lib/ruleName";
import { VerifiedCell, VerifyDialog } from "./UseCases";
import { RuleTestsSection } from "../components/RuleTests";
import { t } from "../i18n";

type Metric = "effectiveness" | "implementation" | "coverage";
const METRICS: { key: Metric; label: string; hint: string }[] = [
  {
    key: "effectiveness",
    label: t("Effectiveness"),
    hint: t("How well the rule detects the threat if it runs everywhere."),
  },
  { key: "implementation", label: t("Implementation"), hint: t("How far the rule is built, tuned and running.") },
  { key: "coverage", label: t("Coverage"), hint: t("Share of the in-scope estate whose logs the rule sees.") },
];

interface Form {
  name: string;
  description: string;
  effectiveness: number | null;
  implementation: number | null;
  coverage: number | null;
  log_sources: string[];
  detection_technologies: string[];
  scopes: string[];
  attack: string;
  siem: string;
  onboarded_at: string;
  interval: string;
  risk: string;
  target: string;
  comments: string;
}

const ATTACK_ID = /^T\d{4}(\.\d{3})?$/;

/** ATT&CK IDs from the text field: separated by ",", ";" or spaces, e.g. "T1003,T1059.001" (#87). */
export function parseAttackIds(text: string): { ids: string[]; invalid: string[] } {
  const tokens = text
    .split(/[\s,;]+/)
    .map((x) => x.trim().toUpperCase())
    .filter(Boolean);
  const ids = [...new Set(tokens.filter((x) => ATTACK_ID.test(x)))];
  return { ids, invalid: tokens.filter((x) => !ATTACK_ID.test(x)) };
}

function toForm(r: L3): Form {
  return {
    name: r.name,
    description: r.description,
    effectiveness: r.effectiveness,
    implementation: r.implementation,
    coverage: r.coverage,
    log_sources: r.log_sources,
    detection_technologies: r.detection_technologies,
    scopes: r.scopes,
    attack: r.attack_techniques.join(", "),
    siem: (r.siem_rule_ids ?? []).join("; "),
    onboarded_at: r.onboarded_at ?? "",
    interval: r.verification_interval_days?.toString() ?? "",
    risk: r.risk_level?.toString() ?? "",
    target: r.target_implementation === null ? "" : String(Math.round(r.target_implementation * 100)),
    comments: r.comments,
  };
}

/** Grows a one-line textarea to fit its text (browsers without CSS field-sizing). */
function fitHeight(el: HTMLTextAreaElement | null) {
  if (!el) return;
  el.style.height = "auto";
  el.style.height = `${el.scrollHeight + 2}px`;
}

export default function RuleDetail() {
  const { code = "" } = useParams();
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const navigate = useNavigate();

  const rule = useLoad(() => api.l3(code), [code]);
  const history = useLoad(() => api.verifications("l3", code), [code]);
  const lists = useLoad(async () => {
    const [log, tech, scope] = await Promise.all([
      api.refs("log_source"),
      api.refs("detection_technology"),
      api.refs("scope"),
    ]);
    return { log, tech, scope };
  });
  const nameFormat = useLoad(() => api.ruleNameSettings());
  // status of the rule's log sources (issue #75): overdue or failed checks are flagged
  const lsStatus = useLoad(loadLogSourceMap);
  const [copied, setCopied] = useState(false);

  const [form, setForm] = useState<Form | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [verifying, setVerifying] = useState(false);

  // The form follows the server data, except while it has unsaved edits: changing the status,
  // ticking the checklist or verifying reloads the rule and must not throw those edits away.
  const base = useRef<string | null>(null);
  useEffect(() => {
    if (!rule.data) return;
    const next = toForm(rule.data);
    // read the ref now: the updater runs on the next render, after base.current is set below.
    // Reading it there made a save never take over the stored values, so a value the server
    // normalises ("T1,T2" -> "T1, T2", trimmed name) stayed "unsaved" forever (issues #77, #87).
    const prev = base.current;
    setForm((f) => (f && prev !== null && JSON.stringify(f) !== prev ? f : next));
    base.current = JSON.stringify(next);
  }, [rule.data]);
  useEffect(() => {
    base.current = null; // another rule: start from its data
  }, [code]);

  const isDirty = !!form && !!rule.data && JSON.stringify(form) !== JSON.stringify(toForm(rule.data));
  // the configuration editor has its own unsaved text; one guard covers both (one router blocker)
  const [configDirty, setConfigDirty] = useState(false);
  useUnsavedGuard(isDirty || configDirty);
  const backup = useDraftBackup(`magma-draft:l3:${code}`, form, isDirty, rule.data?.updated_at ?? null);

  if (rule.error) return <ErrorNote error={rule.error} />;
  if (!rule.data || !form) return <p className="muted">{t("Loading…")}</p>;
  const r = rule.data;
  const set = (patch: Partial<Form>) => {
    setSaved(null);
    setForm((f) => (f ? { ...f, ...patch } : f));
  };

  const e = form.effectiveness,
    i = form.implementation,
    c = form.coverage;
  const assessed = e !== null && i !== null && c !== null;
  const weight = assessed ? e * i * c : null;
  const potential = assessed ? e - weight! : null;
  const dirty = isDirty;
  const attackInvalid = parseAttackIds(form.attack).invalid;
  const discard = () => {
    setForm(toForm(r));
    setError(null);
    backup.clear();
  };

  async function save(ev: FormEvent) {
    ev.preventDefault();
    if (!form) return;
    const attack = parseAttackIds(form.attack);
    if (attack.invalid.length) {
      setError(
        t("Not an ATT&CK technique ID: {ids}. Use IDs like T1059 or T1059.001, separated by , or ;", {
          ids: attack.invalid.join(", "),
        }),
      );
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const updated = await api.updateL3(code, {
        name: form.name,
        description: form.description,
        effectiveness: form.effectiveness,
        implementation: form.implementation,
        coverage: form.coverage,
        log_sources: form.log_sources,
        detection_technologies: form.detection_technologies,
        scopes: form.scopes,
        attack_techniques: attack.ids,
        siem_rule_ids: form.siem
          .split(/[;\n]+/)
          .map((x) => x.trim())
          .filter(Boolean),
        onboarded_at: form.onboarded_at || null,
        verification_interval_days: form.interval ? Number(form.interval) : null,
        risk_level: form.risk ? Number(form.risk) : null,
        target_implementation: form.target === "" ? null : Number(form.target) / 100,
        comments: form.comments,
        expected_updated_at: r.updated_at,
      });
      base.current = null; // saved: take over what the server stored
      backup.clear();
      rule.setData(updated);
      setSaved(t("Saved."));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    const ok = await confirmDialog(
      t(
        "Delete rule {code}? Its verifications, status changes, output metrics and configuration history are deleted with it. This cannot be undone.",
        { code },
      ),
      { title: t("Delete rule"), confirmLabel: t("Delete"), danger: true },
    );
    if (!ok) return;
    try {
      await api.deleteL3(code);
      flushSync(() => setForm(toForm(r))); // nothing left to save: no "unsaved changes" question
      navigate(`/usecases?l2=${r.l2_code}`);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const siemName = nameFormat.data
    ? renderRuleName(nameFormat.data.format, ruleNameValues({ ...r, name: form.name }, nameFormat.data.variables))
    : null;
  const opts = (items: RefItem[] | undefined) => (items ?? []).map((x) => ({ value: x.name, label: x.name }));
  // new reference list entries can be added right from the dropdown (issue #26)
  const addRef = (kind: RefKind) => async (name: string) => {
    const item = await api.createRef(kind, { name, description: "" });
    await lists.reload();
    return item.name;
  };

  return (
    <>
      <form onSubmit={save} className="stack-lg">
        <nav aria-label={t("Breadcrumb")} className="crumbs">
          <Link to="/usecases">{t("Use cases")}</Link>
          <span aria-hidden="true">/</span>
          <Link to={`/usecases?l1=${r.l1_code}`}>{r.l1_code}</Link>
          <span aria-hidden="true">/</span>
          <Link to={`/usecases?l2=${r.l2_code}`}>{r.l2_code}</Link>
          <span aria-hidden="true">/</span>
          <span>{r.code}</span>
        </nav>
        {backup.offer && (
          <DraftRestoreBanner
            at={backup.offer.at}
            onRestore={() => {
              setForm(backup.offer!.value);
              backup.dismiss();
            }}
            onDiscard={backup.clear}
          />
        )}

        <header className="page-header">
          <div className="stack-sm">
            <div className="chips">
              <span className="code-tag">{r.code}</span>
              <StatusPill status={r.lifecycle_status} />
              {r.attack_techniques.map((tt) => (
                <span key={tt} className="chip chip-neutral">
                  {t("ATT&CK")} {tt}
                </span>
              ))}
            </div>
            {editor ? (
              <>
                <label className="sr-only" htmlFor="rule-name">
                  {t("Rule name")}
                </label>
                {/* a textarea so long rule names wrap instead of being cut off; Enter still saves */}
                <textarea
                  id="rule-name"
                  className="title-input"
                  rows={1}
                  ref={fitHeight}
                  value={form.name}
                  required
                  onChange={(ev) => {
                    set({ name: ev.target.value.replace(/\s*\n\s*/g, " ") });
                    fitHeight(ev.currentTarget);
                  }}
                  onKeyDown={(ev) => {
                    if (ev.key === "Enter") {
                      ev.preventDefault();
                      ev.currentTarget.form?.requestSubmit();
                    }
                  }}
                />
              </>
            ) : (
              <h1>{r.name}</h1>
            )}
            {siemName !== null && (
              // the name to use in the SIEM, built from the format in the settings (issue #29)
              <div className="siem-name small">
                <span className="muted">{t("SIEM name")}</span>
                <code className="mono" data-testid="siem-name">
                  {siemName}
                </code>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => {
                    void navigator.clipboard?.writeText(siemName).then(() => {
                      setCopied(true);
                      setTimeout(() => setCopied(false), 1500);
                    });
                  }}
                >
                  {copied ? t("Copied") : t("Copy")}
                </button>
              </div>
            )}
          </div>
          {editor && (
            <div className="row-actions">
              {can("admin") && (
                <button type="button" className="btn btn-danger rule-delete" onClick={remove}>
                  {t("Delete")}
                </button>
              )}
              <button type="button" className="btn btn-dark" onClick={() => setVerifying(true)}>
                {t("Verify now")}
              </button>
              <button type="submit" className="btn btn-primary" disabled={busy || !dirty}>
                {dirty ? t("Save changes") : t("Saved")}
              </button>
            </div>
          )}
        </header>
        {!editor && <p className="form-notice">{t("Read-only: your role cannot change rules.")}</p>}
        <ErrorNote error={error} />
        {saved && !dirty && (
          <p className="form-notice" role="status">
            {saved}
          </p>
        )}

        <div className="split">
          <div className="split-side stack-lg">
            <section className="card stack" aria-labelledby="mh">
              <h2 id="mh">{t("Metrics")}</h2>
              {METRICS.map((m) => {
                const v = form[m.key];
                return (
                  <div key={m.key} className="slider">
                    <div className="slider-head">
                      <label htmlFor={m.key}>{m.label}</label>
                      <span className="strong">{v === null ? t("not set") : `${Math.round(v * 100)} %`}</span>
                    </div>
                    <input
                      id={m.key}
                      type="range"
                      min={0}
                      max={100}
                      step={5}
                      disabled={!editor}
                      value={v === null ? 0 : Math.round(v * 100)}
                      className={v === null ? "unset" : ""}
                      onChange={(ev) => set({ [m.key]: Number(ev.target.value) / 100 } as Partial<Form>)}
                    />
                    <span className="small muted">
                      {m.hint}
                      {editor && v !== null && (
                        <>
                          {" "}
                          <button
                            type="button"
                            className="link-btn"
                            onClick={() => set({ [m.key]: null } as Partial<Form>)}
                          >
                            {t("Clear")}
                          </button>
                        </>
                      )}
                    </span>
                  </div>
                );
              })}
              <div className="metric-results">
                <div>
                  <span className="small muted">{t("Weight (eff × impl × cov)")}</span>
                  <span className="big accent">{num(weight)}</span>
                </div>
                <div>
                  <span className="small muted">{t("Potential (eff − weight)")}</span>
                  <span className="big data1">{num(potential)}</span>
                </div>
              </div>
              {r.effective_target !== null && (
                <p className="small target-line">
                  {t("Target implementation")} {pct(r.effective_target)}
                  {r.implementation_gap ? (
                    <span className="text-err">
                      {" "}
                      · {pct(r.implementation_gap)} {t("to go")}
                    </span>
                  ) : (
                    <span className="text-ok"> {t("· reached")}</span>
                  )}
                  {r.priority !== null && (
                    <span className="muted">
                      {" "}
                      {t("· priority")} {num(r.priority)}
                    </span>
                  )}
                </p>
              )}
              {!assessed && <p className="small muted">{t("Set all three metrics to score the rule.")}</p>}
              {assessed && !["operational", "maintenance"].includes(r.lifecycle_status) && (
                <p className="small muted">{t("Only operational and maintenance rules count towards the scores.")}</p>
              )}
            </section>

            <section className="card stack-sm" aria-labelledby="drh">
              <div className="section-head">
                <h2 id="drh">{t("Drivers")}</h2>
                <Link to={`/usecases?l2=${r.l2_code}`} className="small">
                  {t("Inherited from {code}", { code: r.l2_code })}
                </Link>
              </div>
              <DriverBlock business={r.business_drivers} compliance={r.compliance_drivers} />
            </section>

            <section className="card stack" aria-labelledby="vh">
              <div className="section-head">
                <h2 id="vh">{t("Verification")}</h2>
                <VerifiedCell rule={r} />
              </div>
              <p className="small muted" style={{ margin: 0 }}>
                {t("Next due")} {fmtDate(r.verification_due)}
                {r.verification_interval_days
                  ? ` · ${t("every {n} days", { n: r.verification_interval_days })}`
                  : t(" · default interval")}
                {r.last_verified_by && ` · ${t("last by {user}", { user: r.last_verified_by })}`}
              </p>
              {r.issues_at && (
                <p className="form-error" role="status">
                  {t("The last check on {date} found issues. It does not count as verified until a check is OK.", {
                    date: fmtDate(r.issues_at),
                  })}
                </p>
              )}
              <ErrorNote error={history.error} />
              {history.data && !history.data.length && <p className="muted small">{t("No verifications recorded.")}</p>}
              <ul className="history">
                {history.data?.map((v) => (
                  <li key={v.id}>
                    <span className={v.result === "ok" ? "pill pill-ok" : "badge-gap"}>
                      {v.result === "ok" ? "OK" : t("Issues")}
                    </span>
                    <span className="stack-xs">
                      <span className="strong-500">
                        {fmtDate(v.verified_at)} · {v.username}
                      </span>
                      {v.note && <span className="ink-2">{v.note}</span>}
                      {v.test_id && (
                        <Link to={`/verification/tests/${v.test_id}`} className="small">
                          {t("from test")}
                        </Link>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            </section>

            <LifecyclePanel level="l3" code={code} onChanged={() => void rule.reload()} />
            <TasksPanel level="l3" code={code} />
            {editor && (
              <p className="instant-note">
                {t(
                  "Checklist, status, verification, output metrics and configuration are saved as soon as you change them. Everything else on this page is saved with “Save changes”.",
                )}
              </p>
            )}
          </div>

          <div className="split-wide stack-lg">
            <RuleTestsSection code={code} onChanged={() => void history.reload()} />

            <section className="card stack" aria-labelledby="dh">
              <h2 id="dh">{t("Details")}</h2>
              <div className="form-grid">
                <label className="field">
                  {t("Onboarded on")}
                  <input
                    className="input"
                    type="date"
                    disabled={!editor}
                    value={form.onboarded_at}
                    onChange={(ev) => set({ onboarded_at: ev.target.value })}
                  />
                </label>
                <label className="field">
                  {t("Verify every (days)")}
                  <input
                    className="input"
                    type="number"
                    min={1}
                    max={3650}
                    placeholder={t("Default")}
                    disabled={!editor}
                    value={form.interval}
                    onChange={(ev) => set({ interval: ev.target.value })}
                  />
                </label>
                <label className="field">
                  {t("Risk level")}
                  <select
                    className="input"
                    disabled={!editor}
                    value={form.risk}
                    onChange={(ev) => set({ risk: ev.target.value })}
                  >
                    <option value="">
                      {r.risk_source === "l2"
                        ? t("Same as L2 ({risk})", { risk: r.effective_risk })
                        : t("Same as L2 (not set)")}
                    </option>
                    {[1, 2, 3, 4, 5].map((n) => (
                      <option key={n} value={n}>
                        {n}
                      </option>
                    ))}
                  </select>
                  {r.risk_source === "system" && (
                    <span className="small muted">
                      {t("Used: {risk}, raised by system {name}", { risk: r.effective_risk, name: r.risk_system ?? "" })}
                    </span>
                  )}
                </label>
                <label className="field">
                  {t("Target implementation (%)")}
                  <input
                    className="input"
                    type="number"
                    min={0}
                    max={100}
                    disabled={!editor}
                    placeholder={
                      r.target_source && r.target_source !== "rule"
                        ? `${Math.round((r.effective_target ?? 0) * 100)} (${r.target_source === "l2" ? t("from L2") : t("from risk")})`
                        : t("From L2 or risk level")
                    }
                    value={form.target}
                    onChange={(ev) => set({ target: ev.target.value })}
                  />
                </label>
                <label className="field">
                  {t("ATT&CK techniques")}
                  <input
                    className={"input mono" + (attackInvalid.length ? " is-invalid" : "")}
                    placeholder="T1003, T1059.001"
                    disabled={!editor}
                    value={form.attack}
                    aria-invalid={attackInvalid.length > 0}
                    aria-describedby={attackInvalid.length ? "rule-attack-error" : undefined}
                    onChange={(ev) => set({ attack: ev.target.value })}
                  />
                  {attackInvalid.length > 0 && (
                    <span id="rule-attack-error" className="field-error">
                      {t("Not an ATT&CK technique ID: {ids}. Use IDs like T1059 or T1059.001, separated by , or ;", {
                        ids: attackInvalid.join(", "),
                      })}
                    </span>
                  )}
                </label>
                <label className="field">
                  {t("SIEM rule IDs")}
                  <input
                    className="input mono"
                    placeholder={t("Saved search or rule id; separate with ;")}
                    title={t("Links this rule to the SIEM rule inventory and alert counts (Integrations page)")}
                    disabled={!editor}
                    value={form.siem}
                    onChange={(ev) => set({ siem: ev.target.value })}
                  />
                </label>
              </div>
              <div className="form-grid">
                <MultiSelect
                  label={t("Log sources")}
                  options={opts(lists.data?.log)}
                  value={form.log_sources}
                  disabled={!editor}
                  onChange={(v) => set({ log_sources: v })}
                  onCreate={addRef("log_source")}
                />
                <MultiSelect
                  label={t("Detection technologies")}
                  options={opts(lists.data?.tech)}
                  value={form.detection_technologies}
                  disabled={!editor}
                  onChange={(v) => set({ detection_technologies: v })}
                  onCreate={addRef("detection_technology")}
                />
                <MultiSelect
                  label={t("Scopes")}
                  options={opts(lists.data?.scope)}
                  value={form.scopes}
                  disabled={!editor}
                  onChange={(v) => set({ scopes: v })}
                  onCreate={addRef("scope")}
                />
              </div>
              {(() => {
                const flagged = r.log_sources.filter((n) => logSourceWarning(lsStatus.data?.get(n)));
                return (
                  flagged.length > 0 && (
                    <div className="note-box ls-warning" role="status">
                      <strong>{t("Log source checks need attention")}</strong>
                      <ul className="plain-list small">
                        {flagged.map((n) => (
                          <li key={n}>
                            <strong>{n}</strong>: {logSourceWarning(lsStatus.data?.get(n))}
                          </li>
                        ))}
                      </ul>
                      <Link to="/verification/log-sources" className="small">
                        {t("Open log source verification")}
                      </Link>
                    </div>
                  )
                );
              })()}
              <div className="form-grid ref-links" aria-label={t("Rules that share an entry")}>
                {(
                  [
                    ["log_source", r.log_sources, lists.data?.log],
                    ["detection_technology", r.detection_technologies, lists.data?.tech],
                    ["scope", r.scopes, lists.data?.scope],
                  ] as const
                ).map(([kind, names, items]) => (
                  <div key={kind} className="small">
                    {names.length > 0 && (
                      <>
                        <span className="muted">{t("Show rules with:")} </span>
                        <Chips
                          items={[...names]}
                          href={(n) => refHref(kind, n)}
                          warn={kind === "log_source" ? (n) => logSourceWarning(lsStatus.data?.get(n)) : undefined}
                          title={(n) => {
                            const used = items?.find((i) => i.name === n)?.used_by?.length;
                            return used === undefined
                              ? t("Show all rules that use {name}", { name: n })
                              : t("{n} L3 rules use {name}", { n: used, name: n });
                          }}
                        />
                      </>
                    )}
                  </div>
                ))}
              </div>
              <MarkdownField
                label={t("Description")}
                readOnly={!editor}
                value={form.description}
                onChange={(v) => set({ description: v })}
              />
              <MarkdownField
                label={t("Comments")}
                readOnly={!editor}
                value={form.comments}
                onChange={(v) => set({ comments: v })}
              />
              <p className="small muted" style={{ margin: 0 }}>
                {t("Last changed")} {fmtDate(r.updated_at)}
              </p>
            </section>

            <OutputPanel code={code} editor={editor} />

            <ConfigPanel level="l3" code={code} editor={editor} onDirtyChange={setConfigDirty} />
          </div>
        </div>
        {editor && dirty && (
          <div className="unsaved-bar" role="status">
            <span>{t("Unsaved changes to the rule details and metrics.")}</span>
            <span className="row-actions">
              <button type="button" className="btn btn-ghost" onClick={discard} disabled={busy}>
                {t("Discard")}
              </button>
              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy ? t("Saving…") : t("Save changes")}
              </button>
            </span>
          </div>
        )}
      </form>

      {verifying && (
        <VerifyDialog
          level="l3"
          code={code}
          onClose={() => setVerifying(false)}
          onSaved={() => {
            void rule.reload();
            void history.reload();
          }}
        />
      )}
    </>
  );
}
