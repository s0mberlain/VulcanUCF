import { useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  api,
  type L3,
  type QuickTestInput,
  type TestCaseOut,
  type TestGap,
  type TestOutcome,
  type TestStatus,
  type TestTemplate,
} from "../api";
import { useAuth } from "../auth";
import { confirmDialog, ErrorNote, Modal, useLoad } from "./ui";
import { Markdown, MarkdownField } from "./Markdown";
import { fmtTime } from "../lib/format";
import {
  EXEC_LABEL,
  ROUND_LABEL,
  ROUND_PILL,
  fmtTtd,
  fromInput,
  OUTCOMES,
  OUTCOME_HINT,
  OUTCOME_LABEL,
  OUTCOME_PILL,
  RULE_STATE_LABEL,
  RULE_STATE_PILL,
  TECHNIQUE_PATTERN,
  toInput,
} from "../lib/tests";
import type { RuleTestState } from "../api";
import { t } from "../i18n";

export function OutcomePill({ outcome }: { outcome: TestOutcome | null }) {
  if (!outcome) return <span className="muted">–</span>;
  return <span className={`pill ${OUTCOME_PILL[outcome]}`}>{OUTCOME_LABEL[outcome]}</span>;
}

export function RuleStatePill({ state }: { state: RuleTestState }) {
  return <span className={`pill ${RULE_STATE_PILL[state]}`}>{RULE_STATE_LABEL[state]}</span>;
}

export function Technique({ id, name }: { id: string; name?: string | null }) {
  return (
    <span className="chip chip-neutral" title={name ?? undefined}>
      <span className="mono">{id}</span>
      {name ? ` ${name}` : ""}
    </span>
  );
}

// ------------------------------------------------------------------ rule links

interface LinkState {
  l3_code: string;
  rule_name: string;
  rule_scopes: string[];
  scopes: string[];
}

/** Rules a test covers, with the scopes it covers per rule. */
function RuleLinks({ value, onChange, disabled }: { value: LinkState[]; onChange: (v: LinkState[]) => void; disabled?: boolean }) {
  const rules = useLoad<L3[]>(() => api.l3s());
  const [find, setFind] = useState("");
  const used = new Set(value.map((x) => x.l3_code));
  const hits = useMemo(() => {
    const q = find.trim().toLowerCase();
    if (!q) return [];
    return (rules.data ?? [])
      .filter((r) => !used.has(r.code) && `${r.code} ${r.name}`.toLowerCase().includes(q))
      .slice(0, 8);
  }, [find, rules.data, value]);
  const set = (code: string, patch: Partial<LinkState>) => onChange(value.map((x) => (x.l3_code === code ? { ...x, ...patch } : x)));
  return (
    <fieldset className="fieldset test-links">
      <legend>{t("Rules this test covers")}</legend>
      {!value.length && <p className="muted small">{t("No rule linked. A failed test is then a gap of the technique itself.")}</p>}
      {value.map((l) => (
        <div key={l.l3_code} className="test-link">
          <div className="test-link-head">
            <strong className="mono">{l.l3_code}</strong> <span>{l.rule_name}</span>
            <span className="grow" />
            {!disabled && (
              <button type="button" className="link-btn small" onClick={() => onChange(value.filter((x) => x.l3_code !== l.l3_code))}>
                {t("Remove")}
              </button>
            )}
          </div>
          {l.rule_scopes.length > 0 ? (
            <div className="test-link-scopes" role="group" aria-label={t("Scopes covered for {code}", { code: l.l3_code })}>
              <span className="small muted">{t("Scopes covered")}:</span>
              {l.rule_scopes.map((s) => (
                <label key={s} className="check">
                  <input
                    type="checkbox"
                    disabled={disabled}
                    checked={l.scopes.includes(s)}
                    onChange={(e) => set(l.l3_code, { scopes: e.target.checked ? [...l.scopes, s] : l.scopes.filter((x) => x !== s) })}
                  />
                  {s}
                </label>
              ))}
              {!disabled && (
                <button type="button" className="btn btn-sm" onClick={() => set(l.l3_code, { scopes: l.rule_scopes })}>
                  {t("All scopes of the rule")}
                </button>
              )}
              {l.scopes.length === 0 && <span className="field-error">{t("Choose at least one scope.")}</span>}
            </div>
          ) : (
            <p className="small muted" style={{ margin: 0 }}>{t("This rule has no scopes: the test covers the whole rule.")}</p>
          )}
        </div>
      ))}
      {!disabled && (
        <div className="test-link-add">
          <label className="sr-only" htmlFor="rule-find">
            {t("Find a rule")}
          </label>
          <input id="rule-find" className="input" value={find} placeholder={t("Find a rule by code or name")} onChange={(e) => setFind(e.target.value)} />
          {hits.length > 0 && (
            <ul className="plain-list test-link-hits">
              {hits.map((r) => (
                <li key={r.code}>
                  <button
                    type="button"
                    className="link-btn"
                    onClick={() => {
                      onChange([...value, { l3_code: r.code, rule_name: r.name, rule_scopes: r.scopes, scopes: [] }]);
                      setFind("");
                    }}
                  >
                    <span className="mono">{r.code}</span> {r.name}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </fieldset>
  );
}

const linkStates = (t_: TestCaseOut | null, ruleCode?: string, rules?: L3[]): LinkState[] => {
  if (t_) return t_.links.filter((l) => !l.deleted).map((l) => ({ l3_code: l.l3_code, rule_name: l.rule_name, rule_scopes: l.rule_scopes, scopes: l.scopes }));
  const r = rules?.find((x) => x.code === ruleCode);
  return r ? [{ l3_code: r.code, rule_name: r.name, rule_scopes: r.scopes, scopes: [] }] : [];
};

// ------------------------------------------------------------------ definition

interface DefForm {
  title: string;
  technique: string;
  description: string;
  procedure: string;
  tools: string;
  prerequisites: string;
  expected_detection: string;
  template_id: number | null;
}

const emptyDef = (): DefForm => ({ title: "", technique: "", description: "", procedure: "", tools: "", prerequisites: "", expected_detection: "", template_id: null });

function DefinitionFields({
  form,
  set,
  templates,
  compact,
}: {
  form: DefForm;
  set: (p: Partial<DefForm>) => void;
  templates: TestTemplate[] | null;
  /** keep description, procedure and the rest behind one disclosure */
  compact?: boolean;
}) {
  const More = compact ? ({ children }: { children: ReactNode }) => (
    <details className="more-details" open={!!(form.description || form.procedure || form.tools || form.expected_detection || form.prerequisites)}>
      <summary>{t("More details: description, procedure, tools")}</summary>
      <div className="stack-sm">{children}</div>
    </details>
  ) : ({ children }: { children: ReactNode }) => <>{children}</>;
  return (
    <>
      {templates && templates.length > 0 && (
        <label className="field">
          {t("Start from a library template")}
          <select
            className="input"
            value={form.template_id ?? ""}
            onChange={(e) => {
              const tpl = templates.find((x) => x.id === Number(e.target.value));
              if (tpl)
                set({
                  template_id: tpl.id,
                  title: tpl.title,
                  technique: tpl.technique,
                  description: tpl.description,
                  procedure: tpl.procedure,
                  tools: tpl.tools,
                  prerequisites: tpl.prerequisites,
                  expected_detection: tpl.expected_detection,
                });
              else set({ template_id: null });
            }}
          >
            <option value="">{t("None")}</option>
            {templates.map((x) => (
              <option key={x.id} value={x.id}>
                {x.technique} · {x.title}
              </option>
            ))}
          </select>
        </label>
      )}
      <div className="form-grid">
        <label className="field grow-2">
          {t("Title")} *
          <input className="input" required maxLength={200} value={form.title} onChange={(e) => set({ title: e.target.value })} />
        </label>
        <label className="field">
          {t("ATT&CK technique")} *
          <input
            className="input mono"
            required
            pattern={TECHNIQUE_PATTERN}
            placeholder="T1059.001"
            title={t("A technique ID such as T1059 or T1059.001")}
            value={form.technique}
            onChange={(e) => set({ technique: e.target.value.trim().toUpperCase() })}
          />
        </label>
      </div>
      <More>
      <MarkdownField label={t("Description")} value={form.description} onChange={(v) => set({ description: v })} />
      <label className="field">
        {t("Procedure")}
        <textarea className="input textarea mono" rows={5} maxLength={10000} value={form.procedure} placeholder={t("Steps or commands to run")} onChange={(e) => set({ procedure: e.target.value })} />
      </label>
      <div className="form-grid">
        <label className="field">
          {t("Tools")}
          <input className="input" maxLength={500} value={form.tools} onChange={(e) => set({ tools: e.target.value })} />
        </label>
        <label className="field">
          {t("Expected detection (optional)")}
          <input className="input" maxLength={10000} value={form.expected_detection} placeholder={t("What should alert")} onChange={(e) => set({ expected_detection: e.target.value })} />
        </label>
      </div>
      <label className="field">
        {t("Prerequisites and cleanup (optional)")}
        <textarea className="input textarea" rows={2} maxLength={10000} value={form.prerequisites} onChange={(e) => set({ prerequisites: e.target.value })} />
      </label>
      </More>
    </>
  );
}

/** Create or change a test of a campaign. Red team accounts cannot link rules. */
export function TestDialog({
  test,
  campaignId,
  onClose,
  onSaved,
}: {
  test: TestCaseOut | null;
  campaignId: number;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { user } = useAuth();
  const red = user?.role === "red_team";
  const templates = useLoad<TestTemplate[]>(() => (red ? Promise.resolve([]) : api.library()), [red]);
  const [form, setForm] = useState<DefForm>(
    test
      ? { title: test.title, technique: test.technique, description: test.description, procedure: test.procedure, tools: test.tools, prerequisites: test.prerequisites, expected_detection: test.expected_detection, template_id: null }
      : emptyDef(),
  );
  const [links, setLinks] = useState<LinkState[]>(linkStates(test));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (p: Partial<DefForm>) => setForm((f) => ({ ...f, ...p }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (links.some((l) => l.rule_scopes.length > 0 && l.scopes.length === 0)) {
      setError(t("Choose the scopes this test covers for every rule that has scopes."));
      return;
    }
    setBusy(true);
    try {
      const body = { ...form, links: links.map((l) => ({ l3_code: l.l3_code, scopes: l.scopes })) };
      if (test) await api.updateTest(test.id, { ...body, expected_version: test.version });
      else await api.addTest(campaignId, body);
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={test ? t("Change test") : t("New test")} open onClose={onClose} wide>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error} />
        <DefinitionFields form={form} set={set} templates={templates.data} />
        {!red ? <RuleLinks value={links} onChange={setLinks} /> : <p className="muted small">{t("The blue team links the rules this test covers.")}</p>}
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {t("Save")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ------------------------------------------------------------------ execution and result

function ExecFields({
  status,
  at,
  notes,
  set,
}: {
  status: TestStatus;
  at: string;
  notes: string;
  set: (p: { status?: TestStatus; at?: string; notes?: string }) => void;
}) {
  return (
    <>
      <div className="form-grid">
        <label className="field">
          {t("Execution")}
          <select className="input" value={status} onChange={(e) => set({ status: e.target.value as TestStatus })}>
            {(Object.keys(EXEC_LABEL) as TestStatus[]).map((s) => (
              <option key={s} value={s}>
                {EXEC_LABEL[s]}
              </option>
            ))}
          </select>
        </label>
        {status === "executed" && (
          <label className="field">
            {t("Executed at")} *
            <input className="input" type="datetime-local" required value={at} onChange={(e) => set({ at: e.target.value })} />
          </label>
        )}
      </div>
      <label className="field">
        {t("Red team notes")}
        <textarea className="input textarea" rows={3} maxLength={10000} value={notes} onChange={(e) => set({ notes: e.target.value })} />
      </label>
    </>
  );
}

function ResultFields({
  outcome,
  detectedAt,
  notes,
  set,
}: {
  outcome: TestOutcome | "";
  detectedAt: string;
  notes: string;
  set: (p: { outcome?: TestOutcome | ""; detectedAt?: string; notes?: string }) => void;
}) {
  return (
    <>
      <fieldset className="fieldset">
        <legend>{t("Result")}</legend>
        <div className="result-choices" role="radiogroup" aria-label={t("Result")}>
          {OUTCOMES.map((o) => (
            <label key={o} className={"result-choice" + (outcome === o ? " is-on" : "")}>
              <input type="radio" name="outcome" checked={outcome === o} onChange={() => set({ outcome: o })} />
              <span className={`pill ${OUTCOME_PILL[o]}`}>{OUTCOME_LABEL[o]}</span>
              <span className="small muted">{OUTCOME_HINT[o]}</span>
            </label>
          ))}
        </div>
      </fieldset>
      {(outcome === "blocked" || outcome === "alerted") && (
        <label className="field">
          {t("Detected at")}
          <input className="input" type="datetime-local" value={detectedAt} onChange={(e) => set({ detectedAt: e.target.value })} />
        </label>
      )}
      <label className="field">
        {t("Blue team notes")}
        <textarea className="input textarea" rows={3} maxLength={10000} value={notes} onChange={(e) => set({ notes: e.target.value })} />
      </label>
    </>
  );
}

export function QuickTestDialog({ ruleCode, onClose, onSaved }: { ruleCode?: string; onClose: () => void; onSaved: () => void }) {
  const rules = useLoad<L3[]>(() => api.l3s());
  const templates = useLoad<TestTemplate[]>(() => api.library());
  const rule = rules.data?.find((r) => r.code === ruleCode);
  const [form, setForm] = useState<DefForm>(emptyDef());
  const [links, setLinks] = useState<LinkState[] | null>(null);
  const [status, setStatus] = useState<TestStatus>("executed");
  const [at, setAt] = useState(toInput(new Date().toISOString()));
  const [redNotes, setRedNotes] = useState("");
  const [outcome, setOutcome] = useState<TestOutcome | "">("");
  const [detectedAt, setDetectedAt] = useState("");
  const [blueNotes, setBlueNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const seeded = useRef(false);
  // the rule of the page starts linked, with its technique prefilled
  if (rules.data && !seeded.current) {
    seeded.current = true;
    if (rule) {
      setLinks(linkStates(null, ruleCode, rules.data));
      if (rule.attack_techniques[0]) setForm((f) => ({ ...f, technique: rule.attack_techniques[0] ?? "", title: f.title || rule.name }));
    } else setLinks([]);
  }
  const set = (p: Partial<DefForm>) => setForm((f) => ({ ...f, ...p }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if ((links ?? []).some((l) => l.rule_scopes.length > 0 && l.scopes.length === 0)) {
      setError(t("Choose the scopes this test covers for every rule that has scopes."));
      return;
    }
    if (status !== "executed" && outcome) {
      setError(t("A result needs an executed test."));
      return;
    }
    setBusy(true);
    try {
      const body: QuickTestInput = {
        ...form,
        links: (links ?? []).map((l) => ({ l3_code: l.l3_code, scopes: l.scopes })),
        exec_status: status,
        executed_at: status === "executed" ? fromInput(at) : null,
        red_notes: redNotes,
        outcome: outcome || null,
        detected_at: fromInput(detectedAt),
        blue_notes: blueNotes,
      };
      await api.createQuickTest(body);
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={t("New quick test")} open onClose={onClose} wide>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error} />
        <DefinitionFields form={form} set={set} templates={templates.data} compact />
        <RuleLinks value={links ?? []} onChange={setLinks} />
        <ExecFields status={status} at={at} notes={redNotes} set={(p) => { if (p.status) setStatus(p.status); if (p.at !== undefined) setAt(p.at); if (p.notes !== undefined) setRedNotes(p.notes); }} />
        {status === "executed" && (
          <ResultFields outcome={outcome} detectedAt={detectedAt} notes={blueNotes} set={(p) => { if (p.outcome !== undefined) setOutcome(p.outcome); if (p.detectedAt !== undefined) setDetectedAt(p.detectedAt); if (p.notes !== undefined) setBlueNotes(p.notes); }} />
        )}
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>{t("Cancel")}</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{t("Save")}</button>
        </div>
      </form>
    </Modal>
  );
}

// ------------------------------------------------------------------ gaps

export function AcceptGapDialog({ gap, onClose, onSaved }: { gap: TestGap; onClose: () => void; onSaved: () => void }) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await api.acceptGap({ l3_code: gap.l3_code, technique: gap.technique, scope: gap.scope, test_id: gap.test_id, reason });
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <Modal title={t("Accept this gap")} open onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error} />
        <p className="muted small" style={{ margin: 0 }}>
          {t("An accepted gap no longer counts as open. It stays in the history with your reason, and a later test starts the question again.")}
        </p>
        <label className="field">
          {t("Reason")} *
          <textarea className="input textarea" rows={3} required maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>{t("Cancel")}</button>
          <button type="submit" className="btn btn-primary">{t("Accept gap")}</button>
        </div>
      </form>
    </Modal>
  );
}

export function GapList({ gaps, editor, onChanged }: { gaps: TestGap[]; editor: boolean; onChanged: () => void }) {
  const [accepting, setAccepting] = useState<TestGap | null>(null);
  if (!gaps.length) return null;
  return (
    <>
      <ul className="plain-list gap-test-list">
        {gaps.map((g) => (
          <li key={`${g.test_id}-${g.l3_code}-${g.scope}`}>
            <span className={`pill ${OUTCOME_PILL[g.outcome]}`}>{OUTCOME_LABEL[g.outcome]}</span>{" "}
            {g.l3_code ? (
              <Link to={`/usecases/l3/${g.l3_code}`}>
                <span className="mono">{g.l3_code}</span> {g.rule_name}
              </Link>
            ) : (
              <span>{t("No rule covers technique {id}", { id: g.technique })}</span>
            )}
            {g.scope && <span className="chip chip-neutral">{g.scope}</span>} <Technique id={g.technique} name={g.technique_name} />
            <span className="small muted">
              {" "}
              · <Link to={`/verification/tests/${g.test_id}`}>{g.test_title}</Link> · {fmtTime(g.executed_at)}
            </span>
            {g.accepted ? (
              <span className="small muted">
                {" "}
                · {t("accepted by {user}: {reason}", { user: g.accepted_by ?? "", reason: g.accepted_reason ?? "" })}
              </span>
            ) : (
              editor && (
                <button type="button" className="link-btn small" style={{ marginLeft: 8 }} onClick={() => setAccepting(g)}>
                  {t("Accept")}
                </button>
              )
            )}
          </li>
        ))}
      </ul>
      {accepting && <AcceptGapDialog gap={accepting} onClose={() => setAccepting(null)} onSaved={onChanged} />}
    </>
  );
}

// ------------------------------------------------------------------ card

export function TestCard({
  test,
  onChanged,
  onEdit,
  anchor,
  showCampaign,
}: {
  test: TestCaseOut;
  onChanged: () => void;
  onEdit: () => void;
  anchor?: boolean;
  showCampaign?: boolean;
}) {
  const { user, can } = useAuth();
  const editor = can("admin", "analyst");
  const [open, setOpen] = useState(!!anchor);
  const [error, setError] = useState<string | null>(null);

  async function remove() {
    if (!(await confirmDialog(t("Delete the test {title}?", { title: test.title }), { danger: true, confirmLabel: t("Delete") }))) return;
    try {
      await api.deleteTest(test.id);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function toLibrary() {
    try {
      await api.saveToLibrary(test.id);
      setError(null);
      await confirmDialog(t("Saved to the test library."), { confirmLabel: t("OK"), cancelLabel: t("Close") });
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <article id={`test-${test.id}`} className={"test-card" + (test.open_gaps ? " has-gap" : "")}>
      <div className="test-head">
        <button type="button" className="link-btn iv-toggle test-toggle" aria-expanded={open} onClick={() => setOpen((x) => !x)}>
          <span className="iv-toggle-name">
            {open ? "▾" : "▸"} {test.title}
          </span>
        </button>
        <Technique id={test.technique} name={test.technique_name} />
        <span className="grow" />
        {test.round_count > 1 && <span className="pill pill-none">{t("{n} rounds", { n: test.round_count })}</span>}
        <span className={`pill ${ROUND_PILL[test.status]}`}>{ROUND_LABEL[test.status]}</span>
        {test.outcome && <OutcomePill outcome={test.outcome} />}
        {test.open_gaps > 0 && <span className="pill pill-poor">{t("Gap")}</span>}
      </div>
      <div className="test-meta small muted">
        {showCampaign && test.campaign_name && (
          <>
            <Link to={`/verification/campaigns/${test.campaign_id}`}>{test.campaign_name}</Link> ·{" "}
          </>
        )}
        {test.links.length > 0
          ? test.links.map((l) => (
              <span key={l.l3_code} className="test-rule">
                {l.deleted ? (
                  <span>{t("Rule deleted: {code}", { code: l.l3_code })}</span>
                ) : (
                  <Link to={`/usecases/l3/${l.l3_code}`} className="mono">
                    {l.l3_code}
                  </Link>
                )}
                {l.scopes.length > 0 && <span> ({l.scopes.join(", ")})</span>}
              </span>
            ))
          : test.needs_rules
            ? <span className="pill pill-fair">{t("Created by the red team: link rules")}</span>
            : user?.role !== "red_team" && <span>{t("No rule linked")}</span>}
        {test.created_by_red_team && !test.needs_rules && <span> · {t("created by the red team")}</span>}
        {test.executed_at && <span> · {t("Executed {time}", { time: fmtTime(test.executed_at) })}</span>}
        {test.time_to_detect_seconds !== null && <span> · {t("Time to detect {time}", { time: fmtTtd(test.time_to_detect_seconds) })}</span>}
      </div>
      {open && (
        <div className="test-body stack-sm">
          {test.description && <Markdown text={test.description} className="test-description" />}
          {test.procedure && <pre className="code-block test-procedure">{test.procedure}</pre>}
          <dl className="facts">
            {test.tools && (
              <>
                <dt>{t("Tools")}</dt>
                <dd>{test.tools}</dd>
              </>
            )}
            {test.prerequisites && (
              <>
                <dt>{t("Prerequisites and cleanup")}</dt>
                <dd className="pre-line">{test.prerequisites}</dd>
              </>
            )}
            {test.expected_detection && (
              <>
                <dt>{t("Expected detection")}</dt>
                <dd>{test.expected_detection}</dd>
              </>
            )}
          </dl>
          <ErrorNote error={error} />
          <div className="row-actions start">
            <Link className="btn btn-sm btn-primary" to={`/verification/tests/${test.id}`}>
              {t("Open test")}
            </Link>
            {test.can_edit_definition && (
              <button type="button" className="btn btn-sm" onClick={onEdit}>
                {t("Change test")}
              </button>
            )}
            {editor && (
              <button type="button" className="btn btn-sm" onClick={() => void toLibrary()}>
                {t("Save to library")}
              </button>
            )}
            {test.can_delete && (
              <button type="button" className="btn btn-sm btn-danger" onClick={() => void remove()}>
                {t("Delete")}
              </button>
            )}
          </div>
        </div>
      )}
    </article>
  );
}

export type { ReactNode };
