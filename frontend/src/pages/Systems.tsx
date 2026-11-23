import { useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type Classification, type SystemInput, type SystemRow } from "../api";
import { useAuth } from "../auth";
import { ErrorNote, Modal, useLoad } from "../components/ui";
import { fmtDate, pct } from "../lib/format";
import { CLASSIFICATION_LABEL, SYSTEM_STATE_LABEL } from "../lib/stride";
import { t } from "../i18n";

type SortKey = "name" | "owner_name" | "criticality" | "linked" | "coverage" | "gaps" | "last_interview" | "state";

const STATE_ORDER: Record<SystemRow["state"], number> = { none: 0, due: 1, ok: 2 };

/** Interview state of a system. A first interview still in draft reads "Draft open", not
 * "No interview"; a re-interview in draft keeps the state and adds the draft note. */
export function StatePill({ state, draft = false }: { state: SystemRow["state"]; draft?: boolean }) {
  if (state === "none" && draft) return <span className="pill iv-draft">{t("Draft open")}</span>;
  const cls = state === "ok" ? "pill pill-ok" : state === "due" ? "pill pill-warn" : "pill pill-none";
  return (
    <>
      <span className={cls}>{SYSTEM_STATE_LABEL[state]}</span>
      {draft && <span className="muted small"> · {t("Draft open")}</span>}
    </>
  );
}

export const EMPTY_SYSTEM: SystemInput = {
  name: "",
  description: "",
  owner_name: "",
  owner_department: "",
  owner_email: "",
  criticality: 3,
  internet_facing: false,
  data_classification: "internal",
  review_interval_months: 12,
  archived: false,
};

export function systemInput(s: SystemRow): SystemInput {
  return {
    name: s.name,
    description: s.description,
    owner_name: s.owner_name,
    owner_department: s.owner_department,
    owner_email: s.owner_email ?? "",
    criticality: s.criticality,
    internet_facing: s.internet_facing,
    data_classification: s.data_classification as Classification,
    review_interval_months: s.review_interval_months,
    archived: s.archived,
  };
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Create or edit a system; marks the fields that block saving. */
export function SystemDialog({
  initial,
  id,
  onClose,
  onSaved,
}: {
  initial: SystemInput;
  id?: number;
  onClose: () => void;
  onSaved: (id: number) => void;
}) {
  const [form, setForm] = useState<SystemInput>(initial);
  const [tried, setTried] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (patch: Partial<SystemInput>) => setForm((f) => ({ ...f, ...patch }));
  const invalid = {
    name: !form.name.trim(),
    owner_name: !form.owner_name.trim(),
    criticality: !(form.criticality >= 1 && form.criticality <= 5),
    owner_email: !!form.owner_email?.trim() && !EMAIL.test(form.owner_email.trim()),
    review_interval_months: !(form.review_interval_months >= 1 && form.review_interval_months <= 60),
  };
  const bad = (k: keyof typeof invalid) => (tried && invalid[k] ? " is-invalid" : "");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setTried(true);
    if (Object.values(invalid).some(Boolean)) {
      setError(t("Please correct the marked fields."));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const body = { ...form, owner_email: form.owner_email?.trim() || null };
      const saved = id ? await api.updateSystem(id, body) : await api.createSystem(body);
      onSaved(saved.id);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={id ? t("Edit system") : t("New system")} open onClose={onClose} wide>
      <form className="stack" onSubmit={submit} noValidate>
        <div className="form-grid">
          <label className="field">
            {t("Name")} *
            <input
              className={"input" + bad("name")}
              value={form.name}
              maxLength={255}
              aria-invalid={tried && invalid.name}
              onChange={(e) => set({ name: e.target.value })}
              autoFocus
            />
            {tried && invalid.name && <span className="field-error">{t("Required")}</span>}
          </label>
          <label className="field">
            {t("Criticality (1–5)")} *
            <select
              className={"input" + bad("criticality")}
              value={form.criticality}
              onChange={(e) => set({ criticality: Number(e.target.value) })}
            >
              {[1, 2, 3, 4, 5].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="field">
          {t("Description")}
          <textarea
            className="input textarea"
            rows={2}
            maxLength={10000}
            value={form.description}
            onChange={(e) => set({ description: e.target.value })}
          />
        </label>
        <div className="form-grid">
          <label className="field">
            {t("Business owner")} *
            <input
              className={"input" + bad("owner_name")}
              value={form.owner_name}
              maxLength={255}
              aria-invalid={tried && invalid.owner_name}
              onChange={(e) => set({ owner_name: e.target.value })}
            />
            {tried && invalid.owner_name && <span className="field-error">{t("Required")}</span>}
          </label>
          <label className="field">
            {t("Owner department")}
            <input
              className="input"
              value={form.owner_department}
              maxLength={255}
              onChange={(e) => set({ owner_department: e.target.value })}
            />
          </label>
          <label className="field">
            {t("Owner e-mail")}
            <input
              className={"input" + bad("owner_email")}
              type="email"
              value={form.owner_email ?? ""}
              maxLength={254}
              aria-invalid={tried && invalid.owner_email}
              onChange={(e) => set({ owner_email: e.target.value })}
            />
            {tried && invalid.owner_email && <span className="field-error">{t("Not a valid e-mail address")}</span>}
          </label>
        </div>
        <div className="form-grid">
          <label className="field">
            {t("Data classification")}
            <select
              className="input"
              value={form.data_classification}
              onChange={(e) => set({ data_classification: e.target.value as Classification })}
            >
              {(Object.keys(CLASSIFICATION_LABEL) as Classification[]).map((c) => (
                <option key={c} value={c}>
                  {CLASSIFICATION_LABEL[c]}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            {t("Review interval (months)")}
            <input
              className={"input" + bad("review_interval_months")}
              type="number"
              min={1}
              max={60}
              value={form.review_interval_months}
              onChange={(e) => set({ review_interval_months: Number(e.target.value) })}
            />
          </label>
          <label className="check" style={{ alignSelf: "end", minHeight: 40 }}>
            <input
              type="checkbox"
              checked={form.internet_facing}
              onChange={(e) => set({ internet_facing: e.target.checked })}
            />
            {t("Internet-facing")}
          </label>
        </div>
        <ErrorNote error={error} />
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

export default function Systems() {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const showArchived = params.get("archived") === "1";
  const dueOnly = params.get("due") === "1";
  const list = useLoad(() => api.systems({ archived: showArchived }), [showArchived]);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "name", desc: false });
  const [creating, setCreating] = useState(false);

  const setParam = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next);
  };

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const items = (list.data ?? []).filter(
      (s) =>
        (!q || s.name.toLowerCase().includes(q) || s.owner_name.toLowerCase().includes(q)) &&
        (!dueOnly || (s.state !== "ok" && !s.archived)),
    );
    const val = (s: SystemRow): string | number => {
      if (sort.key === "state") return STATE_ORDER[s.state];
      if (sort.key === "coverage") return s.coverage ?? -1;
      if (sort.key === "last_interview") return s.last_interview ?? "";
      const v = s[sort.key];
      return typeof v === "string" ? v.toLowerCase() : v;
    };
    return [...items].sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const c = x < y ? -1 : x > y ? 1 : a.name.localeCompare(b.name);
      return sort.desc ? -c : c;
    });
  }, [list.data, query, sort, dueOnly]);

  const head = (key: SortKey, label: string, num = false) => (
    <th className={num ? "num" : undefined} aria-sort={sort.key === key ? (sort.desc ? "descending" : "ascending") : "none"}>
      <button
        type="button"
        className="sort-btn"
        onClick={() => setSort((s) => ({ key, desc: s.key === key ? !s.desc : false }))}
      >
        {label}
        {sort.key === key ? (sort.desc ? " ↓" : " ↑") : ""}
      </button>
    </th>
  );

  const dueCount = (list.data ?? []).filter((s) => s.state !== "ok" && !s.archived).length;

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Threat modelling")}</h1>
          <div className="subtitle">
            {t(
              "Business applications and platforms with their owner. Interview the owner to find out which use cases a system needs.",
            )}
          </div>
        </div>
        {editor && (
          <div className="row-actions">
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              {t("+ System")}
            </button>
          </div>
        )}
      </header>
      <ErrorNote error={list.error} />

      <section className="card uc-filters" aria-label={t("Filter systems")}>
        <label className="sr-only" htmlFor="sys-q">
          {t("Search by name or owner")}
        </label>
        <input
          id="sys-q"
          className="input input-sm"
          style={{ minWidth: 240 }}
          placeholder={t("Search by name or owner")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button
          type="button"
          className={"filter-chip" + (dueOnly ? " active" : "")}
          aria-pressed={dueOnly}
          onClick={() => setParam("due", dueOnly ? null : "1")}
        >
          {t("Interview due or missing ({n})", { n: dueCount })}
        </button>
        <span className="grow" />
        <label className="check small">
          <input
            type="checkbox"
            checked={showArchived}
            onChange={(e) => setParam("archived", e.target.checked ? "1" : null)}
          />
          {t("Show archived")}
        </label>
      </section>

      <section className="card table-card">
        <div className="scroll-x">
          <table className="table cards-sm">
            <thead>
              <tr>
                {head("name", t("System"))}
                {head("owner_name", t("Business owner"))}
                {head("criticality", t("Criticality"), true)}
                {head("linked", t("Linked L2"), true)}
                {head("coverage", t("Detection coverage"), true)}
                {head("gaps", t("Gaps"), true)}
                {head("last_interview", t("Last interview"))}
                {head("state", t("Interview status"))}
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.id} className={s.archived ? "row-muted" : ""}>
                  <td>
                    <Link className="strong-500" to={`/systems/${s.id}`}>
                      {s.name}
                    </Link>
                    {s.archived && <span className="chip chip-neutral" style={{ marginLeft: 8 }}>{t("Archived")}</span>}
                  </td>
                  <td data-label={t("Business owner")}>
                    {s.owner_name}
                    {s.owner_department && <span className="muted small"> · {s.owner_department}</span>}
                  </td>
                  <td className="num" data-label={t("Criticality")}>{s.criticality}</td>
                  <td className="num" data-label={t("Linked L2")}>
                    {s.linked ? <Link to={`/usecases?sys=${s.id}&view=table`}>{s.linked}</Link> : <span className="muted">0</span>}
                  </td>
                  <td className="num" data-label={t("Detection coverage")}>{pct(s.coverage)}</td>
                  <td className="num" data-label={t("Gaps")}>
                    {!s.last_interview ? (
                      <span className="muted" title={t("Not assessed yet: no completed interview.")}>–</span>
                    ) : s.gaps ? (
                      <span className="count-gap">{s.gaps}</span>
                    ) : (
                      <span className="muted">0</span>
                    )}
                  </td>
                  <td data-label={t("Last interview")}>{fmtDate(s.last_interview)}</td>
                  <td data-label={t("Interview status")}>
                    <StatePill state={s.state} draft={!!s.draft_id} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {list.data && !rows.length && (
          <div className="empty-flat empty-action">
            <p className="muted">
              {list.data.length
                ? t("No system matches the filters.")
                : t("No systems yet. Add the first system to plan an interview.")}
            </p>
            {editor && !list.data.length && (
              <button type="button" className="btn" onClick={() => setCreating(true)}>
                {t("Add the first system")}
              </button>
            )}
          </div>
        )}
      </section>

      {creating && (
        <SystemDialog
          initial={EMPTY_SYSTEM}
          onClose={() => setCreating(false)}
          onSaved={(id) => navigate(`/systems/${id}`)}
        />
      )}
    </>
  );
}
