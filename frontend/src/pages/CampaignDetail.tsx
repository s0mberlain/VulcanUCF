import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { api, type CampaignDetail as Detail, type L2, type TestCaseOut, type TestProposal, type TestProposals } from "../api";
import { useAuth } from "../auth";
import { confirmDialog, ErrorNote, Modal, useLoad } from "../components/ui";
import { TestCard, TestDialog, Technique } from "../components/TestParts";
import { fmtDate } from "../lib/format";
import { CAMPAIGN_LABEL, CAMPAIGN_PILL, OUTCOMES, OUTCOME_LABEL, OUTCOME_PILL } from "../lib/tests";
import { CampaignDialog } from "./Campaigns";
import { t } from "../i18n";

type Filter = "all" | "link" | "open" | "gaps";

export default function CampaignDetail() {
  const { id } = useParams();
  const cid = Number(id);
  const { user, can } = useAuth();
  const editor = can("admin", "analyst");
  const admin = can("admin");
  const red = user?.role === "red_team";
  const navigate = useNavigate();
  const { hash } = useLocation();
  const data = useLoad<Detail>(() => api.campaign(cid), [cid]);
  const [filter, setFilter] = useState<Filter>("all");
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [proposing, setProposing] = useState(false);
  const [dialog, setDialog] = useState<{ kind: "def"; test: TestCaseOut | null } | null>(null);
  const c = data.data;

  useEffect(() => {
    if (c && hash) document.getElementById(hash.slice(1))?.scrollIntoView({ block: "center" });
  }, [c?.id, hash]);

  const shown = useMemo(() => {
    const tests = c?.test_cases ?? [];
    if (filter === "link") return tests.filter((x) => x.needs_rules);
    if (filter === "open") return tests.filter((x) => x.status !== "done");
    if (filter === "gaps") return tests.filter((x) => x.open_gaps > 0);
    return tests;
  }, [c, filter]);

  async function setStatus(status: "running" | "closed") {
    setError(null);
    try {
      await api.setCampaignStatus(cid, status);
      await data.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function setCollab(mode: "hidden" | "open") {
    if (!c || mode === c.collaboration) return;
    const msg =
      mode === "open"
        ? t("Make the blue team's results and comments visible to the red team now? This includes everything entered so far.")
        : t("Hide the blue team's results and comments from the red team again until the campaign is closed?");
    if (!(await confirmDialog(msg, { confirmLabel: t("Change") }))) return;
    setError(null);
    try {
      await api.setCollaboration(cid, mode);
      await data.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function remove() {
    if (!c || !(await confirmDialog(t("Delete the campaign {name} with its tests?", { name: c.name }), { danger: true, confirmLabel: t("Delete") }))) return;
    try {
      await api.deleteCampaign(cid);
      navigate("/verification/campaigns");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (!c) return <><ErrorNote error={data.error} />{!data.error && <p className="muted">{t("Loading…")}</p>}</>;

  const running = c.status === "running";
  const closed = c.status === "closed";
  const needLink = c.test_cases.filter((x) => x.needs_rules).length;
  return (
    <>
      <nav className="crumbs" aria-label={t("Breadcrumb")}>
        <Link to="/verification/campaigns">{t("Campaigns")}</Link> / <span>{c.name}</span>
      </nav>
      <header className="page-header">
        <div>
          <h1>{c.name}</h1>
          <div className="subtitle">
            <span className={`pill ${CAMPAIGN_PILL[c.status]}`}>{CAMPAIGN_LABEL[c.status]}</span>{" "}
            {fmtDate(c.planned_start)} – {fmtDate(c.planned_end)}
            {c.description && <span className="pre-line"> · {c.description}</span>}
            {c.accounts.length > 0 && ` · ${t("Red team")}: ${c.accounts.map((a) => a.display_name || a.username).join(", ")}`}
          </div>
        </div>
        {editor && (
          <div className="row-actions">
            {c.status === "planned" && (
              <button type="button" className="btn btn-primary" onClick={() => void setStatus("running")}>
                {t("Start campaign")}
              </button>
            )}
            {running && (
              <button type="button" className="btn" onClick={() => void setStatus("closed")}>
                {t("Close campaign")}
              </button>
            )}
            {closed && (
              <button type="button" className="btn" onClick={() => void setStatus("running")}>
                {t("Reopen")}
              </button>
            )}
            <button type="button" className="btn" onClick={() => setEditing(true)}>
              {t("Edit")}
            </button>
            {admin && c.can_delete && (
              <button type="button" className="btn btn-danger" onClick={() => void remove()}>
                {t("Delete")}
              </button>
            )}
          </div>
        )}
      </header>
      <ErrorNote error={error ?? data.error} />
      {red && !closed && (
        <p className="note-box">
          {c.collaboration === "open"
            ? t("You see the tests and record their execution. The blue team's results and comments are visible to you.")
            : t("You see the tests and record their execution. The blue team's results appear when the campaign is closed.")}
        </p>
      )}
      {red && c.status === "planned" && <p className="note-box">{t("The campaign has not started. Results can be entered once it is running.")}</p>}
      {needLink > 0 && editor && (
        <p className="note-box">
          {t("{n} tests were created by the red team and still need rules.", { n: needLink })}{" "}
          <button type="button" className="link-btn" onClick={() => setFilter("link")}>{t("Show them")}</button>
        </p>
      )}

      {editor && (
        <div className="collab-row" role="radiogroup" aria-label={t("Collaboration")}>
          <span className="collab-label">{t("Collaboration")}</span>
          <div className="segmented">
            {(["hidden", "open"] as const).map((m) => (
              <label key={m} className={"segment tap" + (c.collaboration === m ? " is-on" : "")}>
                <input type="radio" name="collab" checked={c.collaboration === m} disabled={closed} onChange={() => void setCollab(m)} />
                {m === "hidden" ? t("Hidden") : t("Open")}
              </label>
            ))}
          </div>
          <span className="small muted">
            {c.collaboration === "hidden"
              ? t("The red team sees the blue team's results and comments only after the campaign is closed.")
              : t("The red team sees the blue team's results and comments immediately.")}
          </span>
        </div>
      )}

      <section className="card stack-sm" aria-labelledby="testsh">
        <div className="section-head">
          <h2 id="testsh">{t("Tests ({n})", { n: c.test_cases.length })}</h2>
          {!closed && !(c.status === "planned" && red) && (
            <div className="row-actions">
              {editor && (
                <button type="button" className="btn btn-sm" onClick={() => setProposing(true)}>
                  {t("Add from use cases")}
                </button>
              )}
              <button type="button" className="btn btn-sm btn-primary" onClick={() => setDialog({ kind: "def", test: null })}>
                {t("+ New test")}
              </button>
            </div>
          )}
        </div>
        {c.outcomes && c.test_cases.length > 0 && (
          <div className="outcome-counts">
            {OUTCOMES.filter((o) => c.outcomes![o] > 0).map((o) => (
              <span key={o} className={`pill ${OUTCOME_PILL[o]}`}>
                {OUTCOME_LABEL[o]} {c.outcomes![o]}
              </span>
            ))}
            {OUTCOMES.every((o) => c.outcomes![o] === 0) && <span className="muted small">{t("No results yet")}</span>}
          </div>
        )}
        <div className="filter-row" role="group" aria-label={t("Show")}>
          {(
            [
              ["all", t("All ({n})", { n: c.test_cases.length })],
              ["open", t("Not finished")],
              ...(editor ? ([["link", t("To link ({n})", { n: needLink })], ["gaps", t("Gaps")]] as [Filter, string][]) : []),
            ] as [Filter, string][]
          ).map(([k, label]) => (
            <button key={k} type="button" className={"filter-chip" + (filter === k ? " active" : "")} aria-pressed={filter === k} onClick={() => setFilter(k)}>
              {label}
            </button>
          ))}
        </div>
        {!c.test_cases.length && (
          <p className="muted">
            {editor
              ? t("No tests yet. Add them from use cases, from the library or by hand.")
              : t("No tests yet. You can add your own tests once the campaign is running.")}
          </p>
        )}
        {c.test_cases.length > 0 && !shown.length && <p className="muted small">{t("No test matches the filter.")}</p>}
        <div className="test-list">
          {shown.map((x) => (
            <TestCard
              key={x.id}
              test={x}
              anchor={hash === `#test-${x.id}`}
              onChanged={() => void data.reload()}
              onEdit={() => setDialog({ kind: "def", test: x })}
            />
          ))}
        </div>
      </section>

      {editing && <CampaignDialog campaign={c} onClose={() => setEditing(false)} onSaved={() => void data.reload()} />}
      {dialog?.kind === "def" && <TestDialog test={dialog.test} campaignId={cid} onClose={() => setDialog(null)} onSaved={() => void data.reload()} />}
      {proposing && <ProposalsDialog campaignId={cid} onClose={() => setProposing(false)} onAdded={() => void data.reload()} />}
    </>
  );
}

/** Pick use cases, get one proposed test per ATT&CK technique, take or drop each. */
function ProposalsDialog({ campaignId, onClose, onAdded }: { campaignId: number; onClose: () => void; onAdded: () => void }) {
  const l2s = useLoad<L2[]>(() => api.l2s());
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [find, setFind] = useState("");
  const [result, setResult] = useState<TestProposals | null>(null);
  const [pick, setPick] = useState<Record<string, boolean>>({});
  const [tpl, setTpl] = useState<Record<string, number | null>>({});
  const [scopes, setScopes] = useState<Record<string, string[]>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const list = (l2s.data ?? []).filter((x) => !find.trim() || `${x.code} ${x.name}`.toLowerCase().includes(find.trim().toLowerCase()));

  async function propose() {
    setBusy(true);
    setError(null);
    try {
      const r = await api.proposals(campaignId, { l2_codes: [...chosen], l3_codes: [] });
      setResult(r);
      setPick(Object.fromEntries(r.proposals.map((p) => [p.technique, p.existing_tests === 0])));
      setTpl(Object.fromEntries(r.proposals.map((p) => [p.technique, p.templates[0]?.id ?? null])));
      setScopes({});
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const key = (p: TestProposal, code: string) => `${p.technique}:${code}`;
  async function add() {
    if (!result) return;
    setError(null);
    const take = result.proposals.filter((p) => pick[p.technique]);
    for (const p of take)
      for (const r of p.rules)
        if (r.scopes.length > 0 && !(scopes[key(p, r.code)] ?? []).length) {
          setError(t("Choose the scopes the test covers for {code} ({technique}).", { code: r.code, technique: p.technique }));
          return;
        }
    setBusy(true);
    try {
      for (const p of take) {
        const tp = p.templates.find((x) => x.id === tpl[p.technique]);
        await api.addTest(campaignId, {
          title: tp?.title ?? p.technique_name ?? p.technique,
          technique: p.technique,
          description: tp?.description ?? "",
          procedure: tp?.procedure ?? "",
          tools: tp?.tools ?? "",
          prerequisites: tp?.prerequisites ?? "",
          expected_detection: tp?.expected_detection ?? "",
          template_id: tp?.id ?? null,
          links: p.rules.map((r) => ({ l3_code: r.code, scopes: r.scopes.length ? scopes[key(p, r.code)] ?? [] : [] })),
        });
      }
      onAdded();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={t("Add tests from use cases")} open onClose={onClose} wide>
      <div className="stack">
        <ErrorNote error={error} />
        {!result ? (
          <>
            <p className="muted small" style={{ margin: 0 }}>
              {t("Choose L2 use cases. Vulcan UCF proposes one test per ATT&CK technique of their rules.")}
            </p>
            <input className="input" placeholder={t("Find a use case")} aria-label={t("Find a use case")} value={find} onChange={(e) => setFind(e.target.value)} />
            <div className="pick-list">
              {list.map((x) => (
                <label key={x.code} className="check">
                  <input
                    type="checkbox"
                    checked={chosen.has(x.code)}
                    onChange={(e) =>
                      setChosen((s) => {
                        const n = new Set(s);
                        if (e.target.checked) n.add(x.code);
                        else n.delete(x.code);
                        return n;
                      })
                    }
                  />
                  <span className="mono small">{x.code}</span> {x.name} <span className="muted small">({x.l3_count})</span>
                </label>
              ))}
            </div>
            <div className="row-actions">
              <button type="button" className="btn" onClick={onClose}>{t("Cancel")}</button>
              <button type="button" className="btn btn-primary" disabled={busy || !chosen.size} onClick={() => void propose()}>
                {t("Propose tests ({n} use cases)", { n: chosen.size })}
              </button>
            </div>
          </>
        ) : (
          <>
            {!result.proposals.length && <p className="note-box">{t("None of the rules has a current ATT&CK technique, so nothing can be proposed.")}</p>}
            {result.proposals.map((p) => (
              <div key={p.technique} className="proposal">
                <label className="check">
                  <input type="checkbox" checked={!!pick[p.technique]} onChange={(e) => setPick({ ...pick, [p.technique]: e.target.checked })} />
                  <Technique id={p.technique} name={p.technique_name} />
                  {p.existing_tests > 0 && <span className="pill pill-fair">{t("Already tested here ({n} tests)", { n: p.existing_tests })}</span>}
                </label>
                {pick[p.technique] && (
                  <div className="proposal-body">
                    {p.templates.length > 0 && (
                      <label className="field">
                        {t("Library template")}
                        <select className="input" value={tpl[p.technique] ?? ""} onChange={(e) => setTpl({ ...tpl, [p.technique]: e.target.value ? Number(e.target.value) : null })}>
                          <option value="">{t("None")}</option>
                          {p.templates.map((x) => (
                            <option key={x.id} value={x.id}>{x.title}</option>
                          ))}
                        </select>
                      </label>
                    )}
                    {p.rules.map((r) => (
                      <div key={r.code} className="test-link-scopes" role="group" aria-label={t("Scopes covered for {code}", { code: r.code })}>
                        <span className="mono small">{r.code}</span> <span className="small">{r.name}</span>
                        {r.scopes.length > 0 ? (
                          <>
                            {r.scopes.map((s) => (
                              <label key={s} className="check">
                                <input
                                  type="checkbox"
                                  checked={(scopes[key(p, r.code)] ?? []).includes(s)}
                                  onChange={(e) => {
                                    const cur = scopes[key(p, r.code)] ?? [];
                                    setScopes({ ...scopes, [key(p, r.code)]: e.target.checked ? [...cur, s] : cur.filter((x) => x !== s) });
                                  }}
                                />
                                {s}
                              </label>
                            ))}
                            <button type="button" className="btn btn-sm" onClick={() => setScopes({ ...scopes, [key(p, r.code)]: r.scopes })}>
                              {t("All scopes of the rule")}
                            </button>
                          </>
                        ) : (
                          <span className="small muted">{t("no scopes")}</span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {result.no_technique.length > 0 && (
              <div className="note-box">
                {t("No ATT&CK technique: add a test by hand for")} {result.no_technique.map((r) => r.code).join(", ")}
              </div>
            )}
            {result.notes.length > 0 && (
              <ul className="plain-list small muted">
                {result.notes.map((n) => <li key={n}>{n}</li>)}
              </ul>
            )}
            <div className="row-actions">
              <button type="button" className="btn" onClick={() => setResult(null)}>{t("Back")}</button>
              <button type="button" className="btn btn-primary" disabled={busy || !Object.values(pick).some(Boolean)} onClick={() => void add()}>
                {t("Add {n} tests", { n: Object.values(pick).filter(Boolean).length })}
              </button>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
