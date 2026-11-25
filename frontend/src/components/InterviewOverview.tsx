import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  api,
  type Detection,
  type Interview,
  type InterviewSave,
  type L2,
  type L3,
  type Proposal,
  type RiskCoverageState,
  type RiskRow,
  type ThreatCategory,
  type UseCaseLevel,
} from "../api";
import { COVERAGE_LABEL, RiskCoverage, detectionLabel, useCaseHref } from "./RiskCoverage";
import { StatusChip } from "./RequestStatus";
import { ErrorNote, StatusPill } from "./ui";
import { IMPACT_LABEL, LIKELIHOOD_LABEL } from "./RiskGrid";
import { fmtDate } from "../lib/format";
import { STRIDE, STRIDE_LABEL, riskLevel, threatLabel } from "../lib/stride";
import { t } from "../i18n";

/**
 * Overview of an interview (step 5 of a draft and the completed interview): the threat matrix
 * with a risk map, a board of the use cases by what has to happen next, and all threats in one
 * list. A click on a use case opens its details in a side panel. `InterviewSummary` is the live
 * panel beside steps 1 to 4.
 */

type Form = Omit<InterviewSave, "expected_version">;

/** What identifies a use case of the interview: an L2, or an L3 rule chosen by hand. */
export interface UseCaseRef {
  level?: UseCaseLevel;
  l2_id: number;
  l3_id?: number | null;
  code: string;
  l2_code?: string | null;
}

const letter = (c: ThreatCategory | string) => ((STRIDE as string[]).includes(c) ? threatLabel(c).charAt(0) : "+");
const findProposal = (list: Proposal[], u: UseCaseRef) =>
  list.find((p) => ((p.level ?? "L2") === "L3" ? u.level === "L3" && p.l3_id === u.l3_id : u.level !== "L3" && p.l2_id === u.l2_id));

/** The column of the use case board a use case belongs to. */
type Lane = "detects" | "sources" | "norule";
function laneOf(p: Proposal): Lane {
  if (p.deleted || p.detection === "no_rules") return "norule";
  if (p.detection === "ok") return "detects";
  return "sources";
}

const DETECTION_WHY: Record<Detection, string> = {
  ok: t("An active rule detects it, and the components deliver the log sources it needs."),
  partial: t("Active rules exist, but the components deliver only some of the log sources they need."),
  blind: t("Active rules exist, but the components deliver none of the log sources they need."),
  unknown: t("Active rules exist, but their log sources are not recorded, so coverage cannot be checked."),
  no_rules: t("No active rule yet, so nothing alerts on this use case today."),
};

// ---------------------------------------------------------------- overview with tabs

export function InterviewOverview({ iv }: { iv: Interview }) {
  const [tab, setTab] = useState<"matrix" | "board" | "list">("matrix");
  const [details, setDetails] = useState<UseCaseRef | null>(null);
  const v = iv.view;
  const risks = v.risks ?? [];
  const tabs: [typeof tab, string][] = [
    ["matrix", t("Matrix")],
    ["board", t("Use case board")],
    ["list", t("Threat list")],
  ];
  return (
    <div className="stack iv-overview">
      <div className="tabs" role="tablist" aria-label={t("Overview")}>
        {tabs.map(([k, label]) => (
          <button
            key={k}
            id={`ov-tab-${k}`}
            type="button"
            role="tab"
            aria-selected={tab === k}
            aria-controls="ov-panel"
            className={"tab" + (tab === k ? " active" : "")}
            onClick={() => setTab(k)}
          >
            {label}
          </button>
        ))}
      </div>
      <div id="ov-panel" role="tabpanel" aria-labelledby={`ov-tab-${tab}`} className="stack">
        {tab === "matrix" && (
          <>
            <RiskCoverage risks={risks} components={v.components} onUseCase={setDetails} title={t("Threat matrix")} />
            {risks.length > 0 && <RiskMap risks={risks} threshold={v.threshold} />}
          </>
        )}
        {tab === "board" && <UseCaseBoard iv={iv} onOpen={setDetails} />}
        {tab === "list" && <ThreatList risks={risks} onOpen={setDetails} />}
      </div>
      {details && <UseCaseDetails u={details} iv={iv} onClose={() => setDetails(null)} />}
    </div>
  );
}

/** Where the applying threats sit on the likelihood × impact grid. */
function RiskMap({ risks, threshold }: { risks: RiskRow[]; threshold: number }) {
  const rated = risks.filter((r) => r.likelihood && r.impact);
  return (
    <section className="card stack-sm" aria-labelledby="rmap-h">
      <div>
        <h2 id="rmap-h">{t("Risk map")}</h2>
        <p className="muted small" style={{ margin: 0 }}>
          {t("Where the rated threats sit. Outlined squares reach the proposal threshold of {n}.", { n: threshold })}
        </p>
      </div>
      <div className="scroll-x">
        <table className="rmap" aria-label={t("Risk map")}>
          <tbody>
            {[5, 4, 3, 2, 1].map((l) => (
              <tr key={l}>
                <th scope="row">{LIKELIHOOD_LABEL[l - 1]}</th>
                {[1, 2, 3, 4, 5].map((i) => {
                  const here = rated.filter((r) => r.likelihood === l && r.impact === i);
                  return (
                    <td key={i} className={`lv-${riskLevel(l * i)}` + (l * i >= threshold ? " is-thr" : "")}>
                      {here.map((r) => (
                        <span
                          key={`${r.component}:${r.category}`}
                          className="rmap-chip"
                          title={`${r.component_name} · ${threatLabel(r.category)}: ${r.description}`}
                        >
                          <span className={`cov-dot cov-${r.coverage}`} aria-hidden="true" />
                          {r.component_name} · {letter(r.category)}
                        </span>
                      ))}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
          <tfoot>
            <tr>
              <td />
              {IMPACT_LABEL.map((x) => (
                <th key={x} scope="col">
                  {x}
                </th>
              ))}
            </tr>
          </tfoot>
        </table>
      </div>
      <p className="small muted" style={{ margin: 0 }}>
        {t("↑ Likelihood · Impact →")}
      </p>
    </section>
  );
}

// ---------------------------------------------------------------- use case board

function UseCaseBoard({ iv, onOpen }: { iv: Interview; onOpen: (u: UseCaseRef) => void }) {
  const v = iv.view;
  const risks = v.risks ?? [];
  const score = useMemo(() => new Map(risks.map((r) => [`${r.component}:${r.category}`, r.score])), [risks]);
  const lanes: { key: Lane; label: string; hint: string; cls: RiskCoverageState }[] = [
    { key: "detects", label: t("Detects today"), hint: t("Active rule, and the log sources it needs are delivered."), cls: "covered" },
    { key: "sources", label: t("Log sources missing"), hint: t("Active rules exist; onboard the missing log sources."), cls: "partial" },
    { key: "norule", label: t("No active rule"), hint: t("Accepted, but a rule has to be built or activated."), cls: "gap" },
  ];
  const byRisk = new Map<string, typeof v.requests>();
  for (const r of v.requests) {
    const k = `${r.component}:${r.category}`;
    byRisk.set(k, [...(byRisk.get(k) ?? []), r]);
  }
  const bareGaps = risks.filter((r) => r.coverage === "gap" && !byRisk.has(`${r.component}:${r.category}`));

  return (
    <section className="stack-sm" aria-label={t("Use case board")}>
      <p className="muted small" style={{ margin: 0 }}>
        {t("Every accepted use case with the threats it should detect, grouped by what the use case team has to do next. Click a card for the details.")}
      </p>
      <div className="ucb">
        {lanes.map((lane) => {
          const list = v.proposals.filter((p) => laneOf(p) === lane.key).sort((a, b) => b.sources.length - a.sources.length || a.code.localeCompare(b.code));
          return (
            <section key={lane.key} className="ucb-col" aria-label={lane.label}>
              <h3 className={`ucb-head cov-line-${lane.cls}`}>
                {lane.label}
                <span className="ucb-n">{list.length}</span>
              </h3>
              <p className="ucb-hint">{lane.hint}</p>
              {list.map((p) => {
                const level = p.level ?? "L2";
                const active = p.rules.filter((r) => r.active).length;
                return (
                  <button key={`${level}-${p.l3_id ?? p.l2_id}`} type="button" className="ucb-card" onClick={() => onOpen(p)}>
                    <span className="ucb-top">
                      <span className={`lvl lvl-${level}`}>{level}</span>
                      <span className="code-tag">{p.code}</span>
                      <span className="grow" />
                      <span className="small muted">{t("{n} threats", { n: p.sources.length })}</span>
                    </span>
                    <span className="ucb-name">{p.name}</span>
                    <span className="ucb-meta">
                      {p.deleted
                        ? t("deleted")
                        : p.rules.length
                          ? t("{a} of {n} rules active", { a: active, n: p.rules.length })
                          : t("No rule yet")}
                      {p.manual ? ` · ${t("added by hand")}` : ""}
                    </span>
                    <span className="ucb-thr">
                      {p.sources.map((s) => (
                        <span key={`${s.component}:${s.category}`} className="ucb-chip">
                          <span className={`risk risk-${riskLevel(score.get(`${s.component}:${s.category}`) ?? s.score) ?? 0}`}>{s.score ?? "–"}</span>
                          {s.component_name} · {letter(s.category)}
                        </span>
                      ))}
                    </span>
                    <span className="ucb-more">{t("Details")} →</span>
                  </button>
                );
              })}
              {!list.length && <p className="small muted">{t("None")}</p>}
            </section>
          );
        })}
        <section className="ucb-col" aria-label={t("Detection requests")}>
          <h3 className="ucb-head cov-line-req">
            {t("Detection requests")}
            <span className="ucb-n">{v.requests.length}</span>
          </h3>
          <p className="ucb-hint">{t("For gaps and on top of existing use cases. They go to the use case team when the interview is completed.")}</p>
          {[...byRisk.entries()].map(([k, reqs]) => {
            const r = risks.find((x) => `${x.component}:${x.category}` === k);
            return (
              <div key={k} className="ucb-card is-static">
                <span className="ucb-top">
                  <span className="ucb-letter">{letter(reqs[0]!.category)}</span>
                  <span className="grow">{reqs[0]!.component_name}</span>
                  {r && <span className={`risk risk-${r.level ?? 0}`}>{r.score ?? "–"}</span>}
                </span>
                <span className="ucb-name">
                  {threatLabel(reqs[0]!.category)}{" "}
                  {r && <span className={`cov-badge cov-${r.coverage}`}>{COVERAGE_LABEL[r.coverage]}</span>}
                </span>
                <ol className="ucb-reqs">
                  {reqs.map((q) => (
                    <li key={q.key}>
                      {q.title} <StatusChip status={q.status} />
                    </li>
                  ))}
                </ol>
              </div>
            );
          })}
          {bareGaps.map((r) => (
            <div key={`${r.component}:${r.category}`} className="ucb-card is-static is-warn">
              <span className="ucb-top">
                <span className="ucb-letter">{letter(r.category)}</span>
                <span className="grow">{r.component_name}</span>
                <span className={`risk risk-${r.level ?? 0}`}>{r.score ?? "–"}</span>
              </span>
              <span className="ucb-name">{threatLabel(r.category)}</span>
              <span className="ucb-meta">{t("Gap without a detection request.")}</span>
            </div>
          ))}
          {!v.requests.length && !bareGaps.length && <p className="small muted">{t("None")}</p>}
        </section>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- threat list

function ThreatList({ risks, onOpen }: { risks: RiskRow[]; onOpen: (u: UseCaseRef) => void }) {
  if (!risks.length) return <p className="muted">{t("No threat applies, so there is no risk to cover.")}</p>;
  return (
    <div className="card scroll-x">
      <table className="table table-plain">
        <thead>
          <tr>
            <th className="num">{t("Risk")}</th>
            <th>{t("Threat")}</th>
            <th>{t("Coverage")}</th>
            <th>{t("Use cases")}</th>
          </tr>
        </thead>
        <tbody>
          {risks.map((r) => (
            <tr key={`${r.component}:${r.category}`}>
              <td className="num">
                <span className={`risk risk-${r.level ?? 0}`}>{r.score ?? "–"}</span>
              </td>
              <td>
                <strong>
                  {r.component_name} · {threatLabel(r.category)}
                </strong>
                {r.description && <div className="small muted">{r.description}</div>}
                {r.requests.length > 0 && (
                  <ul className="plain-list small tl-reqs">
                    {r.requests.map((q, i) => (
                      <li key={i}>
                        ↗ {q.title} <StatusChip status={q.status} />
                      </li>
                    ))}
                  </ul>
                )}
              </td>
              <td>
                <span className={`cov-badge cov-${r.coverage}`}>{COVERAGE_LABEL[r.coverage]}</span>
              </td>
              <td>
                <div className="chips">
                  {r.use_cases.map((u) => (
                    <button
                      key={`${u.level}-${u.l3_id ?? u.l2_id}`}
                      type="button"
                      className="chip chip-btn"
                      disabled={u.deleted}
                      title={`${u.name}: ${detectionLabel(u.detection, u.level, u.deleted)}`}
                      onClick={() => onOpen(u)}
                    >
                      <span className={`cov-dot uc-${u.state}`} aria-hidden="true" />
                      <span className="mono">{u.code}</span>
                    </button>
                  ))}
                  {!r.use_cases.length && <span className="muted small">–</span>}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------- use case details

/** Side panel with the details of one use case of the interview. */
export function UseCaseDetails({ u, iv, onClose }: { u: UseCaseRef; iv: Interview; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const level = u.level ?? "L2";
  const l2code = level === "L3" ? u.l2_code ?? "" : u.code;
  const p = findProposal(iv.view.proposals, u);
  const [l2, setL2] = useState<L2 | null>(null);
  const [l3s, setL3s] = useState<L3[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
  }, []);
  useEffect(() => {
    let live = true;
    setError(null);
    if (!l2code) return;
    Promise.all([api.l2(l2code), api.l3s({ l2: l2code })])
      .then(([a, b]) => {
        if (!live) return;
        setL2(a);
        setL3s(b);
      })
      .catch((e: Error) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [l2code]);

  const rules = p?.rules ?? [];
  const byCode = new Map((l3s ?? []).map((r) => [r.code, r]));
  const techniques = [...new Set(rules.flatMap((r) => byCode.get(r.code)?.attack_techniques ?? []))].sort();
  const others = (l2?.systems ?? []).filter((s) => s.id !== iv.system_id);
  const comps = new Map(iv.view.components.map((c) => [c.key, c]));
  const name = p?.name ?? (level === "L3" ? byCode.get(u.code)?.name : l2?.name) ?? "";

  return (
    <dialog ref={ref} className="side-panel" aria-labelledby="ucd-title" onClose={onClose} onCancel={onClose}>
      <div className="side-panel-head">
        <span className="small muted">{t("Use case details")}</span>
        <button type="button" className="btn btn-sm" onClick={onClose}>
          {t("Close")}
        </button>
      </div>
      <div className="stack ucd">
        <div>
          <div className="row-actions start">
            <span className={`lvl lvl-${level}`}>{level}</span>
            <span className="code-tag">{u.code}</span>
            {p?.detection && <span className={`uc-state uc-${p.detection === "ok" ? "ok" : p.detection === "no_rules" ? "gap" : "partial"}`}>{detectionLabel(p.detection, level, !!p.deleted)}</span>}
          </div>
          <h2 id="ucd-title" className="ucd-title">
            {name}
          </h2>
          {level === "L3" && u.l2_code && <p className="small muted">{t("rule of {code} {name}", { code: u.l2_code, name: p?.l2_name ?? "" })}</p>}
          {l2?.description && <p className="small ink-2 ucd-desc">{l2.description}</p>}
        </div>
        {p?.detection && <div className={`note-box ucd-why uc-why-${p.detection}`}>{DETECTION_WHY[p.detection]}</div>}
        <ErrorNote error={error} />

        <section className="stack-sm">
          <h3 className="ucd-h">{t("Threats it covers in this interview ({n})", { n: p?.sources.length ?? 0 })}</h3>
          {p?.sources.length ? (
            <ul className="plain-list ucd-list">
              {p.sources.map((s) => (
                <li key={`${s.component}:${s.category}`}>
                  <span className={`risk risk-${riskLevel(s.score) ?? 0}`}>{s.score ?? "–"}</span> {s.component_name} · {threatLabel(s.category)}
                </li>
              ))}
            </ul>
          ) : (
            <p className="small muted">{t("Not accepted for a threat of this interview.")}</p>
          )}
        </section>

        <section className="stack-sm">
          <h3 className="ucd-h">{t("Rules and log sources ({n})", { n: rules.length })}</h3>
          {rules.length ? (
            <ul className="plain-list ucd-rules">
              {rules.map((r) => {
                const l3 = byCode.get(r.code);
                return (
                  <li key={r.code} className={r.active ? undefined : "muted"}>
                    <div className="row-actions start">
                      <span className="mono small">{r.code}</span>
                      <strong className="grow">{r.name}</strong>
                      <StatusPill status={r.lifecycle_status} />
                    </div>
                    <div className="small muted">
                      {r.active ? t("Counts for detection") : t("Not counted (inactive)")}
                      {l3?.last_verified_at
                        ? ` · ${t("last verified {date}", { date: fmtDate(l3.last_verified_at) })}`
                        : ` · ${t("never verified")}`}
                    </div>
                    {r.log_sources.length > 0 ? (
                      <div className="chips ucd-ls">
                        {r.log_sources.map((ls) =>
                          r.missing.includes(ls) ? (
                            <span key={ls} className="chip ucd-miss" title={t("Not delivered by the threatened components")}>
                              ✗ {ls}
                            </span>
                          ) : (
                            <span key={ls} className="chip ucd-ok" title={t("Delivered")}>
                              ✓ {ls}
                            </span>
                          ),
                        )}
                      </div>
                    ) : (
                      <div className="small muted">{t("No log source recorded on this rule.")}</div>
                    )}
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="small muted">{t("No rule exists yet. A detection request on the threat asks the use case team to build one.")}</p>
          )}
          {p && p.sources.length > 0 && (
            <p className="small muted" style={{ margin: 0 }}>
              {t("Delivered by the threatened components")}:{" "}
              {[...new Set(p.sources.map((s) => s.component))]
                .map((k) => {
                  const c = comps.get(k);
                  return c ? `${c.name}: ${c.log_sources.map((x) => x.name).join(", ") || t("none")}` : "";
                })
                .filter(Boolean)
                .join(" · ")}
            </p>
          )}
        </section>

        {techniques.length > 0 && (
          <section className="stack-sm">
            <h3 className="ucd-h">{t("MITRE ATT&CK")}</h3>
            <div className="chips">
              {techniques.map((x) => (
                <span key={x} className="chip chip-neutral mono">
                  {x}
                </span>
              ))}
            </div>
          </section>
        )}

        {l2 && (
          <section className="stack-sm">
            <h3 className="ucd-h">{t("Also linked to")}</h3>
            <p className="small" style={{ margin: 0 }}>
              {others.length ? others.map((s) => s.name).join(", ") : <span className="muted">{t("No other system")}</span>}
            </p>
          </section>
        )}

        <div>
          <Link className="btn btn-sm" to={useCaseHref({ level, code: u.code })}>
            {t("Open in Use cases")}
          </Link>
        </div>
      </div>
    </dialog>
  );
}

// ---------------------------------------------------------------- live summary (steps 1 to 4)

export function InterviewSummary({
  iv,
  form,
  onJump,
  onStep,
}: {
  iv: Interview;
  form: Form;
  onJump: (comp: string, cat: string) => void;
  onStep: (n: number) => void;
}) {
  const v = iv.view;
  const risk = new Map((v.risks ?? []).map((r) => [`${r.component}:${r.category}`, r]));
  const cells = form.components.length * 6;
  let answered = 0;
  const applying: { comp: string; name: string; cat: string; score: number | null; cov: RiskCoverageState }[] = [];
  const incomplete: { comp: string; name: string; cat: string }[] = [];
  for (const c of form.components) {
    for (const cat of STRIDE) {
      const x = c.threats.find((y) => y.category === cat);
      if (x && x.state !== "not_discussed") answered++;
      if (x?.state !== "applies") continue;
      const s = x.likelihood && x.impact ? x.likelihood * x.impact : null;
      const rated = s !== null && x.description.trim();
      if (!rated) incomplete.push({ comp: c.key, name: c.name, cat });
      const r = risk.get(`${c.key}:${cat}`);
      applying.push({ comp: c.key, name: c.name, cat, score: s, cov: !rated ? "unrated" : r && r.score === s ? r.coverage : s < v.threshold ? "below" : "unrated" });
    }
  }
  applying.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
  const pct = cells ? Math.round((answered / cells) * 100) : 0;
  const lanes = { detects: 0, sources: 0, norule: 0 };
  for (const p of v.proposals) lanes[laneOf(p)]++;
  const gaps = (v.risks ?? []).filter((r) => r.coverage === "gap");
  const noLogs = form.components.filter((c) => !c.log_source_ids.length);
  const attention = incomplete.length + gaps.length + noLogs.length;

  return (
    <aside className="iv-summary" aria-label={t("Live summary")}>
      <section className="card">
        <h3 className="iv-sum-h">{t("Progress")}</h3>
        <div className="row-actions start">
          <strong className="iv-sum-big">{pct}%</strong>
          <span className="small muted">{t("{a} of {n} questions answered", { a: answered, n: cells })}</span>
        </div>
        <div className="bar" aria-hidden="true">
          <div style={{ width: `${pct}%` }} />
        </div>
        {form.components.length > 0 && (
          <table className="iv-mini" aria-label={t("Components and STRIDE categories")}>
            <thead>
              <tr>
                <th />
                {STRIDE.map((cat) => (
                  <th key={cat} scope="col" title={STRIDE_LABEL[cat]}>
                    {STRIDE_LABEL[cat].charAt(0)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {form.components.map((c, i) => (
                <tr key={c.key}>
                  <th scope="row" title={c.name}>
                    {c.name || t("Component {n}", { n: i + 1 })}
                  </th>
                  {STRIDE.map((cat) => {
                    const x = c.threats.find((y) => y.category === cat);
                    const st = x?.state ?? "not_discussed";
                    const a = applying.find((y) => y.comp === c.key && y.cat === cat);
                    const label = `${c.name} · ${STRIDE_LABEL[cat]}: ${
                      st === "applies" ? COVERAGE_LABEL[a?.cov ?? "unrated"] + (a?.score ? ` (${a.score})` : "") : st === "does_not_apply" ? t("Does not apply") : t("Not discussed")
                    }`;
                    return (
                      <td key={cat}>
                        <button
                          type="button"
                          className={"iv-mini-cell " + (st === "applies" ? `cov-${a?.cov ?? "unrated"}` : st === "does_not_apply" ? "is-no" : "is-open")}
                          title={label}
                          aria-label={label}
                          onClick={() => onJump(c.key, cat)}
                        >
                          {st === "applies" ? a?.score ?? "?" : st === "does_not_apply" ? "–" : ""}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <h3 className="iv-sum-h">{t("Threats that apply ({n})", { n: applying.length })}</h3>
        {applying.length ? (
          <ul className="plain-list iv-top">
            {applying.slice(0, 7).map((a) => (
              <li key={`${a.comp}:${a.cat}`}>
                <button type="button" onClick={() => onJump(a.comp, a.cat)}>
                  <span className={`risk risk-${riskLevel(a.score) ?? 0}`}>{a.score ?? "–"}</span>
                  <span className="iv-top-name">
                    {a.name} · {threatLabel(a.cat)}
                  </span>
                  <span className={`cov-dot cov-${a.cov}`} title={COVERAGE_LABEL[a.cov]} />
                </button>
              </li>
            ))}
            {applying.length > 7 && <li className="small muted">{t("+ {n} more", { n: applying.length - 7 })}</li>}
          </ul>
        ) : (
          <p className="small muted" style={{ margin: 0 }}>
            {t("No threat applies yet.")}
          </p>
        )}
      </section>

      <section className="card">
        <h3 className="iv-sum-h">{t("Use cases ({n})", { n: v.proposals.length })}</h3>
        <dl className="iv-sum-dl">
          <dt>
            <span className="cov-dot uc-ok" aria-hidden="true" /> {t("Detect today")}
          </dt>
          <dd>{lanes.detects}</dd>
          <dt>
            <span className="cov-dot uc-partial" aria-hidden="true" /> {t("Log sources missing")}
          </dt>
          <dd>{lanes.sources}</dd>
          <dt>
            <span className="cov-dot uc-gap" aria-hidden="true" /> {t("No active rule")}
          </dt>
          <dd>{lanes.norule}</dd>
          <dt>↗ {t("Detection requests")}</dt>
          <dd>{form.requests.length}</dd>
        </dl>
        <p className="small muted" style={{ margin: "6px 0 0" }}>
          {t("As of the last save.")}
        </p>
      </section>

      <section className="card">
        <h3 className="iv-sum-h">{t("Needs attention ({n})", { n: attention })}</h3>
        <ul className="plain-list iv-attn">
          {incomplete.map((x) => (
            <li key={`i-${x.comp}:${x.cat}`}>
              <button type="button" className="is-info" onClick={() => onJump(x.comp, x.cat)}>
                <strong>{t("Needs rating")}:</strong> {x.name} · {threatLabel(x.cat)}
              </button>
            </li>
          ))}
          {gaps.map((r) => (
            <li key={`g-${r.component}:${r.category}`}>
              <button type="button" onClick={() => onStep(4)}>
                <strong>{t("Gap")}:</strong> {r.component_name} · {threatLabel(r.category)} ({r.score})
                {r.requests.length > 0 && ` · ${t("{n} detection requests", { n: r.requests.length })}`}
              </button>
            </li>
          ))}
          {noLogs.map((c) => (
            <li key={`l-${c.key}`}>
              <button type="button" className="is-fair" onClick={() => onStep(2)}>
                <strong>{t("No log sources")}:</strong> {c.name || "–"}
              </button>
            </li>
          ))}
          {!attention && <li className="small muted">{t("Nothing open.")}</li>}
        </ul>
      </section>
    </aside>
  );
}
