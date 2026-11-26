import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { Detection, RiskCoverageState, RiskRow } from "../api";
import { StatusChip } from "./RequestStatus";
import { num } from "../lib/format";
import { STRIDE, STRIDE_LABEL, threatLabel } from "../lib/stride";
import { t } from "../i18n";

/**
 * Threat modelling overview: every risk (applying STRIDE threat of a component) with the L2/L3
 * use cases that address it and how well they cover it. Shows a component × STRIDE matrix and a
 * risk list; clicking a matrix cell jumps to its risk.
 */

export const COVERAGE_LABEL: Record<RiskCoverageState, string> = {
  covered: t("Covered"),
  partial: t("Partly covered"),
  gap: t("Gap"),
  below: t("Below threshold"),
  unrated: t("Not rated"),
};

const COVERAGE_HINT: Record<RiskCoverageState, string> = {
  covered: t("At least one active use case gets the log sources it needs."),
  partial: t("Use cases address the risk, but log sources are missing in part or not recorded."),
  gap: t("No working detection: no use case, no active rule, or none of the log sources is delivered."),
  below: t("Below the proposal threshold and no use case chosen: accepted risk."),
  unrated: t("Likelihood or impact is missing."),
};

export function detectionLabel(d: Detection | null, level: "L2" | "L3", deleted: boolean): string {
  if (deleted) return t("deleted");
  switch (d) {
    case "ok":
      return t("Detects");
    case "partial":
      return t("Some log sources missing");
    case "unknown":
      return t("Log source unknown");
    case "blind":
      return t("Log sources missing");
    case "no_rules":
      return level === "L3" ? t("Rule not active") : t("No active rule");
    default:
      return "–";
  }
}

export function useCaseHref(u: { level?: string; code: string }): string {
  return u.level === "L3" ? `/usecases/l3/${encodeURIComponent(u.code)}` : `/usecases?l2=${encodeURIComponent(u.code)}`;
}

const riskId = (r: { component: string; category: string }) => `risk-${r.component}-${r.category}`;

type Filter = "all" | "open" | RiskCoverageState;

export type RiskUseCase = RiskRow["use_cases"][number];

export function RiskCoverage({
  risks,
  components,
  showWeight = false,
  onAdd,
  onRemove,
  onRequest,
  onUseCase,
  addDisabled,
  title,
  actions,
}: {
  risks: RiskRow[];
  /** matrix rows in interview order (components without applying threats included) */
  components: { key: string; name: string }[];
  showWeight?: boolean;
  /** offers "+ Use case" on every risk */
  onAdd?: (r: RiskRow) => void;
  /** #57: offers to take a use case off a risk */
  onRemove?: (r: RiskRow, u: RiskUseCase) => void;
  /** offers "+ Detection request" on every risk, also on covered ones */
  onRequest?: (r: RiskRow) => void;
  /** offers "Details" next to every use case */
  onUseCase?: (u: RiskUseCase) => void;
  addDisabled?: boolean;
  title?: string;
  actions?: React.ReactNode;
}) {
  const [filter, setFilter] = useState<Filter>("all");
  const [focus, setFocus] = useState<string | null>(null);
  const counts = useMemo(() => {
    const c: Record<RiskCoverageState, number> = { covered: 0, partial: 0, gap: 0, below: 0, unrated: 0 };
    for (const r of risks) c[r.coverage]++;
    return c;
  }, [risks]);
  const hasCustom = risks.some((r) => r.custom);
  const byRef = useMemo(() => new Map(risks.map((r) => [`${r.component}:${r.category}`, r])), [risks]);
  const shown = risks.filter((r) =>
    filter === "all" ? true : filter === "open" ? r.coverage === "gap" || r.coverage === "partial" : r.coverage === filter,
  );

  function jump(r: RiskRow) {
    setFilter("all");
    const id = riskId(r);
    setFocus(id);
    requestAnimationFrame(() => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "center" }));
  }

  const filters: { key: Filter; label: string; n: number }[] = [
    { key: "all", label: t("All risks"), n: risks.length },
    { key: "gap", label: COVERAGE_LABEL.gap, n: counts.gap },
    { key: "partial", label: COVERAGE_LABEL.partial, n: counts.partial },
    { key: "covered", label: COVERAGE_LABEL.covered, n: counts.covered },
    { key: "below", label: COVERAGE_LABEL.below, n: counts.below },
  ];
  if (counts.unrated) filters.push({ key: "unrated", label: COVERAGE_LABEL.unrated, n: counts.unrated });

  return (
    <section className="card stack-sm" aria-labelledby="rcov-h">
      <div className="section-head">
        <h2 id="rcov-h">{title ?? t("Risks and use cases")}</h2>
        {actions}
      </div>
      {!risks.length ? (
        <p className="muted" style={{ margin: 0 }}>
          {t("No threat applies, so there is no risk to cover.")}
        </p>
      ) : (
        <>
          <dl className="rcov-stats">
            <div>
              <dt>{t("Risks")}</dt>
              <dd>{risks.length}</dd>
            </div>
            {(["covered", "partial", "gap", "below"] as const).map((k) => (
              <div key={k} className={`rcov-stat cov-${k}`} title={COVERAGE_HINT[k]}>
                <dt>
                  <span className={`cov-dot cov-${k}`} aria-hidden="true" /> {COVERAGE_LABEL[k]}
                </dt>
                <dd>{counts[k]}</dd>
              </div>
            ))}
          </dl>

          <div className="scroll-x">
            <table className="rcov-matrix" aria-label={t("Threat matrix")}>
              <thead>
                <tr>
                  <th scope="col">{t("Component")}</th>
                  {STRIDE.map((c) => (
                    <th key={c} scope="col" title={STRIDE_LABEL[c]}>
                      <span className="rcov-letter">{STRIDE_LABEL[c].charAt(0)}</span>
                      <span className="rcov-cat">{STRIDE_LABEL[c]}</span>
                    </th>
                  ))}
                  {hasCustom && (
                    <th scope="col" title={t("Custom threats linked to MITRE ATT&CK")}>
                      <span className="rcov-letter">+</span>
                      <span className="rcov-cat">{t("ATT&CK")}</span>
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {components.map((c) => (
                  <tr key={c.key}>
                    <th scope="row">{c.name}</th>
                    {STRIDE.map((cat) => {
                      const r = byRef.get(`${c.key}:${cat}`);
                      if (!r) {
                        return (
                          <td key={cat} className="rcov-none">
                            <span aria-label={t("Does not apply")}>·</span>
                          </td>
                        );
                      }
                      return (
                        <td key={cat}>
                          <button
                            type="button"
                            className={`rcov-cell cov-${r.coverage}`}
                            onClick={() => jump(r)}
                            title={`${c.name} / ${STRIDE_LABEL[cat]}: ${COVERAGE_LABEL[r.coverage]} · ${t("{n} use cases", { n: r.use_cases.length })}`}
                          >
                            <strong>{r.score ?? "–"}</strong>
                            <span className="rcov-n">
                              {r.use_cases.length ? t("{n} UC", { n: r.use_cases.length }) : "–"}
                              {r.requests.length > 0 && (
                                <span className="rcov-req" title={t("{n} detection requests", { n: r.requests.length })}>
                                  {" "}↗{r.requests.length}
                                </span>
                              )}
                            </span>
                          </button>
                        </td>
                      );
                    })}
                    {hasCustom && (
                      <td className="rcov-custom">
                        {risks
                          .filter((r) => r.custom && r.component === c.key)
                          .map((r) => (
                            <button
                              key={r.category}
                              type="button"
                              className={`rcov-cell cov-${r.coverage}`}
                              onClick={() => jump(r)}
                              title={`${c.name} / ${threatLabel(r.category)} (${(r.techniques ?? []).join(", ")}): ${COVERAGE_LABEL[r.coverage]} · ${t("{n} use cases", { n: r.use_cases.length })}`}
                            >
                              <strong>{r.score ?? "–"}</strong>
                              <span className="rcov-n">{r.use_cases.length ? t("{n} UC", { n: r.use_cases.length }) : "–"}</span>
                            </button>
                          ))}
                        {!risks.some((r) => r.custom && r.component === c.key) && <span aria-label={t("None")}>·</span>}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted small rcov-legend" style={{ margin: 0 }}>
            {t("Cells show the risk score (likelihood × impact) and the number of use cases; the colour shows the coverage. Click a cell to jump to the risk.")}
          </p>

          <div className="filter-row" role="group" aria-label={t("Show")}>
            {filters.map((f) => (
              <button
                key={f.key}
                type="button"
                className={"filter-chip" + (filter === f.key ? " active" : "")}
                aria-pressed={filter === f.key}
                onClick={() => setFilter(f.key)}
              >
                {f.key !== "all" && <span className={`cov-dot cov-${f.key}`} aria-hidden="true" />} {f.label} ({f.n})
              </button>
            ))}
          </div>

          {!shown.length && <p className="muted small">{t("No risk matches the filter.")}</p>}
          <ul className="plain-list rcov-list">
            {shown.map((r) => (
              <li key={riskId(r)} id={riskId(r)} className={`rcov-risk cov-edge-${r.coverage}` + (focus === riskId(r) ? " is-focus" : "")}>
                <div className="rcov-risk-head">
                  <span className={`risk risk-${r.level ?? 0}`} title={t("Risk level {r}", { r: r.level ?? "–" })}>
                    {r.score ?? "–"}
                  </span>
                  <strong>
                    {r.component_name} · {threatLabel(r.category)}
                  </strong>
                  {r.custom && (r.techniques ?? []).map((x) => (
                    <span key={x} className="chip chip-neutral mono" title={t("MITRE ATT&CK technique")}>
                      {x}
                    </span>
                  ))}
                  <span className={`cov-badge cov-${r.coverage}`} title={COVERAGE_HINT[r.coverage]}>
                    {COVERAGE_LABEL[r.coverage]}
                  </span>
                  <span className="grow" />
                  {onRequest && (
                    <button type="button" className="btn btn-sm" disabled={addDisabled} onClick={() => onRequest(r)}>
                      {t("+ Detection request")}
                    </button>
                  )}
                  {onAdd && (
                    <button type="button" className="btn btn-sm" disabled={addDisabled} onClick={() => onAdd(r)}>
                      {t("+ Use case")}
                    </button>
                  )}
                </div>
                {r.description && <p className="small ink-2 rcov-desc">{r.description}</p>}
                {r.use_cases.length > 0 ? (
                  <ul className="plain-list rcov-ucs">
                    {r.use_cases.map((u) => (
                      <li key={`${u.level}-${u.l3_id ?? u.l2_id}`}>
                        <span className={`cov-dot uc-${u.state}`} aria-hidden="true" />
                        <span className={`lvl lvl-${u.level}`}>{u.level}</span>
                        {u.deleted ? (
                          <span className="muted">
                            <span className="mono small">{u.code}</span> {u.name}
                          </span>
                        ) : (
                          <Link to={useCaseHref(u)} className="rcov-uc-link">
                            <span className="mono small">{u.code}</span> {u.name}
                          </Link>
                        )}
                        {u.level === "L3" && u.l2_code && <span className="small muted">{t("in {code}", { code: u.l2_code })}</span>}
                        <span className={`uc-state uc-${u.state}`}>{detectionLabel(u.detection, u.level, u.deleted)}</span>
                        {showWeight && <span className="small muted">{t("weight {w}", { w: num(u.weight) })}</span>}
                        {onUseCase && !u.deleted && (
                          <button
                            type="button"
                            className="link-btn small"
                            aria-label={t("Details of {code}", { code: u.code })}
                            onClick={() => onUseCase(u)}
                          >
                            {t("Details")}
                          </button>
                        )}
                        {onRemove && (
                          <button
                            type="button"
                            className="link-btn small rcov-uc-remove"
                            disabled={addDisabled}
                            title={t("Remove {code} from this risk", { code: u.code })}
                            aria-label={t("Remove {code} from this risk", { code: u.code })}
                            onClick={() => onRemove(r, u)}
                          >
                            {t("Remove")}
                          </button>
                        )}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="small muted" style={{ margin: 0 }}>
                    {r.coverage === "unrated"
                      ? t("Not rated yet: add likelihood and impact in step 3.")
                      : r.above_threshold
                        ? t("No use case addresses this risk.")
                        : t("No use case chosen (below the threshold).")}
                  </p>
                )}
                {r.requests.length > 0 && (
                  <ul className="plain-list small rcov-reqs">
                    {r.requests.map((q, i) => (
                      <li key={i}>
                        <span className="chip chip-neutral">{t("Detection request")}</span> {q.title}{" "}
                        <StatusChip status={q.status} />
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
