import { Link } from "react-router-dom";
import { api, type DriverCoverageReport, type OverviewRequest, type SystemRow, type DueRule, type Kpis, type RecentCommit, type Scores } from "../api";
import { useAuth } from "../auth";
import { CoverageCell } from "../components/Drivers";
import { ErrorNote, GapBadge, MetricBars, MetricLegend, useLoad } from "../components/ui";
import { fmtDate, num, pct, today } from "../lib/format";
import { t } from "../i18n";

interface Tile {
  label: string;
  value: number | null;
  sub: string;
  /** where the figure comes from */
  to: string;
  /** growth potential shrinks as the detection score grows */
  lower?: boolean;
}

/** The four figures that answer "how well are we covered"; the rest sits under "More figures". */
function kpiTiles(k: Kpis): { main: Tile[]; more: Tile[] } {
  return {
    main: [
      { label: t("SOC detection score"), value: k.soc_detection_score, sub: t("Average weight of applicable L1"), to: "/usecases" },
      {
        label: t("Catalogue coverage"),
        value: k.catalogue_coverage,
        sub: t("Same average, L2 without scored rules count as 0"),
        to: "/usecases?view=table",
      },
      {
        label: t("Framework completeness"),
        value: k.framework_completeness,
        sub: t("{a} of {b} L2 have scored rules", { a: k.l2_with_scored_rules, b: k.applicable_l2 }),
        to: "/usecases?view=table",
      },
      {
        label: t("Verification health"),
        value: k.verification_health,
        sub: t("{a} of {b} rules overdue", { a: k.verification_overdue, b: k.operational_rules }),
        to: "/verification",
      },
    ],
    more: [
      {
        label: t("Assessment coverage"),
        value: k.assessment_coverage,
        sub: t("{a} of {b} active rules assessed", { a: k.assessed_rules, b: k.active_rules }),
        to: "/usecases?view=table",
      },
      { label: t("Growth potential"), value: k.growth_potential, sub: t("Average effectiveness − weight"), to: "/priorities", lower: true },
    ],
  };
}

type Rating = "good" | "fair" | "poor";

/**
 * Rates a key figure so the tile shows at a glance whether it is good or needs work.
 * Higher-is-better figures: good from 70 %, fair from 40 %. Lower-is-better figures are mirrored.
 */
export function rateKpi(value: number | null, lowerIsBetter: boolean): Rating | null {
  if (value === null || value === undefined) return null;
  const score = lowerIsBetter ? 1 - value : value;
  if (score >= 0.7) return "good";
  if (score >= 0.4) return "fair";
  return "poor";
}

const RATING_LABEL: Record<Rating, string> = { good: t("Good"), fair: t("Fair"), poor: t("Poor") };

export function DueBadge({ d }: { d: Pick<DueRule, "due" | "overdue" | "days_left"> }) {
  if (!d.due) return <span className="badge-gap">{t("Never verified")}</span>;
  if (d.overdue) return <span className="badge-gap">{t("{n} days overdue", { n: -(d.days_left ?? 0) })}</span>;
  return <span className="pill pill-ok">{t("due in {n} days", { n: d.days_left })}</span>;
}

/** One KPI tile: the label links to the list behind the figure. */
function KpiTile({ k, ready }: { k: Tile; ready: boolean }) {
  const rating = ready ? rateKpi(k.value, !!k.lower) : null;
  return (
    <div className="card kpi">
      <Link to={k.to} className="kpi-label">
        {k.label}
      </Link>
      <div className="kpi-head">
        <span className="kpi-value">{ready ? pct(k.value) : "–"}</span>
        {rating && <span className={`kpi-rating rating-${rating}`}>{RATING_LABEL[rating]}</span>}
      </div>
      <div className="bar">
        <div style={{ width: `${Math.round((k.value ?? 0) * 100)}%` }} className={rating ? `rating-${rating}` : ""} />
      </div>
      <span className="kpi-sub">{ready ? k.sub : "…"}</span>
      {k.lower && (
        <span className="kpi-good">
          <span aria-hidden="true">↓</span> {t("Lower is better")}
        </span>
      )}
    </div>
  );
}

/** Work that is waiting, with a link to each list. Shown before the scores. */
function Attention({
  overdue,
  requests,
  gaps,
  interviews,
  testGaps,
  ready,
}: {
  overdue: number | null;
  requests: number | null;
  gaps: number | null;
  interviews: number | null;
  testGaps: number | null;
  ready: boolean;
}) {
  const items = [
    { n: overdue, label: t("rules never verified or overdue"), to: "/verification", action: t("Verify") },
    { n: requests, label: t("open or in-progress detection requests"), to: "/usecases/requests", action: t("Show requests") },
    { n: gaps, label: t("gaps in systems"), to: "/systems", action: t("Show systems") },
    { n: interviews, label: t("interviews due"), to: "/systems?due=1", action: t("Show systems") },
    { n: testGaps, label: t("detection gaps from tests"), to: "/verification/gaps", action: t("Show gaps") },
  ].filter((x) => x.n);
  return (
    <section className="card stack-sm attention" aria-labelledby="needh">
      <h2 id="needh">{t("Needs attention")}</h2>
      {!ready ? (
        <p className="muted small">…</p>
      ) : items.length === 0 ? (
        <p className="muted">{t("Nothing needs attention right now.")}</p>
      ) : (
        <ul className="plain-list attention-list">
          {items.map((x) => (
            <li key={x.to}>
              <strong className="attention-n">{x.n}</strong>
              <span className="attention-label">{x.label}</span>
              <Link to={x.to} className="btn btn-sm">
                {x.action}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default function Dashboard() {
  const { can } = useAuth();
  const scores = useLoad<Scores>(() => api.scores());
  const due = useLoad<DueRule[]>(() => api.due(30));
  const commits = useLoad<RecentCommit[]>(() => api.recentCommits(5));
  const drivers = useLoad<DriverCoverageReport>(() => api.driverCoverage());
  const interviewsDue = useLoad(() => api.systemsDue());
  const requests = useLoad<{ requests: OverviewRequest[] }>(() => api.detectionRequests());
  const systems = useLoad<SystemRow[]>(() => api.systems());
  const testGaps = useLoad(() => api.testGapCount());
  const s = scores.data;
  const tiles = kpiTiles(s ? s.kpis : ({} as Kpis));
  const ready = due.data !== null && requests.data !== null && systems.data !== null && interviewsDue.data !== null;

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Dashboard")}</h1>
          <div className="subtitle">
            {t("Workspace: Default SOC")}
            {s &&
              ` · ${s.l1.length} L1 · ${s.l2.length} L2 · ${s.l1.reduce((a, x) => a + x.rules, 0)} ${t("L3 rules")}`}
          </div>
        </div>
        <div className="row-actions">
          <a className="btn" href="/api/report.pdf" download>
            {t("Download PDF report")}
          </a>
          {can("admin", "analyst") && (
            <Link className="btn btn-primary" to="/usecases">
              {t("Edit use cases")}
            </Link>
          )}
        </div>
      </header>

      <ErrorNote error={scores.error} />

      <Attention
        ready={ready}
        overdue={due.data ? due.data.filter((d) => !d.due || d.overdue).length : null}
        requests={
          requests.data ? requests.data.requests.filter((r) => !r.archived && (r.status === "open" || r.status === "in_progress")).length : null
        }
        gaps={systems.data ? systems.data.reduce((a, x) => a + x.gaps, 0) : null}
        interviews={interviewsDue.data?.due ?? null}
        testGaps={testGaps.data?.open ?? null}
      />

      <section className="stack-sm" aria-labelledby="kpih">
        <h2 id="kpih">
          {t("Key figures")}
        </h2>
        <div className="kpi-grid kpi-grid-4">
          {tiles.main.map((k) => (
            <KpiTile key={k.label} k={k} ready={!!s} />
          ))}
        </div>
        <p className="muted small">
          {t("Figures as of {date}.", { date: fmtDate(today()) })}{" "}
          {t("Rating: Good from 70 %, Fair from 40 %, Poor below. For figures where lower is better, the scale is mirrored.")}
        </p>
        <details className="kpi-more">
          <summary>{t("More figures")}</summary>
          <div className="kpi-grid kpi-grid-4">
            {tiles.more.map((k) => (
              <KpiTile key={k.label} k={k} ready={!!s} />
            ))}
          </div>
        </details>
      </section>

      <section className="card" aria-labelledby="l1h">
          <div className="section-head">
            <h2 id="l1h">{t("Detection per L1 use case")}</h2>
            <MetricLegend />
          </div>
          <div className="scroll-x">
            <table className="table table-plain">
              <thead>
                <tr>
                  <th>{t("L1 use case")}</th>
                  <th className="num">L2</th>
                  <th className="num">L3</th>
                  <th style={{ width: "34%" }}>{t("Eff / Impl / Cov")}</th>
                  <th className="num">{t("Weight")}</th>
                  <th className="num">{t("Potential")}</th>
                </tr>
              </thead>
              <tbody>
                {s?.l1.map((r) => (
                  <tr key={r.code} className={r.applicable ? "" : "row-muted"}>
                    <td>
                      <Link className="code-link" to={`/usecases?l1=${r.code}`}>
                        <span className="code-tag">{r.code}</span>
                        <span>{r.name}</span>
                      </Link>
                    </td>
                    <td className="num">
                      {r.scored_l2}/{r.l2_count}
                    </td>
                    <td className="num">{r.rules}</td>
                    <td>
                      {!r.applicable ? (
                        <span className="muted">{t("Not applicable")}</span>
                      ) : r.weight === null ? (
                        <GapBadge>
                          {t("Detection gap ·")} {r.rules ? t("no scored rules") : t("no rules yet")}
                        </GapBadge>
                      ) : (
                        <MetricBars e={r.effectiveness} i={r.implementation} c={r.coverage} />
                      )}
                    </td>
                    <td className="num strong">{num(r.weight)}</td>
                    <td className="num">{num(r.potential)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted small">
            {t(
              "L2 column: use cases with scored rules / all. Only operational and maintenance rules with all three metrics count.",
            )}
          </p>
      </section>

      <div className="two-col even">
          <section className="card stack-sm" aria-labelledby="vh">
            <div className="section-head">
              <h2 id="vh">{t("Verification due")}</h2>
              <Link to="/verification" className="small">
                {t("All")} {due.data?.length ?? ""}
              </Link>
            </div>
            <ErrorNote error={due.error} />
            {due.data && !due.data.length && <p className="muted">{t("Nothing is due in the next 30 days.")}</p>}
            <ul className="link-list">
              {due.data?.slice(0, 7).map((d) => (
                <li key={d.code}>
                  <Link to={`/usecases/l3/${d.code}`}>
                    <span className="stack">
                      <span className="mono small muted">{d.code}</span>
                      <span className="strong-500">{d.name}</span>
                      {d.last_verified_at && (
                        <span className="small muted">
                          {t("Last verified")} {fmtDate(d.last_verified_at)}
                        </span>
                      )}
                    </span>
                    <DueBadge d={d} />
                  </Link>
                </li>
              ))}
            </ul>
          </section>

          <section className="card stack-sm" aria-labelledby="ch">
            <h2 id="ch">{t("Recent config commits")}</h2>
            {commits.data && !commits.data.length && <p className="muted small">{t("No configurations yet.")}</p>}
            <ul className="link-list">
              {commits.data?.map((c) => (
                <li key={c.sha}>
                  <Link to={c.level === "l3" ? `/usecases/l3/${c.code}` : `/usecases?l2=${c.code}`}>
                    <span className="mono small accent" style={{ paddingTop: 1 }}>
                      {c.short}
                    </span>
                    <span className="stack grow">
                      <span className="strong-500">{c.message}</span>
                      <span className="small muted">
                        {c.code} r{c.rev} · {c.author} · {fmtDate(c.created_at)}
                      </span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>
      </div>
      <DriverCoverageCards data={drivers.data} error={drivers.error} />
    </>
  );
}

function DriverCoverageCards({ data, error }: { data: DriverCoverageReport | null; error: string | null }) {
  return (
    <div className="two-col even">
      <section className="card table-card" aria-labelledby="bdc">
        <div className="table-title section-head">
          <h2 id="bdc">{t("Coverage per business driver")}</h2>
          <Link to="/drivers" className="small">
            {t("Drivers")}
          </Link>
        </div>
        <ErrorNote error={error} />
        <div className="scroll-x">
        <table className="table table-compact">
          <thead>
            <tr>
              <th>{t("Business driver")}</th>
              <th className="num">L2</th>
              <th style={{ width: "38%" }}>{t("Coverage")}</th>
            </tr>
          </thead>
          <tbody>
            {data?.business.map((d) => (
              <tr key={d.id}>
                <td>
                  <Link className="code-link" to={`/usecases?bd=${encodeURIComponent(d.code)}&view=table`}>
                    <span className="code-tag">{d.code}</span>
                    <span>{d.name}</span>
                  </Link>
                </td>
                <td className="num">{d.l2_count}</td>
                <td>
                  <CoverageCell d={d} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </section>
      <section className="card table-card" aria-labelledby="csc">
        <div className="table-title section-head">
          <h2 id="csc">{t("Coverage per compliance source")}</h2>
        </div>
        <div className="scroll-x">
        <table className="table table-compact">
          <thead>
            <tr>
              <th>{t("Compliance source")}</th>
              <th className="num">{t("Linked")}</th>
              <th className="num">L2</th>
              <th style={{ width: "38%" }}>{t("Coverage")}</th>
            </tr>
          </thead>
          <tbody>
            {data?.sources.map((x) => (
              <tr key={x.id}>
                <td>
                  <Link to={`/usecases?src=${x.id}&view=table`}>{x.name}</Link>
                  {x.gap_drivers > 0 && (
                    <div className="small muted">
                      {t("Requirements without a use case: {n}", { n: x.gap_drivers })}
                    </div>
                  )}
                </td>
                <td className="num">
                  {x.linked_drivers}/{x.drivers}
                </td>
                <td className="num">{x.l2_count}</td>
                <td>
                  <CoverageCell
                    d={{ coverage: x.coverage, gap: x.l2_count === 0, low: x.coverage !== null && x.coverage < data.low_threshold }}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        {data && (
          <p className="muted small" style={{ padding: "0 16px 12px" }}>
            {t("Coverage = average weight of the linked L2 use cases; L2 without scored rules count as 0. Below {p} is low.", {
              p: pct(data.low_threshold),
            })}
          </p>
        )}
      </section>
    </div>
  );
}
