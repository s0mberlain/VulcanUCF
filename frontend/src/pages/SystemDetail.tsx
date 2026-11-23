import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, REQUEST_STATUSES, type RequestStatus, type SystemDetail as Detail } from "../api";
import { useAuth } from "../auth";
import { confirmDialog, ErrorNote, useLoad } from "../components/ui";
import { RiskCoverage, useCaseHref } from "../components/RiskCoverage";
import { isTodo, RequestCard, statusLabel } from "../components/RequestStatus";
import { fmtDate, fmtTime, num, pct } from "../lib/format";
import { CLASSIFICATION_LABEL, INTERVIEW_STATUS_LABEL, registerCustomThreats, threatLabel } from "../lib/stride";
import { StatePill, SystemDialog, systemInput } from "./Systems";
import { t } from "../i18n";

export default function SystemDetail() {
  const { id } = useParams();
  const sid = Number(id);
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const navigate = useNavigate();
  const sys = useLoad<Detail>(() => api.system(sid), [sid]);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // detection requests still to do are shown first; the others can be switched on (PROJ-1)
  const [shown, setShown] = useState<Set<RequestStatus>>(new Set(["open", "in_progress"]));
  const s = sys.data;

  async function run(fn: () => Promise<unknown>) {
    setError(null);
    try {
      await fn();
      await sys.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function startInterview() {
    if (!s) return;
    if (s.draft_id) {
      navigate(`/interviews/${s.draft_id}`);
      return;
    }
    setError(null);
    try {
      const iv = await api.startInterview(s.id);
      navigate(`/interviews/${iv.id}`);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function archive(on: boolean) {
    if (!s) return;
    const ok = await confirmDialog(
      on
        ? t("Archive {name}? It is hidden from the list, not counted as due and has no effect on priorities.", { name: s.name })
        : t("Reactivate {name}?", { name: s.name }),
    );
    if (ok) await run(() => api.updateSystem(s.id, { ...systemInput(s), archived: on }));
  }

  async function remove() {
    if (!s) return;
    const ok = await confirmDialog(t("Delete {name}? This cannot be undone.", { name: s.name }), {
      danger: true,
      confirmLabel: t("Delete"),
    });
    if (!ok) return;
    try {
      await api.deleteSystem(s.id);
      navigate("/systems");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (!s) {
    return (
      <>
        <ErrorNote error={sys.error} />
        {!sys.error && <p className="muted">{t("Loading…")}</p>}
      </>
    );
  }

  const facts: [string, string][] = [
    [t("Business owner"), s.owner_name],
    [t("Owner department"), s.owner_department || "–"],
    [t("Owner e-mail"), s.owner_email || "–"],
    [t("Criticality"), `${s.criticality}/5`],
    [t("Internet-facing"), s.internet_facing ? t("Yes") : t("No")],
    [t("Data classification"), CLASSIFICATION_LABEL[s.data_classification as keyof typeof CLASSIFICATION_LABEL] ?? s.data_classification],
    [t("Review interval"), t("{n} months", { n: s.review_interval_months })],
    [t("Next interview due"), s.next_due ? fmtDate(s.next_due) : t("now")],
  ];
  const blind = s.gap_log_sources.filter((g) => g.blind);
  const partial = s.gap_log_sources.filter((g) => !g.blind);
  registerCustomThreats(s.components.flatMap((c) => c.custom_threats ?? []));
  const uncovered = s.gap_risks ?? [];
  // #59: the same gaps as the "Gap" filter of the risk overview (risks without use case) plus
  // the gaps of linked use cases and open detection requests
  const todoRequests = s.gap_requests.filter((g) => isTodo(g.status));
  const lastDone = [...s.interviews].filter((i) => i.status !== "draft").sort((x, y) => y.id - x.id)[0];
  const gapCount = uncovered.length + s.gap_no_rules.length + blind.length + todoRequests.length;

  return (
    <>
      <nav className="crumbs" aria-label={t("Breadcrumb")}>
        <Link to="/systems">{t("Threat modelling")}</Link> / <span>{s.name}</span>
      </nav>
      <header className="page-header">
        <div>
          <h1>
            {s.name} {s.archived && <span className="chip chip-neutral">{t("Archived")}</span>}
          </h1>
          <div className="subtitle">
            <StatePill state={s.state} draft={!!s.draft_id} />{" "}
            {s.last_interview && t("Last interview {date}", { date: fmtDate(s.last_interview) })}
          </div>
        </div>
        {editor && (
          <div className="row-actions">
            {!s.archived && (
              <button type="button" className="btn btn-primary" onClick={() => void startInterview()}>
                {s.draft_id ? t("Continue draft") : t("Start interview")}
              </button>
            )}
            <button type="button" className="btn" onClick={() => setEditing(true)}>
              {t("Edit")}
            </button>
            <button type="button" className="btn" onClick={() => void archive(!s.archived)}>
              {s.archived ? t("Reactivate") : t("Archive")}
            </button>
            {s.can_delete && (
              <button type="button" className="btn btn-danger" onClick={() => void remove()}>
                {t("Delete")}
              </button>
            )}
          </div>
        )}
      </header>
      <ErrorNote error={error ?? sys.error} />
      {s.archived && s.draft_id && (
        <p className="form-notice">
          {t("This system is archived but has a draft interview.")}{" "}
          <Link to={`/interviews/${s.draft_id}`}>{t("Open draft")}</Link>
        </p>
      )}

      <section className="card stack-sm" aria-labelledby="stath">
        <h2 id="stath" className="sr-only">
          {t("Status")}
        </h2>
        <dl className="stat-grid">
          <div>
            <dt>{t("Detection coverage")}</dt>
            <dd>{s.last_interview ? pct(s.coverage) : "–"}</dd>
          </div>
          <div>
            <dt>{t("Linked use cases")}</dt>
            <dd>{s.links.length}</dd>
          </div>
          <div>
            <dt>{t("Gaps")}</dt>
            <dd>{s.last_interview ? <a href="#gaph">{gapCount}</a> : "–"}</dd>
          </div>
          <div>
            <dt>{t("Open requests")}</dt>
            <dd>{todoRequests.length ? <a href="#sys-requests">{todoRequests.length}</a> : 0}</dd>
          </div>
          <div>
            <dt>{t("Owner confirmation")}</dt>
            <dd className="stat-text">
              {lastDone ? (
                <Link to={`/interviews/${lastDone.id}`}>{INTERVIEW_STATUS_LABEL[lastDone.status]}</Link>
              ) : (
                <span className="muted">{t("No interview yet.")}</span>
              )}
            </dd>
          </div>
        </dl>
        <p className="muted small" style={{ margin: 0 }}>
          {t("Coverage = average weight of the linked L2 use cases and L3 rules; use cases without scored rules count as 0.")}
        </p>
      </section>

      <section className="card stack-sm" aria-labelledby="gaph">
        <h2 id="gaph" className="h-sm">
          {t("Gaps")}{" "}
          {gapCount > 0 && (
            <span className="muted small">
              {t("{r} risks without use case · {a} without rules · {b} blind · {c} requests", {
                r: uncovered.length,
                a: s.gap_no_rules.length,
                b: blind.length,
                c: todoRequests.length,
              })}
            </span>
          )}
        </h2>
        {!gapCount && (
          <p className="muted" style={{ margin: 0 }}>
            {s.last_interview
              ? t("No gaps.")
              : s.draft_id
                ? t("Not assessed yet: the first interview is still a draft.")
                : t("Not assessed yet: there is no completed interview.")}
          </p>
        )}
        {uncovered.length > 0 && (
          <div>
            <h3 className="small strong">{t("Risks that no use case addresses")}</h3>
            <ul className="plain-list">
              {uncovered.map((g) => (
                <li key={`${g.component}:${g.category}`}>
                  <span className={`risk risk-${g.level ?? 0}`} title={t("Risk level {r}", { r: g.level ?? "–" })}>
                    {g.score ?? "–"}
                  </span>{" "}
                  {g.component_name} / {threatLabel(g.category)}
                </li>
              ))}
            </ul>
          </div>
        )}
        {s.gap_no_rules.length > 0 && (
          <div>
            <h3 className="small strong">{t("Linked use cases without rules")}</h3>
            <ul className="plain-list">
              {s.gap_no_rules.map((g) => (
                <li key={g.code}>
                  <span className="badge-gap">{t("No rules")}</span>{" "}
                  <Link to={useCaseHref({ level: levelOf(g.code), code: g.code })}>
                    <span className="mono small">{g.code}</span> {g.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}
        {blind.length > 0 && (
          <div>
            <h3 className="small strong">{t("Linked use cases whose rules get none of their log sources")}</h3>
            <GapGroups groups={blind} />
          </div>
        )}
        {partial.length > 0 && (
          <details>
            <summary className="small strong">{t("Rules that get only some of their log sources ({n} use cases)", { n: partial.length })}</summary>
            <GapGroups groups={partial} />
          </details>
        )}
        {s.gap_requests.length > 0 && (
          <div id="sys-requests">
            <div className="section-head">
              <h3 className="small strong">{t("Detection requests")}</h3>
              <Link className="small" to={`/usecases/requests?system=${sid}`}>
                {t("Show all requests")}
              </Link>
            </div>
            <div className="req-filter" role="group" aria-label={t("Show requests with status")}>
              {REQUEST_STATUSES.map((st) => (
                <label key={st}>
                  <input
                    type="checkbox"
                    checked={shown.has(st)}
                    onChange={() =>
                      setShown((x) => {
                        const next = new Set(x);
                        if (!next.delete(st)) next.add(st);
                        return next;
                      })
                    }
                  />
                  {statusLabel(st)} ({s.gap_requests.filter((g) => g.status === st).length})
                </label>
              ))}
            </div>
            {s.gap_requests.some((g) => shown.has(g.status)) ? (
              <div className="req-list">
                {s.gap_requests
                  .filter((g) => shown.has(g.status))
                  .map((g) => (
                    <RequestCard
                      key={g.key}
                      systemId={sid}
                      r={g}
                      where={`${g.component} / ${threatLabel(g.category)}`}
                      canSetStatus={editor && !s.archived}
                      onChanged={() => void sys.reload()}
                    />
                  ))}
              </div>
            ) : (
              <p className="muted small" style={{ margin: "8px 0 0" }}>
                {t("No detection requests with the chosen status.")}
              </p>
            )}
          </div>
        )}
      </section>

      <section className="card table-card" aria-labelledby="ivh">
        <h2 id="ivh" className="table-title">
          {t("Interviews")}
        </h2>
        {s.interviews.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>{t("Date")}</th>
                <th>{t("Analyst")}</th>
                <th>{t("Status")}</th>
                <th>{t("Confirmed by / on")}</th>
              </tr>
            </thead>
            <tbody>
              {s.interviews.map((i) => (
                <tr key={i.id}>
                  <td>
                    <Link to={`/interviews/${i.id}`}>{fmtDate(i.interview_date)}</Link>
                    {i.completed_at && <span className="muted small"> · {t("completed {time}", { time: fmtTime(i.completed_at) })}</span>}
                    {i.previous_id && (
                      <div className="small muted">
                        {t("Re-interview of {date}", {
                          date: fmtDate(s.interviews.find((x) => x.id === i.previous_id)?.interview_date ?? null),
                        })}
                      </div>
                    )}
                  </td>
                  <td>{i.analyst}</td>
                  <td>
                    <span className={`pill iv-${i.status}`}>{INTERVIEW_STATUS_LABEL[i.status]}</span>
                  </td>
                  <td>{i.confirmed_by ? `${i.confirmed_by} · ${fmtDate(i.confirmed_at)}` : <span className="muted">–</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted empty-flat">{t("No interview yet.")}</p>
        )}
      </section>

      {s.last_interview && (
        <details className="fold">
          <summary>
            {t("Risks and use cases")} <span className="muted small">({t("{n} risks", { n: s.risks.length })})</span>
          </summary>
        <RiskCoverage
          risks={s.risks}
          components={s.components}
          showWeight
          title={t("Risks and use cases")}
          actions={
            <span className="small muted">
              {t("From the interview of {date}; use case state as of now.", { date: fmtDate(s.last_interview) })}
            </span>
          }
        />
        </details>
      )}

      <details className="fold">
        <summary>
          {t("System and linked use cases")} <span className="muted small">({t("{n} use cases", { n: s.links.length })})</span>
        </summary>
      <div className="split">
        <section className="card split-side stack-sm" aria-labelledby="ownh">
          <h2 id="ownh" className="h-sm">
            {t("System and owner")}
          </h2>
          {s.description && <p className="ink-2" style={{ margin: 0 }}>{s.description}</p>}
          <dl className="facts">
            {facts.map(([k, v]) => (
              <div key={k} style={{ display: "contents" }}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="card split-main" aria-labelledby="covh">
          <div className="section-head">
            <h2 id="covh">{t("Linked use cases")}</h2>
            {s.links.length > 0 && (
              <Link className="btn btn-sm" to={`/usecases?sys=${s.id}&view=table`}>
                {t("Show on Use cases")}
              </Link>
            )}
          </div>
          <p className="muted small" style={{ margin: 0 }}>
            {t("Coverage = average weight of the linked L2 use cases and L3 rules; use cases without scored rules count as 0.")}
          </p>
          {s.links.length ? (
            <div className="scroll-x">
              <table className="table table-plain">
                <thead>
                  <tr>
                    <th>{t("Use case")}</th>
                    <th>{t("From threats")}</th>
                    <th className="num">{t("Risk score")}</th>
                    <th className="num">{t("Weight")}</th>
                  </tr>
                </thead>
                <tbody>
                  {s.links.map((l) => (
                    <tr key={`${l.level}-${l.l3_id ?? l.l2_id}`}>
                      <td>
                        <div className="code-link-row">
                          <span className={`lvl lvl-${l.level}`}>{l.level}</span>
                          <Link className="code-link" to={useCaseHref(l)}>
                            <span className="code-tag">{l.code}</span>
                            <span>{l.name}</span>
                          </Link>
                        </div>
                      </td>
                      <td className="small">
                        {l.sources.map((x) => `${x.component}: ${threatLabel(x.category)}`).join("; ")}
                      </td>
                      <td className="num">
                        <span className={`risk risk-${l.risk_level ?? 0}`} title={t("Risk level {r}", { r: l.risk_level ?? "–" })}>
                          {l.risk_score || "–"}
                        </span>
                      </td>
                      <td className="num">{num(l.weight)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="note-box">
              {t("No use cases are linked yet. They are linked when an interview is completed.")}{" "}
              {editor && !s.archived && (
                <button type="button" className="link-btn" onClick={() => void startInterview()}>
                  {s.draft_id ? t("Continue draft") : t("Start interview")}
                </button>
              )}
            </div>
          )}
        </section>
      </div>

      </details>

      {editing && (
        <SystemDialog
          id={s.id}
          initial={systemInput(s)}
          onClose={() => setEditing(false)}
          onSaved={() => {
            setEditing(false);
            void sys.reload();
          }}
        />
      )}
    </>
  );
}

/** Log source gaps grouped by L2 use case (#41). */
function GapGroups({ groups }: { groups: Detail["gap_log_sources"] }) {
  return (
    <ul className="plain-list gap-groups">
      {groups.map((g) => (
        <li key={g.l2_code}>
          <Link to={useCaseHref({ level: levelOf(g.l2_code), code: g.l2_code })}>
            <span className="mono small">{g.l2_code}</span> {g.l2_name}
          </Link>{" "}
          <span className="muted small">· {g.components.join(", ")}</span>
          <ul className="plain-list small gap-rules">
            {g.rules.map((r) => (
              <li key={r.rule_code}>
                <Link to={`/usecases/l3/${encodeURIComponent(r.rule_code)}`}>
                  <span className="mono">{r.rule_code}</span> {r.rule_name}
                </Link>{" "}
                <span className="muted">· {t("missing: {list}", { list: r.missing.join(", ") })}</span>
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}

/** L3 codes are XX-YYY-NN (more parts may follow), L2 codes XX-YYY. */
function levelOf(code: string): "L2" | "L3" {
  return code.split("-").length > 2 ? "L3" : "L2";
}
