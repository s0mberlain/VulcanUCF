import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type TestGap } from "../api";
import { useAuth } from "../auth";
import { ErrorNote, useLoad } from "../components/ui";
import { AcceptGapDialog, Technique } from "../components/TestParts";
import { fmtTime } from "../lib/format";
import { OUTCOME_LABEL, OUTCOME_PILL } from "../lib/tests";
import { t } from "../i18n";

const QUICK = "quick";

/** Detection gaps found by tests (logged or not detected), grouped by rule. */
export default function Gaps() {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const [accepted, setAccepted] = useState(false);
  const [campaign, setCampaign] = useState("");
  const [accepting, setAccepting] = useState<TestGap | null>(null);
  const gaps = useLoad<TestGap[]>(() => api.testGaps(accepted), [accepted]);

  const campaigns = useMemo(() => {
    const m = new Map<string, string>();
    for (const g of gaps.data ?? []) m.set(g.campaign_id ? String(g.campaign_id) : QUICK, g.campaign_name ?? t("Quick tests"));
    return [...m.entries()];
  }, [gaps.data]);
  const groups = useMemo(() => {
    const m = new Map<string, TestGap[]>();
    for (const g of gaps.data ?? []) {
      if (campaign && (g.campaign_id ? String(g.campaign_id) : QUICK) !== campaign) continue;
      const key = g.l3_code ?? `t:${g.technique}`;
      m.set(key, [...(m.get(key) ?? []), g]);
    }
    return [...m.values()];
  }, [gaps.data, campaign]);

  return (
    <>
      <nav className="crumbs" aria-label={t("Breadcrumb")}>
        <Link to="/verification">{t("Verification")}</Link> / <span>{t("Detection gaps")}</span>
      </nav>
      <header className="page-header">
        <div>
          <h1>{t("Detection gaps")}</h1>
          <div className="subtitle">{t("Rules where a test logged the attack or missed it. A later successful test closes the gap.")}</div>
        </div>
      </header>
      <ErrorNote error={gaps.error} />
      <div className="filter-bar">
        <div className="filter-row" role="group" aria-label={t("Show")}>
          <button type="button" className={"filter-chip tap" + (!accepted ? " active" : "")} aria-pressed={!accepted} onClick={() => setAccepted(false)}>
            {t("Open")}
          </button>
          <button type="button" className={"filter-chip tap" + (accepted ? " active" : "")} aria-pressed={accepted} onClick={() => setAccepted(true)}>
            {t("Including accepted")}
          </button>
        </div>
        {campaigns.length > 1 && (
          <label className="field-inline">
            <span className="sr-only">{t("Campaign")}</span>
            <select className="input tap" value={campaign} onChange={(e) => setCampaign(e.target.value)}>
              <option value="">{t("All campaigns")}</option>
              {campaigns.map(([id, name]) => (
                <option key={id} value={id}>{name}</option>
              ))}
            </select>
          </label>
        )}
      </div>
      {gaps.data && !groups.length && (
        <div className="card">
          <p className="muted">{t("No open gaps. Tests that log or miss an attack show up here.")}</p>
        </div>
      )}
      <div className="test-list">
        {groups.map((list) => {
          const head = list[0];
          return (
            <article key={head.l3_code ?? head.technique} className="test-card">
              <div className="test-head">
                {head.l3_code ? (
                  <Link to={`/usecases/l3/${head.l3_code}`} className="rule-link">
                    <span className="mono small muted">{head.l3_code}</span>
                    <span className="strong-500">{head.rule_name}</span>
                  </Link>
                ) : (
                  <span className="strong-500">{t("No rule covers technique {id}", { id: head.technique })}</span>
                )}
                <Technique id={head.technique} name={head.technique_name} />
              </div>
              <ul className="plain-list gap-test-list">
                {list.map((g) => (
                  <li key={`${g.test_id}-${g.scope}`}>
                    <span className={`pill ${OUTCOME_PILL[g.outcome]}`}>{OUTCOME_LABEL[g.outcome]}</span>
                    {g.scope && <span className="chip chip-neutral">{g.scope}</span>}
                    <span className="small muted">
                      <Link to={`/verification/tests/${g.test_id}`}>{g.test_title}</Link>
                      {g.campaign_name ? ` · ${g.campaign_name}` : ""} · {fmtTime(g.executed_at)}
                    </span>
                    {g.accepted ? (
                      <span className="small muted">{t("accepted by {user}: {reason}", { user: g.accepted_by ?? "", reason: g.accepted_reason ?? "" })}</span>
                    ) : (
                      editor && (
                        <button type="button" className="btn btn-sm tap" onClick={() => setAccepting(g)}>
                          {t("Accept")}
                        </button>
                      )
                    )}
                  </li>
                ))}
              </ul>
            </article>
          );
        })}
      </div>
      {accepting && <AcceptGapDialog gap={accepting} onClose={() => setAccepting(null)} onSaved={() => void gaps.reload()} />}
    </>
  );
}
