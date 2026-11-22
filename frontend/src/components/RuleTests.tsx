import { useState } from "react";
import { Link } from "react-router-dom";
import { api, type L2TestSummary, type RuleTests } from "../api";
import { useAuth } from "../auth";
import { ErrorNote, useLoad } from "./ui";
import { GapList, OutcomePill, QuickTestDialog, RuleStatePill, Technique } from "./TestParts";
import { fmtDate } from "../lib/format";
import { RULE_STATE_LABEL, SCOPE_STATUS_LABEL } from "../lib/tests";
import { t } from "../i18n";

/** The tests of one rule: how far they cover its scopes, open gaps, the list of tests. */
export function RuleTestsSection({ code, onChanged }: { code: string; onChanged?: () => void }) {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const data = useLoad<RuleTests>(() => api.ruleTests(code), [code]);
  const [quick, setQuick] = useState(false);
  const d = data.data;
  const reload = () => {
    void data.reload();
    onChanged?.();
  };
  return (
    <section className="card stack-sm" aria-labelledby="rth">
      <div className="section-head">
        <h2 id="rth" className="h-sm">
          {t("Tests")}
        </h2>
        {editor && (
          <button type="button" className="btn btn-sm" onClick={() => setQuick(true)}>
            {t("Quick test")}
          </button>
        )}
      </div>
      <ErrorNote error={data.error} />
      {d && (
        <>
          <p className="small" style={{ margin: 0 }}>
            <RuleStatePill state={d.state} />{" "}
            {d.total > 0 && d.state !== "none" && (
              <span className="muted">
                {t("{a} of {b} scopes covered", { a: d.covered, b: d.total })} · {t("valid for {n} days", { n: d.interval_days })}
              </span>
            )}
          </p>
          {d.scopes.length > 0 && d.scopes.some((s) => s.status !== "open") && (
            <ul className="plain-list scope-states">
              {d.scopes.map((s) => (
                <li key={s.scope || "all"}>
                  <span className={`cov-dot ${s.status === "covered" ? "cov-covered" : s.status === "problem" ? "cov-gap" : s.status === "expired" ? "cov-partial" : "cov-below"}`} aria-hidden="true" />
                  <strong>{s.scope || t("Whole rule")}</strong> · {SCOPE_STATUS_LABEL[s.status]}
                  {s.test_id && (
                    <span className="muted small">
                      {" "}
                      · <Link to={`/verification/tests/${s.test_id}`}>{s.test_title}</Link> {s.date && fmtDate(s.date)}
                      {s.until && s.status !== "problem" && ` → ${fmtDate(s.until)}`}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
          {d.gaps.length > 0 && (
            <div>
              <h3 className="small strong">{t("Open gaps")}</h3>
              <GapList gaps={d.gaps.filter((g) => !g.accepted)} editor={editor} onChanged={reload} />
            </div>
          )}
          {!d.tests.length ? (
            <p className="muted small" style={{ margin: 0 }}>
              {t("No test has covered this rule yet.")}
            </p>
          ) : (
            <ul className="plain-list rule-tests">
              {d.tests.map((x) => (
                <li key={x.id}>
                  <span className="muted small">{x.executed_at ? fmtDate(x.executed_at) : "–"}</span> <OutcomePill outcome={x.outcome} />{" "}
                  <Link to={`/verification/tests/${x.id}`}>{x.title}</Link> <Technique id={x.technique} />
                  <span className="muted small"> · {x.campaign_name ?? t("Quick test")}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {quick && <QuickTestDialog ruleCode={code} onClose={() => setQuick(false)} onSaved={reload} />}
    </section>
  );
}

/** The summary of the tests of an L2 use case's rules. */
export function L2TestSummaryLine({ code }: { code: string }) {
  const s = useLoad<L2TestSummary>(() => api.l2TestSummary(code), [code]);
  const d = s.data;
  if (!d) return null;
  const states = (["verified", "partial", "issues", "due"] as const).filter((k) => d.states[k] > 0);
  return (
    <div className="driver-block">
      <span className="small muted">{t("Tests")}:</span>{" "}
      {d.tests === 0 ? (
        <span className="small muted">{t("none yet")}</span>
      ) : (
        <span className="chips" style={{ display: "inline-flex" }}>
          <span className="chip chip-neutral">{t("{n} tests", { n: d.tests })}</span>
          {d.last_test && <span className="chip chip-neutral">{t("last {date}", { date: fmtDate(d.last_test) })}</span>}
          {states.map((k) => (
            <span key={k} className="chip chip-neutral">
              {RULE_STATE_LABEL[k]} {d.states[k]}
            </span>
          ))}
          {d.open_gaps > 0 && (
            <Link to="/verification/gaps" className="chip chip-info chip-link">
              {t("{n} open gaps", { n: d.open_gaps })}
            </Link>
          )}
        </span>
      )}
    </div>
  );
}
