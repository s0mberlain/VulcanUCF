import { useState } from "react";
import { api, type TestCaseOut, type TestOutcome } from "../api";
import { useAuth } from "../auth";
import { ErrorNote, useLoad } from "../components/ui";
import { QuickTestDialog, TestCard, TestDialog } from "../components/TestParts";
import { OUTCOMES, OUTCOME_LABEL } from "../lib/tests";
import { t } from "../i18n";

export default function QuickTests() {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const [outcome, setOutcome] = useState<TestOutcome | "">("");
  const [technique, setTechnique] = useState("");
  const [gapsOnly, setGapsOnly] = useState(false);
  const list = useLoad<TestCaseOut[]>(
    () => api.quickTests({ outcome: outcome || undefined, technique: technique.trim() || undefined, open_gaps: gapsOnly }),
    [outcome, technique, gapsOnly],
  );
  const [creating, setCreating] = useState(false);
  const [dialog, setDialog] = useState<{ kind: "def"; test: TestCaseOut } | null>(null);
  const reload = () => {
    void list.reload();
  };
  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Quick tests")}</h1>
          <div className="subtitle">{t("Single tests without a campaign. Execution and result are recorded at once.")}</div>
        </div>
        {editor && (
          <div className="row-actions">
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              {t("+ New quick test")}
            </button>
          </div>
        )}
      </header>
      <ErrorNote error={list.error} />

      <section className="card stack-sm" aria-label={t("Quick tests")}>
        <div className="uc-filters" style={{ border: 0, padding: 0 }}>
          <div className="filter-row" role="group" aria-label={t("Result")}>
            <button type="button" className={"filter-chip" + (outcome === "" ? " active" : "")} aria-pressed={outcome === ""} onClick={() => setOutcome("")}>
              {t("All results")}
            </button>
            {OUTCOMES.map((o) => (
              <button key={o} type="button" className={"filter-chip" + (outcome === o ? " active" : "")} aria-pressed={outcome === o} onClick={() => setOutcome(o)}>
                {OUTCOME_LABEL[o]}
              </button>
            ))}
            <button type="button" className={"filter-chip" + (gapsOnly ? " active" : "")} aria-pressed={gapsOnly} onClick={() => setGapsOnly((x) => !x)}>
              {t("Open gaps")}
            </button>
          </div>
          <label className="sr-only" htmlFor="qt-tech">{t("ATT&CK technique")}</label>
          <input id="qt-tech" className="input input-sm" placeholder={t("Technique, e.g. T1059")} value={technique} onChange={(e) => setTechnique(e.target.value.toUpperCase())} />
        </div>
        {list.data && !list.data.length && (
          <div className="empty-flat">
            <p className="muted">{outcome || technique || gapsOnly ? t("No quick test matches the filters.") : t("No quick tests yet. Start one from a rule page or here.")}</p>
          </div>
        )}
        <div className="test-list">
          {list.data?.map((x) => (
            <TestCard
              key={x.id}
              test={x}
              onChanged={reload}
              onEdit={() => setDialog({ kind: "def", test: x })}
            />
          ))}
        </div>
      </section>
      {creating && <QuickTestDialog onClose={() => setCreating(false)} onSaved={reload} />}
      {dialog?.kind === "def" && <TestDialog test={dialog.test} campaignId={0} onClose={() => setDialog(null)} onSaved={reload} />}
    </>
  );
}
