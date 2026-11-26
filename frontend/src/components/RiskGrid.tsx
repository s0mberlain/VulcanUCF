import { useRef } from "react";
import { riskLevel } from "../lib/stride";
import { t } from "../i18n";

/** The scales said in words, so "4" means the same to everyone in the room. */
export const LIKELIHOOD_LABEL = [t("rare"), t("unlikely"), t("possible"), t("likely"), t("almost certain")];
export const IMPACT_LABEL = [t("minor"), t("limited"), t("moderate"), t("major"), t("severe")];

/**
 * Likelihood × impact as one 5 × 5 grid: a click sets both. Rows are likelihood (5 at the top),
 * columns impact; each square shows its risk score and the colour of its risk level. One square
 * is in the tab order (roving tab index); the arrow keys move and Enter or Space chooses.
 */
export function RiskGrid({
  likelihood,
  impact,
  onChange,
  disabled,
  invalid,
  id,
}: {
  likelihood: number | null;
  impact: number | null;
  onChange: (likelihood: number, impact: number) => void;
  disabled?: boolean;
  /** a check failed and the rating is still missing */
  invalid?: boolean;
  id?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const tabL = likelihood ?? 3;
  const tabI = impact ?? 3;

  function move(e: React.KeyboardEvent, l: number, i: number) {
    const d: Record<string, [number, number]> = { ArrowUp: [1, 0], ArrowDown: [-1, 0], ArrowLeft: [0, -1], ArrowRight: [0, 1] };
    const step = d[e.key];
    if (!step) return;
    e.preventDefault();
    const nl = Math.min(5, Math.max(1, l + step[0]));
    const ni = Math.min(5, Math.max(1, i + step[1]));
    box.current?.querySelector<HTMLButtonElement>(`[data-l="${nl}"][data-i="${ni}"]`)?.focus();
  }

  const rows = [5, 4, 3, 2, 1];
  const cols = [1, 2, 3, 4, 5];
  return (
    <div className="rgrid-wrap">
      <div
        ref={box}
        id={id}
        className={"rgrid" + (invalid ? " is-invalid" : "")}
        role="group"
        aria-label={t("Risk: choose likelihood (row) and impact (column)")}
        tabIndex={invalid ? -1 : undefined}
      >
        {rows.map((l) => (
          <div key={l} className="rgrid-row">
            <span className="rgrid-ax">
              {l} {LIKELIHOOD_LABEL[l - 1]}
            </span>
            {cols.map((i) => {
              const sel = likelihood === l && impact === i;
              const s = l * i;
              return (
                <button
                  key={i}
                  type="button"
                  data-l={l}
                  data-i={i}
                  className={`rgrid-cell lv-${riskLevel(s)}` + (sel ? " is-selected" : "")}
                  aria-pressed={sel}
                  aria-label={t("Likelihood {l} ({lt}), impact {i} ({it}): score {s}", {
                    l,
                    lt: LIKELIHOOD_LABEL[l - 1]!,
                    i,
                    it: IMPACT_LABEL[i - 1]!,
                    s,
                  })}
                  tabIndex={l === tabL && i === tabI ? 0 : -1}
                  disabled={disabled}
                  onClick={() => onChange(l, i)}
                  onKeyDown={(e) => move(e, l, i)}
                >
                  {s}
                </button>
              );
            })}
          </div>
        ))}
        <div className="rgrid-row rgrid-foot" aria-hidden="true">
          <span className="rgrid-ax" />
          {cols.map((i) => (
            <span key={i} className="rgrid-axb">
              {i}
              <br />
              {IMPACT_LABEL[i - 1]}
            </span>
          ))}
        </div>
      </div>
      <div className="rgrid-cap small muted">
        <span>{t("↑ Likelihood · Impact →")}</span>
        <span aria-live="polite">
          {likelihood && impact ? (
            <>
              {t("{l} × {i} = score {s}", { l: LIKELIHOOD_LABEL[likelihood - 1]!, i: IMPACT_LABEL[impact - 1]!, s: likelihood * impact })}
            </>
          ) : (
            t("Not rated yet: click a square.")
          )}
        </span>
      </div>
    </div>
  );
}
