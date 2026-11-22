import type { CampaignStatus, RoundState, RuleTestState, TestOutcome, TestStatus } from "../api";
import { t } from "../i18n";

export const OUTCOMES: TestOutcome[] = ["blocked", "alerted", "logged", "not_detected"];

/** Result of a test: the four values keep their English names in every language. */
export const OUTCOME_LABEL: Record<TestOutcome, string> = {
  blocked: t("Blocked"),
  alerted: t("Alerted"),
  logged: t("Logged"),
  not_detected: t("Not detected"),
};

export const OUTCOME_HINT: Record<TestOutcome, string> = {
  blocked: t("The attack was prevented. Verifies the rule."),
  alerted: t("An alert fired. Verifies the rule."),
  logged: t("Traces are in the log, but no alert. A gap: problems found."),
  not_detected: t("Neither alert nor trace. A gap: problems found."),
};

export const OUTCOME_PILL: Record<TestOutcome, string> = {
  blocked: "pill-good",
  alerted: "pill-good",
  logged: "pill-fair",
  not_detected: "pill-poor",
};

export const EXEC_LABEL: Record<TestStatus, string> = {
  not_run: t("Not run"),
  executed: t("Executed"),
  not_executable: t("Not executable"),
};

export const CAMPAIGN_LABEL: Record<CampaignStatus, string> = {
  planned: t("Planned"),
  running: t("Running"),
  closed: t("Closed"),
};

export const CAMPAIGN_PILL: Record<CampaignStatus, string> = {
  planned: "pill-none",
  running: "pill-ok",
  closed: "pill-good",
};

export const RULE_STATE_LABEL: Record<RuleTestState, string> = {
  verified: t("Verified"),
  partial: t("Partly verified"),
  issues: t("Problems found"),
  due: t("Due"),
  none: t("Not tested"),
};

export const RULE_STATE_PILL: Record<RuleTestState, string> = {
  verified: "pill-good",
  partial: "pill-fair",
  issues: "pill-poor",
  due: "pill-fair",
  none: "pill-none",
};

export const SCOPE_STATUS_LABEL = {
  covered: t("covered"),
  expired: t("expired"),
  problem: t("problem"),
  open: t("not tested"),
} as const;

/** Value of a datetime-local input for an ISO time (local time). */
export function toInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** ISO time (UTC) for a datetime-local input value; null when empty. */
export function fromInput(v: string): string | null {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export function fmtTtd(seconds: number | null): string {
  if (seconds === null) return "–";
  const m = Math.round(seconds / 60);
  if (m < 60) return t("{n} min", { n: m });
  const h = Math.floor(m / 60);
  return m % 60 ? t("{h} h {m} min", { h, m: m % 60 }) : t("{h} h", { h });
}

export const TECHNIQUE_PATTERN = "T\\d{4}(\\.\\d{3})?";

/** State of a test or of one round: open = not run, waiting = the blue team has no result yet. */
export const ROUND_LABEL: Record<RoundState, string> = {
  open: t("Open"),
  waiting: t("Waiting for blue team"),
  done: t("Done"),
};

export const ROUND_PILL: Record<RoundState, string> = {
  open: "pill-none",
  waiting: "pill-fair",
  done: "pill-ok",
};
