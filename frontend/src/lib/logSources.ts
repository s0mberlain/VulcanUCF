import { api, type LogSourceState, type LogSourceStatus, type LogSourceCheck } from "../api";
import { fmtDate } from "./format";
import { t } from "../i18n";

/** Log source verification (issue #75): labels and the warning shown on rules. */
export const CHECK_LABEL: Record<LogSourceCheck, string> = {
  intake: t("Log intake"),
  configuration: t("Configuration"),
  filtering: t("Filtering"),
  responsibilities: t("Responsibilities"),
};
export const CHECK_HINT: Record<LogSourceCheck, string> = {
  intake: t("Events arrive in the SIEM, complete and on time"),
  configuration: t("Source and collector are configured as documented"),
  filtering: t("Filters and parsers drop nothing the rules need"),
  responsibilities: t("Owner and contacts are known and up to date"),
};
export const STATE_LABEL: Record<LogSourceState, string> = {
  never: t("Never verified"),
  ok: t("Verified"),
  due: t("Due soon"),
  overdue: t("Overdue"),
  issues: t("Issues found"),
};
export const STATE_CLASS: Record<LogSourceState, string> = {
  never: "pill pill-muted",
  ok: "pill pill-ok",
  due: "pill pill-warn",
  overdue: "pill pill-bad",
  issues: "pill pill-bad",
};

/** Text for a log source whose check is overdue or found issues; null when nothing to flag. */
export function logSourceWarning(s: LogSourceStatus | undefined): string | null {
  if (!s) return null;
  if (s.status === "issues") return t("Log source check on {date} found issues", { date: fmtDate(s.issues_at) });
  if (s.status === "overdue") return t("Log source check overdue since {date}", { date: fmtDate(s.due) });
  return null;
}

export function loadLogSourceMap(): Promise<Map<string, LogSourceStatus>> {
  return api.logSourceStatuses().then((rows) => new Map(rows.map((r) => [r.name, r])));
}
