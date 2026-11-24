import type { DueRule } from "../api";

/** Never verified or past its due date: one definition for the sidebar badge and the page. */
export const isOverdue = (d: Pick<DueRule, "due" | "overdue">): boolean => !d.due || d.overdue;

export type DueFilter = "all" | "overdue" | "failed" | "soon";

export function matchesDue(d: DueRule, f: DueFilter): boolean {
  if (f === "overdue") return isOverdue(d);
  if (f === "failed") return !!d.issues_at;
  if (f === "soon") return !isOverdue(d) && !d.issues_at;
  return true;
}

/** Most urgent first: failed check, never verified, then by days left. */
export function urgency(d: DueRule): number {
  if (d.issues_at) return -2e6;
  if (!d.due) return -1e6;
  return d.days_left ?? 0;
}
