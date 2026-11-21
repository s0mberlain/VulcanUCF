import { locale, t } from "../i18n";
import type { Lifecycle, RefKind } from "../api";

/** 0..1 → "62 %"; null → "–". */
export function pct(v: number | null | undefined, digits = 0): string {
  return v === null || v === undefined ? "–" : `${(v * 100).toFixed(digits)} %`;
}

/** 0..1 → "0.62"; null → "–". */
export function num(v: number | null | undefined, digits = 2): string {
  return v === null || v === undefined ? "–" : v.toFixed(digits);
}

const DATE_FMT = new Intl.DateTimeFormat(locale(), { year: "numeric", month: "short", day: "numeric" });

/** The server stores UTC; SQLite hands datetimes back without a zone mark, so a bare time counts as UTC. */
export function asUtc(iso: string): string {
  return iso.includes("T") && !/(Z|[+-]\d\d:?\d\d)$/i.test(iso) ? iso + "Z" : iso;
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "–";
  const d = new Date(iso.length === 10 ? iso + "T00:00:00" : asUtc(iso));
  return Number.isNaN(d.getTime()) ? iso : DATE_FMT.format(d);
}

/** Date and time, e.g. "14 Nov 2026 09:05"; null → "never". */
export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return t("never");
  const d = new Date(asUtc(iso));
  return `${fmtDate(iso)} ${d.toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" })}`;
}

export function today(): string {
  const d = new Date();
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
}

export function daysSince(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const ms = Date.now() - new Date(iso + "T00:00:00").getTime();
  return Math.floor(ms / 86400000);
}

export const STATUS_LABEL: Record<Lifecycle, string> = {
  onboarding: t("Onboarding"),
  operational: t("Operational"),
  maintenance: t("Maintenance"),
  offloading: t("Offloading"),
  retired: t("Retired"),
};

export const REF_KINDS = [
  { kind: "threat_actor", label: t("Threat actors"), hint: t("Who the L2 use cases defend against.") },
  {
    kind: "detection_technology",
    label: t("Detection technologies"),
    hint: t("Tools that raise the alerts of an L3 rule."),
  },
  { kind: "log_source", label: t("Log sources"), hint: t("Data sources a rule reads. A rule can use several.") },
  { kind: "scope", label: t("Scopes"), hint: t("Parts of the estate a rule covers.") },
] as const;

/** One entry of a reference list, e.g. "Log source". */
export const REF_KIND_ONE: Record<RefKind, string> = {
  threat_actor: t("Threat actor"),
  detection_technology: t("Detection technology"),
  log_source: t("Log source"),
  scope: t("Scope"),
};

export const isRefKind = (v: string | null): v is RefKind =>
  v === "threat_actor" || v === "detection_technology" || v === "log_source" || v === "scope";

/** URL parameters of the reference filter on the Use cases page. */
export const REF_KIND_PARAM = "ref_kind";
export const REF_PARAM = "ref";

/** Use cases page filtered to what uses one reference entry (L2 for threat actors, else L3 rules). */
export function refHref(kind: RefKind, name: string): string {
  return `/usecases?${new URLSearchParams({ [REF_KIND_PARAM]: kind, [REF_PARAM]: name })}`;
}

/** Codes for a tooltip: the first `max`, then "and N more". */
export function codeList(codes: string[], max = 20): string {
  if (codes.length <= max) return codes.join(", ");
  return t("{codes} and {n} more", { codes: codes.slice(0, max).join(", "), n: codes.length - max });
}

/** File size for people: 512 B, 40 KB, 3.2 MB. */
export function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
