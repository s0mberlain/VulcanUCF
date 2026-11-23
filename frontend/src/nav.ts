import { t } from "./i18n";
import type { Role } from "./api";
import type { NavIconKey } from "./components/NavIcon";

export interface NavItem {
  label: string;
  path: string;
  /** Milestone from docs/PLAN.md in which the screen gets built. */
  milestone?: string;
  /** Only these roles see the entry (default: everyone). */
  roles?: Role[];
  /** Heading the entry is listed under in the sidebar. */
  group: "work" | "threat" | "purple" | "analysis" | "admin" | "manage";
  icon: NavIconKey;
  /** other path prefixes whose screens belong to this entry (an interview belongs to its system) */
  also?: string[];
  /** Path of the entry this one is listed under; shown indented when that entry is opened. */
  parent?: string;
}

/** Sidebar groups by domain: each feature lives in one place (critique 2026-11-21). The group
 * heading names the domain, so entries inside it stay short ("Systems", "Trends"). */
export const NAV_GROUPS: { key: NavItem["group"]; label: string }[] = [
  { key: "work", label: t("Daily work") },
  { key: "threat", label: t("Threat modelling") },
  { key: "purple", label: t("Purple teaming") },
  { key: "analysis", label: t("Analysis") },
  { key: "admin", label: t("Setup") },
  { key: "manage", label: t("Administration") },
];

export const NAV_ITEMS: NavItem[] = [
  { label: t("Dashboard"), path: "/", icon: "dashboard", group: "work" },
  { label: t("Use cases"), path: "/usecases", icon: "usecases", group: "work" },
  { label: t("Detection requests"), path: "/usecases/requests", icon: "requests", group: "work", parent: "/usecases" },
  { label: t("Verification"), path: "/verification", icon: "verification", group: "work" },
  { label: t("Priorities"), path: "/priorities", icon: "priorities", group: "work" },
  { label: t("Systems"), path: "/systems", icon: "threat", group: "threat", also: ["/interviews/"] },
  { label: t("STRIDE mapping"), path: "/stride-mapping", icon: "stride", group: "threat" },
  {
    label: t("Assessments"),
    path: "/purple",
    icon: "purple",
    group: "purple",
    also: ["/purple/assessments/", "/purple/test-cases/"],
  },
  { label: t("Trends"), path: "/purple/trends", icon: "trends", group: "purple" },
  { label: t("Library"), path: "/purple/library", icon: "library", group: "purple" },
  { label: t("ATT&CK coverage"), path: "/attack", icon: "attack", group: "analysis" },
  { label: t("Output metrics"), path: "/output", icon: "output", group: "analysis" },
  { label: t("History & trends"), path: "/history", icon: "history", group: "analysis" },
  { label: t("Business drivers"), path: "/drivers", icon: "drivers", group: "admin" },
  { label: t("Reference lists"), path: "/references", icon: "references", group: "admin" },
  { label: t("Import / Export"), path: "/import-export", icon: "transfer", group: "admin" },
  { label: t("Integrations"), path: "/integrations", icon: "integrations", group: "admin" },
  { label: t("Audit log"), path: "/audit", icon: "audit", roles: ["admin", "auditor"], group: "manage" },
  { label: t("Users"), path: "/admin/users", icon: "users", roles: ["admin"], group: "manage" },
  { label: t("Settings"), path: "/settings", icon: "settings", roles: ["admin"], group: "manage" },
];

/** Whether a nav entry is the current one: its own path exactly, or one of its `also` prefixes,
 * or a sub-path that no other entry claims (e.g. /usecases/l3/X under Use cases). */
export function navActive(item: NavItem, pathname: string): boolean {
  if (pathname === item.path) return true;
  if (item.path === "/") return false;
  if (item.also?.some((p) => pathname.startsWith(p))) return true;
  if (!pathname.startsWith(item.path + "/")) return false;
  return !NAV_ITEMS.some((o) => o !== item && o.path.startsWith(item.path + "/") && pathname.startsWith(o.path));
}
