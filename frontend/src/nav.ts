import { t } from "./i18n";
import type { Role } from "./api";
import type { NavIconKey } from "./components/NavIcon";

export interface NavItem {
  label: string;
  path: string;
  /** Only these roles see the entry (default: everyone). */
  roles?: Role[];
  /** Heading the entry is listed under in the sidebar. */
  group: "work" | "analysis" | "admin" | "manage";
  icon: NavIconKey;
  /** other path prefixes whose screens belong to this entry (an interview belongs to its system) */
  also?: string[];
  /** Path of the entry this one is listed under; shown indented when that entry is opened. */
  parent?: string;
}

export const NAV_GROUPS: { key: NavItem["group"]; label: string }[] = [
  { key: "work", label: t("Daily work") },
  { key: "analysis", label: t("Analysis") },
  { key: "admin", label: t("Setup") },
  { key: "manage", label: t("Administration") },
];

export const NAV_ITEMS: NavItem[] = [
  { label: t("Dashboard"), path: "/", icon: "dashboard", group: "work" },
  { label: t("Use cases"), path: "/usecases", icon: "usecases", group: "work" },
  { label: t("Detection requests"), path: "/usecases/requests", icon: "requests", group: "work", parent: "/usecases" },
  { label: t("Verification"), path: "/verification", icon: "verification", group: "work" },
  {
    label: t("Campaigns"),
    path: "/verification/campaigns",
    icon: "campaigns",
    group: "work",
    parent: "/verification",
    roles: ["admin", "analyst", "auditor", "red_team"],
  },
  { label: t("Quick tests"), path: "/verification/quick-tests", icon: "quick", group: "work", parent: "/verification" },
  { label: t("Detection gaps"), path: "/verification/gaps", icon: "gaps", group: "work", parent: "/verification" },
  { label: t("Test library"), path: "/verification/library", icon: "library", group: "work", parent: "/verification" },
  { label: t("Log sources"), path: "/verification/log-sources", icon: "logsources", group: "work", parent: "/verification" },
  { label: t("Tasks"), path: "/tasks", icon: "tasks", group: "work" },
  { label: t("Priorities"), path: "/priorities", icon: "priorities", group: "work" },
  { label: t("Threat modelling"), path: "/systems", icon: "threat", also: ["/interviews"], group: "work" },
  { label: t("ATT&CK coverage"), path: "/attack", icon: "attack", group: "analysis" },
  { label: t("Output metrics"), path: "/output", icon: "output", group: "analysis" },
  { label: t("History & trends"), path: "/history", icon: "history", group: "analysis" },
  { label: t("Business drivers"), path: "/drivers", icon: "drivers", group: "admin" },
  { label: t("STRIDE mapping"), path: "/stride-mapping", icon: "stride", group: "admin" },
  { label: t("Reference lists"), path: "/references", icon: "references", group: "admin" },
  { label: t("Import / Export"), path: "/import-export", icon: "transfer", group: "admin" },
  { label: t("Integrations"), path: "/integrations", icon: "integrations", group: "admin" },
  { label: t("Audit log"), path: "/audit", icon: "audit", roles: ["admin", "auditor"], group: "manage" },
  { label: t("Users"), path: "/admin/users", icon: "users", roles: ["admin"], group: "manage" },
  { label: t("Settings"), path: "/settings", icon: "settings", roles: ["admin"], group: "manage" },
];
