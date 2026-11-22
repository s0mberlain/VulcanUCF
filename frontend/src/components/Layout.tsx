import { useEffect, useState } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { api } from "../api";
import { ROLE_LABEL, useAuth } from "../auth";
import { isOverdue } from "../lib/verification";
import { NAV_GROUPS, NAV_ITEMS, type NavItem } from "../nav";
import LanguageSelect from "./LanguageSelect";
import Logo from "./Logo";
import NavIcon from "./NavIcon";
import { t } from "../i18n";

function initials(name: string): string {
  return (
    name
      .split(/[\s._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((p) => p[0]!.toUpperCase())
      .join("") || "?"
  );
}

const COLLAPSE_KEY = "magma.sidebar.collapsed";

/** Does the current address belong to this entry? An interview belongs to its system. */
function belongs(item: NavItem, path: string): boolean {
  if (item.path === "/") return path === "/";
  return [item.path, ...(item.also ?? [])].some((p) => path === p || path.startsWith(p + "/"));
}

export default function Layout() {
  const { user, logout, can } = useAuth();
  const name = user?.display_name || user?.username || "";
  // On a phone the menu is folded away behind a button and closes again after a choice.
  const [open, setOpen] = useState(false);
  // On a wide screen the sidebar can be folded to an icon rail; the choice is remembered.
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSE_KEY) === "1";
    } catch {
      return false;
    }
  });
  const toggleCollapsed = () =>
    setCollapsed((x) => {
      try {
        localStorage.setItem(COLLAPSE_KEY, x ? "0" : "1");
      } catch {
        /* storage blocked: keep the choice for this visit only */
      }
      return !x;
    });
  const location = useLocation();
  const path = location.pathname;
  useEffect(() => setOpen(false), [path]);
  // one title per screen, so browser tabs and history entries can be told apart
  useEffect(() => {
    const hit = NAV_ITEMS.filter((n) => belongs(n, path)).sort((x, y) => y.path.length - x.path.length)[0];
    const label = hit ? hit.label : path.startsWith("/account") ? t("Account") : "";
    document.title = label ? `${label} · ${t("Vulcan UCF")}` : t("Vulcan UCF");
  }, [path]);
  // red team accounts see only the entries that name their role; everyone else the rest
  const visible = NAV_ITEMS.filter((item) =>
    user?.role === "red_team" ? !!item.roles?.includes("red_team") : !item.roles || can(...item.roles),
  );
  // open work shown next to the entries that lead to it
  const [counts, setCounts] = useState({ requests: 0, overdue: 0 });
  useEffect(() => {
    if (!user || user.role === "red_team") return;
    let live = true;
    Promise.all([api.detectionRequests(), api.due(30)])
      .then(([r, d]) => {
        if (!live) return;
        setCounts({
          requests: r.requests.filter((x) => !x.archived && (x.status === "open" || x.status === "in_progress")).length,
          overdue: d.filter(isOverdue).length,
        });
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [user?.username, path]);
  const countOf = (item: NavItem): { n: number; text: string } | null => {
    const n = item.path === "/usecases/requests" ? counts.requests : item.path === "/verification" ? counts.overdue : 0;
    if (!n) return null;
    return { n, text: item.path === "/verification" ? t("{n} overdue", { n }) : t("{n} open", { n }) };
  };
  // entries with sub-entries open and close; the one with the current page is open
  const [opened, setOpened] = useState<Set<string>>(new Set());
  const isOpen = (item: NavItem) => opened.has(item.path) || (belongs(item, path) && visible.some((c) => c.parent === item.path)) || visible.some((c) => c.parent === item.path && belongs(c, path));
  const expand = (p: string) => setOpened((x) => (x.has(p) ? x : new Set(x).add(p)));
  const toggle = (p: string) =>
    setOpened((x) => {
      const next = new Set(x);
      if (!next.delete(p)) next.add(p);
      return next;
    });

  const link = (item: NavItem, active: boolean, sub: boolean, onClick?: () => void) => {
    const c = countOf(item);
    return (
      <Link
        key={item.path}
        to={item.path}
        className={"nav-link" + (sub ? " nav-link-sub" : "") + (active ? " active" : "")}
        aria-current={active ? "page" : undefined}
        title={item.label}
        onClick={onClick}
      >
        <NavIcon name={item.icon} />
        <span className="nav-label">{item.label}</span>
        {c && (
          <>
            <span className="nav-count" aria-hidden="true">
              {c.n}
            </span>
            <span className="sr-only">{c.text}</span>
          </>
        )}
      </Link>
    );
  };

  const group = (g: (typeof NAV_GROUPS)[number]) => {
    const items = visible.filter((item) => item.group === g.key);
    if (!items.length) return null;
    return (
      <div key={g.key} className={"nav-group" + (g.key === "manage" ? " nav-group-manage" : "")} role="group" aria-label={g.label}>
        <span className="nav-group-head">{g.label}</span>
        {items
          .filter((item) => !item.parent || !items.some((p) => p.path === item.parent))
          .map((item) => {
            const subs = items.filter((c) => c.parent === item.path);
            const expanded = isOpen(item);
            const onSub = subs.some((c) => belongs(c, path));
            const active = belongs(item, path) && !onSub;
            return (
              <div key={item.path} className="nav-branch">
                <div className={"nav-row" + (onSub ? " is-ancestor" : "")}>
                  {/* a click on the entry opens its sub-entries (the arrow also closes them) */}
                  {link(item, active, false, () => subs.length > 0 && expand(item.path))}
                  {subs.length > 0 && (
                    <button
                      type="button"
                      className="nav-expand"
                      aria-expanded={expanded}
                      aria-controls={expanded ? `nav-sub-${item.path.slice(1)}` : undefined}
                      aria-label={t("Show entries under {name}", { name: item.label })}
                      title={t("Show entries under {name}", { name: item.label })}
                      onClick={() => toggle(item.path)}
                    >
                      <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
                        <path
                          d={expanded ? "M2 4l4 4 4-4" : "M4 2l4 4-4 4"}
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.8"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                      </svg>
                    </button>
                  )}
                </div>
                {subs.length > 0 && (
                  <div id={`nav-sub-${item.path.slice(1)}`} className={"nav-sub" + (expanded ? "" : " is-folded")}>
                    {subs.map((c) => link(c, belongs(c, path), true))}
                  </div>
                )}
              </div>
            );
          })}
      </div>
    );
  };

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        {t("Skip to content")}
      </a>
      <nav
        className={"sidebar" + (open ? " is-open" : "") + (collapsed ? " is-collapsed" : "")}
        aria-label={t("Main")}
      >
        <div className="brand">
          <Logo />
          <span className="brand-name">{t("Vulcan UCF")}</span>
          <button
            type="button"
            className="nav-collapse"
            aria-expanded={!collapsed}
            aria-controls="nav-menu"
            title={collapsed ? t("Show menu") : t("Hide menu")}
            aria-label={collapsed ? t("Show menu") : t("Hide menu")}
            onClick={toggleCollapsed}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
              <path
                d={collapsed ? "M6 3l5 5-5 5" : "M10 3L5 8l5 5"}
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </button>
          <button
            type="button"
            className="nav-toggle"
            aria-expanded={open}
            aria-controls="nav-menu"
            onClick={() => setOpen((x) => !x)}
          >
            {open ? t("Close menu") : t("Menu")}
          </button>
        </div>
        <div id="nav-menu" className="nav-menu">
          <div className="nav-scroll">{NAV_GROUPS.filter((g) => g.key !== "manage").map(group)}</div>
          <div className="nav-foot">
            {NAV_GROUPS.filter((g) => g.key === "manage").map(group)}
            {user && (
              <div className="user-box">
                <Link
                  className={"avatar" + (path.startsWith("/account") ? " is-current" : "")}
                  to="/account"
                  title={t("Account and two-factor login")}
                  aria-label={t("Account and two-factor login")}
                  tabIndex={collapsed ? 0 : -1}
                >
                  {initials(name)}
                </Link>
                <Link
                  className={"user-meta" + (path.startsWith("/account") ? " is-current" : "")}
                  to="/account"
                  title={t("Account and two-factor login")}
                  aria-current={path.startsWith("/account") ? "page" : undefined}
                >
                  <span>{name}</span>
                  <span>
                    {ROLE_LABEL[user.role]} · {user.auth_source === "sso" ? "SSO" : t("Local")}
                  </span>
                </Link>
                <LanguageSelect save className="lang-dark" />
                <button type="button" className="signout" title={t("Sign out")} onClick={() => void logout()}>
                  <NavIcon name="signout" />
                  <span className="nav-label">{t("Sign out")}</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </nav>
      <main id="main" tabIndex={-1} className="content">
        <Outlet />
      </main>
    </div>
  );
}
