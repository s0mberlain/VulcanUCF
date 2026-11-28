/**
 * Texts that the API sends as labels (lifecycle definition of done and change drivers, trend
 * metrics). They are shown with `t(label)`; listing them here
 * puts them into the translation files and `npm run i18n:check`. Keep in sync with
 * backend/app/lifecycle.py and backend/app/snapshots.py.
 */
import { t } from "./i18n";

export const serverTexts = () => [
  t("Log sources deliver data"),
  t("Required log sources are connected and delivering."),
  t("Scope implemented"),
  t("All assets, users or networks in scope are covered."),
  t("Incident response documented"),
  t("There is a playbook for the alerts."),
  t("Roles documented"),
  t("Owner and responsibilities for the use case are written down."),
  t("Rules implemented, tested and documented"),
  t("Detection logic is live and tested."),
  t("Threat landscape"),
  t("Business change"),
  t("Regulation"),
  t("IT infrastructure"),
  t("Red / purple teaming"),
  t("Incident lessons learned"),
  t("Threat hunting"),
  t("Tuning / false positives"),
  t("Other"),
  t("SOC detection score"),
  t("Catalogue coverage"),
  t("Growth potential"),
  t("Framework completeness"),
  t("Assessment coverage"),
  t("Verification health"),
  t("L2 use cases with rules"),
  t("L3 rules"),
  t("Operational rules"),
  t("Log sources in use"),
  t("Scopes in use"),
  t("Now"),
];

/** Marks an English server message for the translation files (picked up by i18n:check). */
const st = (s: string) => s;

/** Error messages the API sends (#53). Fixed texts are looked up as they are; `{name}` parts
 * match any text and are put into the translation. Keep in sync with the backend messages. */
const SERVER_MESSAGES = [
  st("Not signed in"),
  st("Your role does not allow this action"),
  st("Invalid username or password"),
  st("Invalid authentication code"),
  st("Too many failed sign-ins, try again later"),
  st("Account temporarily locked, try again later"),
  st("Local login is disabled"),
  st("The request is too large"),
  st("Cross-site request refused"),
  st("Not found"),
  st("Username already exists"),
  st("You cannot delete yourself"),
  st("Cannot remove the last active admin"),
  st("Delete or move its L3 rules first"),
  st("Delete or move its L2 use cases first"),
  st("Nothing to commit: the content is unchanged"),
  st("Verification date cannot be in the future"),
  st("Only admins can skip the definition of done"),
  st("This system already has a draft interview"),
  st("Only a draft interview can be deleted"),
  st("Complete the interview before confirming"),
  st("The interview is not confirmed"),
  st("The interview date cannot be in the future"),
  st("The confirmation date cannot be before the interview date"),
  st("Add at least one component before completing the interview"),
  st("A detection request needs a text"),
  st("A detection request is tied to a threat that does not apply"),
  st("Give a reason for a rejected or not feasible request"),
  st("Detection request not found"),
  st("Unknown log source; reload the page"),
  st("Unknown L2 use case; reload the page"),
  st("Unknown L3 rule; reload the page"),
  st("A completed interview cannot be changed; start a new one"),
  st("Evidence can only be added while the interview is a draft"),
  st("Evidence of a completed interview cannot be removed"),
  st("A sign-off can be added after completion and before the confirmation"),
  st("This interview has a sign-off file already"),
  st("A sign-off must be a PDF, JPG or PNG file"),
  st("The file is empty"),
  st("The file is larger than 20 MB"),
  st("This draft was changed by {user}; reload to see the changes"),
  st("Already confirmed by {name}; remove that confirmation first"),
  st("The interview date must be on or after the previous interview ({date})"),
  st("Complete description, likelihood and impact of these threats: {list}"),
  st("A system named {name} exists already"),
  st("{code} is already {status}"),
  st("Definition of done is not complete: {list}"),
  st("Password must be at least {n} characters"),
  st("The file content does not match a .{ext} file"),
  st("The evidence storage is full ({mb} MB); ask an admin to remove old files or raise EVIDENCE_MAX_TOTAL_MB"),
  // purple teaming (app/api/purple.py, purple_library.py)
  st("Assessment not found"),
  st("Campaign not found"),
  st("Test case not found"),
  st("Test procedure not found"),
  st("Campaign template not found"),
  st("This was changed by {user}; reload to see the changes"),
  st("Unknown L3 rule {code}"),
  st("Enter the time the attack started"),
  st("A test case can only move within its assessment"),
  st("A test case can have at most {n} files"),
  st("The file is larger than 20 MB"),
  st("The file is larger than 10 MB"),
  st("The file is empty"),
  st("{name} exists already"),
  st("Atomic test not found"),
  // Single sign-on settings (backend/app/api/sso_settings.py)
  st("SSO is set in the environment (OIDC_* variables); change it there"),
  st("Enter your own tenant ID: common, organizations and consumers let in accounts of any tenant"),
  st("The tenant ID is a GUID or a domain such as contoso.onmicrosoft.com"),
  st("The issuer must be an https:// URL"),
  st("The scopes must include openid"),
  st("Enter the tenant ID or issuer and the client ID before turning SSO on"),
  st("Map at least one group or role, or set a default role, before turning SSO on"),
  st("Enter the tenant ID or issuer and the client ID first"),
  st("{value} is mapped twice"),
];

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const PATTERNS = SERVER_MESSAGES.filter((m) => m.includes("{")).map((m) => {
  const names: string[] = [];
  const re = escape(m).replace(/\\\{(\w+)\\\}/g, (_x, n: string) => {
    names.push(n);
    return "(.+?)";
  });
  return { template: m, names, re: new RegExp(`^${re}$`) };
});
const FIXED = new Set(SERVER_MESSAGES.filter((m) => !m.includes("{")));

/** The server's (English) message in the user's language, when it is a known one. */
export function translateServer(message: string): string {
  if (FIXED.has(message)) return t(message);
  for (const p of PATTERNS) {
    const m = p.re.exec(message);
    if (m) return t(p.template, Object.fromEntries(p.names.map((n, i) => [n, m[i + 1]])));
  }
  return message;
}
