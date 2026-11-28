import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import {
  api,
  type SsoCheckItem,
  type SsoProvider,
  type SsoRole,
  type SsoSettings,
  type SsoSettingsIn,
  type SsoSettingsOut,
  type SsoTestResult,
} from "../api";
import { ErrorNote, useLoad, useUnsavedGuard } from "../components/ui";
import MicrosoftLogo from "../components/MicrosoftLogo";
import { fmtDate, fmtTime } from "../lib/format";
import { t } from "../i18n";

/**
 * Administration → Single sign-on (backend/app/sso.py, api/sso_settings.py): the values the IAM
 * team needs, the connection, the role mapping, a test sign-in and the switch for the sign-in
 * page. Read-only when the OIDC_* environment variables set SSO.
 */

const ROLES: { value: SsoRole; label: string }[] = [
  { value: "admin", label: t("Admin") },
  { value: "analyst", label: t("Analyst") },
  { value: "auditor", label: t("Auditor (read-only)") },
];
const ROLE_NAME: Record<SsoRole, string> = { admin: t("Admin"), analyst: t("Analyst"), auditor: t("Auditor (read-only)") };
const DEFAULT_SCOPES: Record<SsoProvider, string> = { entra: "openid profile email User.Read", oidc: "openid profile email" };
const DEFAULT_ROLE_CLAIM: Record<SsoProvider, string> = { entra: "roles", oidc: "groups" };
const SUGGESTED_APP_ROLES: { value: string; role: SsoRole }[] = [
  { value: "Vulcan.Admin", role: "admin" },
  { value: "Vulcan.Analyst", role: "analyst" },
  { value: "Vulcan.Auditor", role: "auditor" },
];
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MULTI_TENANT = ["common", "organizations", "consumers"];
const STATUS_TEXT: Record<SsoCheckItem["status"], string> = { ok: t("OK"), warn: t("Warning"), fail: t("Failed") };
const STATUS_ICON: Record<SsoCheckItem["status"], string> = { ok: "✓", warn: "!", fail: "✕" };

function editable(s: SsoSettingsOut): SsoSettings {
  return {
    enabled: s.enabled,
    provider: s.provider,
    tenant_id: s.tenant_id,
    issuer: s.issuer,
    client_id: s.client_id,
    scopes: s.scopes,
    role_claim: s.role_claim,
    role_map: s.role_map,
    default_role: s.default_role,
    username_claim: s.username_claim,
    button_label: s.button_label,
  };
}

function connectionSet(s: SsoSettings): boolean {
  return !!(s.provider === "entra" ? s.tenant_id.trim() : s.issuer.trim()) && !!s.client_id.trim();
}

function defaultLabel(provider: SsoProvider): string {
  return provider === "entra" ? t("Sign in with Microsoft") : t("Sign in with SSO");
}

function checkText(c: SsoCheckItem): string {
  const p = c.params;
  switch (`${c.key}:${c.status}`) {
    case "discovery:ok":
      return t("Found the identity provider ({issuer}).", { issuer: p.issuer ?? "" });
    case "discovery:fail":
      return t("Could not load {url}.", { url: p.url ?? "" });
    case "multi_tenant:fail":
      return t("This is the multi-tenant endpoint, which lets in accounts of every Entra ID tenant. Enter your own tenant ID.");
    case "keys:ok":
      return t("Loaded {n} signing keys.", { n: p.n ?? "0" });
    case "keys:fail":
      return t("Could not load the signing keys.");
    case "client:ok":
      return t("The client ID and secret were accepted.");
    case "client:fail":
      return t("The identity provider rejected the client ID or secret.");
    case "client_unknown:warn":
      return t("The client secret could not be checked this way. A test sign-in shows whether it works.");
    case "client_public:warn":
      return t("No client secret is set. This only works when the app is registered as a public client.");
    case "redirect_http:warn":
      return t("BASE_URL starts with http://. Entra ID and most providers only accept https:// redirect URIs, except for localhost.");
    case "no_roles:warn":
      return t("No role mapping and no default role: nobody can sign in yet.");
    case "entra_group_names:warn":
      return t("Entra ID sends group object IDs, not names, so these never match: {values}", { values: p.values ?? "" });
    default:
      return c.key;
  }
}

function testErrorText(r: SsoTestResult): string {
  const name = r.username ?? "";
  switch (r.error) {
    case "no_access":
      return t("None of the values in {claim} matches a mapping and there is no default role, so this person would get no access.", {
        claim: r.role_claim,
      });
    case "local_account":
      return t("The user name {name} belongs to a local account, so this person cannot sign in with SSO. Rename or delete the local account first.", { name });
    case "name_taken":
      return t("The user name {name} is already used by another SSO account.", { name });
    case "disabled":
      return t("The account {name} is disabled.", { name });
    case "invalid_token":
      return t("The ID token could not be verified.");
    case "rejected":
      return t("The identity provider refused the sign-in. Check the client ID, the client secret and the redirect URI.");
    case "unreachable":
      return t("The identity provider could not be reached.");
    case "cancelled":
      return t("Sign-in was cancelled or refused by the identity provider");
    default:
      return t("The sign-in failed.");
  }
}

/** The text for the IAM team's ticket, in the page's language. */
function iamText(s: SsoSettingsOut, form: SsoSettings): string {
  const roles = (form.role_map.length ? form.role_map : SUGGESTED_APP_ROLES)
    .map((m) => `${m.value} (${ROLE_NAME[m.role]})`)
    .join(", ");
  const lines =
    form.provider === "entra"
      ? [
          t("Please register an application in Microsoft Entra ID for single sign-on to {app}:", { app: "Vulcan UCF" }),
          "- " + t("App registrations → New registration, accounts in this organizational directory only"),
          "- " + t("Redirect URI (platform Web): {uri}", { uri: s.redirect_uri }),
          "- " + t("API permissions: Microsoft Graph User.Read (delegated), with admin consent"),
          form.role_claim === "groups"
            ? "- " +
              t("Token configuration: add the groups claim (security groups, ID token, Group ID) for these groups: {roles}", { roles })
            : "- " + t("App roles (allowed member types: Users/Groups): {roles}. Assign people or groups to them under Enterprise applications → Users and groups.", { roles }),
          "- " + t("Create a client secret and send us its value, the Application (client) ID and the Directory (tenant) ID."),
        ]
      : [
          t("Please register an OpenID Connect client for single sign-on to {app}:", { app: "Vulcan UCF" }),
          "- " + t("Client type: confidential (web application), authorization code flow with PKCE"),
          "- " + t("Redirect URI: {uri}", { uri: s.redirect_uri }),
          "- " + t("Scopes: {scopes}", { scopes: form.scopes }),
          "- " + t("Put the user's groups or roles into the ID token claim {claim}: {roles}", { claim: form.role_claim, roles }),
          "- " + t("Send us the issuer URL, the client ID and the client secret."),
        ];
  return lines.join("\n");
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [state, setState] = useState<"" | "ok" | "fail">("");
  function copy() {
    const done = (ok: boolean) => {
      setState(ok ? "ok" : "fail");
      window.setTimeout(() => setState(""), 2500);
    };
    if (!navigator.clipboard) return done(false);
    navigator.clipboard.writeText(text).then(
      () => done(true),
      () => done(false),
    );
  }
  return (
    <button type="button" className="btn btn-sm" onClick={copy}>
      {state === "ok" ? t("Copied") : state === "fail" ? t("Copy failed") : (label ?? t("Copy"))}
    </button>
  );
}

function CopyValue({ value }: { value: string }) {
  return (
    <span className="sso-copy">
      <code className="mono">{value}</code>
      <CopyButton text={value} />
    </span>
  );
}

function StatusPill({ s }: { s: SsoSettingsOut }) {
  if (s.enabled) return <span className="pill sso-pill-on">{t("On")}</span>;
  if (connectionSet(s)) return <span className="pill pill-warn">{t("Set up, not turned on")}</span>;
  return <span className="pill sso-pill-off">{t("Off")}</span>;
}

function claimValue(v: unknown): string {
  return typeof v === "string" ? v : JSON.stringify(v);
}

function TestResult({ r }: { r: SsoTestResult }) {
  const claims = Object.entries(r.claims);
  return (
    <div className={"sso-result " + (r.ok ? "is-ok" : "is-fail")}>
      <div className="section-head">
        <strong>{r.ok ? t("The test sign-in worked") : t("The test sign-in failed")}</strong>
        <span className="small muted">
          {t("Test by {user} on {date}", { user: r.by, date: `${fmtDate(r.at)} ${fmtTime(r.at)}` })}
        </span>
      </div>
      {r.ok && r.role ? (
        <p>
          {t("{name} would sign in as {role}.", { name: r.username ?? "", role: ROLE_NAME[r.role] })}{" "}
          {r.account === "existing" ? t("The existing account is used.") : t("The account is created at the first sign-in.")}
        </p>
      ) : (
        <p>{testErrorText(r)}</p>
      )}
      {r.detail && <code className="sso-detail">{r.detail}</code>}

      {(r.values.length > 0 || r.groups_from) && (
        <div className="stack-xs">
          <span className="small">{t("Values in {claim}", { claim: r.role_claim })}</span>
          {r.values.length > 0 ? (
            <ul className="sso-values" aria-label={t("Values in {claim}", { claim: r.role_claim })}>
              {r.values.map((v) => (
                <li key={v} className={r.matched.includes(v) ? "is-match" : ""}>
                  {v}
                  {r.matched.includes(v) && <span className="sr-only"> {t("(mapped)")}</span>}
                </li>
              ))}
            </ul>
          ) : (
            <span className="small muted">{t("The identity provider sent no {claim} claim.", { claim: r.role_claim })}</span>
          )}
          {r.groups_from === "microsoft_graph" && (
            <span className="small muted">
              {t("Entra ID left the groups out of the token (more than 200 groups); the mapped ones were looked up in Microsoft Graph.")}
            </span>
          )}
          {r.groups_from === "userinfo" && <span className="small muted">{t("Taken from the userinfo endpoint.")}</span>}
        </div>
      )}

      {claims.length > 0 && (
        <details>
          <summary className="small">{t("All claims in the ID token ({n})", { n: claims.length })}</summary>
          <div className="scroll-x">
            <table className="table sso-claims">
              <tbody>
                {claims.map(([k, v]) => (
                  <tr key={k}>
                    <th scope="row" className="mono">
                      {k}
                    </th>
                    <td className="mono">{claimValue(v)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  );
}

export default function SsoSettingsPage() {
  const saved = useLoad(() => api.ssoSettings());
  const test = useLoad(() => api.ssoTestResult());
  const [params] = useSearchParams();
  const [form, setForm] = useState<SsoSettings | null>(null);
  const [secret, setSecret] = useState("");
  const [removeSecret, setRemoveSecret] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [checks, setChecks] = useState<SsoCheckItem[] | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    if (saved.data) setForm(editable(saved.data));
  }, [saved.data]);

  // back from a test sign-in: show its result
  const fromTest = params.get("test") === "done";
  useEffect(() => {
    if (fromTest && test.data) document.getElementById("sso-test")?.scrollIntoView({ block: "start" });
  }, [fromTest, test.data]);

  const s = saved.data;
  const dirty = !!s && !!form && (JSON.stringify(form) !== JSON.stringify(editable(s)) || secret !== "" || removeSecret);
  useUnsavedGuard(dirty);

  if (saved.error) return <ErrorNote error={saved.error} />;
  if (!s || !form) return <p className="muted">{t("Loading…")}</p>;

  const readOnly = s.source === "env";
  const entra = form.provider === "entra";
  const groups = entra && form.role_claim === "groups";
  const tenantBad = entra && MULTI_TENANT.includes(form.tenant_id.trim().toLowerCase());
  const groupNames = groups ? form.role_map.map((m) => m.value.trim()).filter((v) => v && !GUID.test(v)) : [];
  const base = new URL(s.base_url, window.location.href);
  const httpBase = base.protocol === "http:" && !["localhost", "127.0.0.1"].includes(base.hostname);
  const label = form.button_label.trim() || defaultLabel(form.provider);
  const canTest = connectionSet(s) && !dirty;

  const update = (patch: Partial<SsoSettings>) => {
    setNotice(null);
    setChecks(null);
    setForm((f) => (f ? { ...f, ...patch } : f));
  };
  const setProvider = (p: SsoProvider) => {
    const other: SsoProvider = p === "entra" ? "oidc" : "entra";
    update({
      provider: p,
      scopes: form.scopes === DEFAULT_SCOPES[other] ? DEFAULT_SCOPES[p] : form.scopes,
      role_claim: form.role_claim === DEFAULT_ROLE_CLAIM[other] ? DEFAULT_ROLE_CLAIM[p] : form.role_claim,
    });
  };
  const setMapping = (i: number, patch: Partial<SsoSettings["role_map"][number]>) =>
    update({ role_map: form.role_map.map((m, j) => (j === i ? { ...m, ...patch } : m)) });

  function body(): SsoSettingsIn {
    if (!form) throw new Error("no form");
    return {
      ...form,
      role_map: form.role_map.filter((m) => m.value.trim()).map((m) => ({ ...m, value: m.value.trim() })),
      client_secret: removeSecret ? "" : secret.trim() ? secret.trim() : null,
    };
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await api.saveSsoSettings(body());
      saved.setData(r);
      setSecret("");
      setRemoveSecret(false);
      setNotice(t("Saved."));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function runCheck() {
    setChecking(true);
    setError(null);
    try {
      setChecks(await api.checkSso(body()));
    } catch (err) {
      setChecks(null);
      setError((err as Error).message);
    } finally {
      setChecking(false);
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Single sign-on")}</h1>
          <div className="subtitle">
            {t("Let people sign in with their company account through OpenID Connect, for example Microsoft Entra ID.")}
          </div>
        </div>
        <StatusPill s={s} />
      </header>

      {readOnly && (
        <p className="note-box" style={{ margin: 0 }}>
          {t(
            "These settings come from the OIDC_* environment variables and can only be changed there. Remove OIDC_ISSUER from the environment to manage single sign-on on this page.",
          )}
        </p>
      )}

      <form className="stack-lg" onSubmit={save}>
        {/* ---- 1. for the IAM team */}
        <section className="card stack" aria-labelledby="sso-iam-h">
          <div className="stack-xs">
            <h2 id="sso-iam-h">{t("1. Information for your IAM team")}</h2>
            <span className="muted small">
              {t(
                "Whoever manages your identity provider registers this app with these values and sends back what step 2 needs.",
              )}
            </span>
          </div>
          {httpBase && (
            <p className="form-error" role="alert">
              {t(
                "BASE_URL is {url}. Identity providers only accept https:// redirect URIs (except for localhost). Set BASE_URL to the public https:// address of this app.",
                { url: s.base_url },
              )}
            </p>
          )}
          <dl className="facts">
            <dt>{t("Redirect URI")}</dt>
            <dd>
              <CopyValue value={s.redirect_uri} />
            </dd>
            <dt>{t("Sign-in page")}</dt>
            <dd>
              <CopyValue value={s.login_url} />
            </dd>
            <dt>{t("Platform")}</dt>
            <dd>{t("Web application (confidential client with a client secret)")}</dd>
            <dt>{t("Flow")}</dt>
            <dd>{t("Authorization code with PKCE (S256)")}</dd>
            <dt>{t("Scopes")}</dt>
            <dd>
              <code className="mono">{form.scopes}</code>
            </dd>
            <dt>{t("Roles")}</dt>
            <dd>
              {entra
                ? groups
                  ? t("Groups claim with security group object IDs")
                  : t("App roles: {roles}", {
                      roles: (form.role_map.length ? form.role_map : SUGGESTED_APP_ROLES).map((m) => m.value).join(", "),
                    })
                : t("Groups or roles in the claim {claim}", { claim: form.role_claim })}
            </dd>
          </dl>
          <span className="small muted">{t("The redirect URI comes from BASE_URL in the environment.")}</span>
          <div className="row-actions start">
            <CopyButton text={iamText(s, form)} label={t("Copy as text for a ticket")} />
          </div>
        </section>

        {/* ---- 2. connection */}
        <section className="card stack" aria-labelledby="sso-conn-h">
          <h2 id="sso-conn-h">{t("2. Connection")}</h2>
          <div className="sso-choice-row" role="radiogroup" aria-label={t("Identity provider")}>
            <span className="sso-choice-label">{t("Identity provider")}</span>
            <div className="sso-segmented">
              {(["entra", "oidc"] as const).map((p) => (
                <label key={p} className={"sso-segment" + (form.provider === p ? " is-on" : "")}>
                  <input type="radio" name="sso-provider" checked={form.provider === p} disabled={readOnly} onChange={() => setProvider(p)} />
                  {p === "entra" && <MicrosoftLogo size={14} />}
                  {p === "entra" ? t("Microsoft Entra ID") : t("Other OpenID Connect provider")}
                </label>
              ))}
            </div>
          </div>

          <div className="form-grid">
            {entra ? (
              <label className="field">
                {t("Directory (tenant) ID")}
                <input
                  className={"input mono" + (tenantBad ? " is-invalid" : "")}
                  value={form.tenant_id}
                  disabled={readOnly}
                  spellCheck={false}
                  autoComplete="off"
                  maxLength={253}
                  placeholder="00000000-0000-0000-0000-000000000000"
                  onChange={(e) => update({ tenant_id: e.target.value })}
                />
                {tenantBad ? (
                  <span className="field-error">
                    {t("This lets in accounts of every Entra ID tenant. Enter your own tenant ID.")}
                  </span>
                ) : (
                  <span className="small muted">
                    {t("Entra admin center → Overview → Tenant ID, or a domain such as contoso.onmicrosoft.com.")}
                  </span>
                )}
              </label>
            ) : (
              <label className="field">
                {t("Issuer URL")}
                <input
                  className="input mono"
                  type="url"
                  value={form.issuer}
                  disabled={readOnly}
                  spellCheck={false}
                  autoComplete="off"
                  maxLength={500}
                  placeholder="https://login.example.com/realms/soc"
                  onChange={(e) => update({ issuer: e.target.value })}
                />
                <span className="small muted">{t("The address in front of /.well-known/openid-configuration.")}</span>
              </label>
            )}
            <label className="field">
              {entra ? t("Application (client) ID") : t("Client ID")}
              <input
                className="input mono"
                value={form.client_id}
                disabled={readOnly}
                spellCheck={false}
                autoComplete="off"
                maxLength={255}
                onChange={(e) => update({ client_id: e.target.value })}
              />
            </label>
          </div>

          {!readOnly && (
            <div className="stack-sm">
              <label className="field">
                {t("Client secret")}
                <input
                  className="input mono"
                  type="password"
                  value={secret}
                  disabled={removeSecret}
                  autoComplete="new-password"
                  maxLength={1000}
                  placeholder={s.client_secret_status === "set" ? t("Stored. Leave empty to keep it.") : ""}
                  onChange={(e) => {
                    setNotice(null);
                    setChecks(null);
                    setSecret(e.target.value);
                  }}
                />
                {s.client_secret_status === "unreadable" ? (
                  <span className="field-error">
                    {t("The stored secret cannot be read because SECRET_KEY changed. Enter it again.")}
                  </span>
                ) : (
                  entra && (
                    <span className="small muted">
                      {t(
                        "Certificates & secrets → New client secret. Copy its Value, not the Secret ID, and note when it expires: sign-in stops working then.",
                      )}
                    </span>
                  )
                )}
              </label>
              {s.client_secret_status === "set" && (
                <label className="check small">
                  <input type="checkbox" checked={removeSecret} onChange={(e) => setRemoveSecret(e.target.checked)} />
                  {t("Remove the stored secret")}
                </label>
              )}
            </div>
          )}
          {readOnly && (
            <p className="small muted" style={{ margin: 0 }}>
              {s.client_secret_status === "set" ? t("A client secret is set.") : t("No client secret is set.")}
            </p>
          )}

          <div className="row-actions start">
            <button type="button" className="btn" disabled={checking || !connectionSet(form)} onClick={() => void runCheck()}>
              {checking ? t("Checking…") : t("Check connection")}
            </button>
          </div>
          {checks && (
            <ul className="sso-checks" aria-label={t("Check results")}>
              {checks.map((c) => (
                <li key={c.key} className={"sso-check is-" + c.status}>
                  <span className="sso-check-icon" aria-hidden="true">
                    {STATUS_ICON[c.status]}
                  </span>
                  <div className="stack-xs">
                    <span>
                      <span className="sr-only">{STATUS_TEXT[c.status]}: </span>
                      {checkText(c)}
                    </span>
                    {c.detail && <code className="sso-detail">{c.detail}</code>}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* ---- 3. roles */}
        <section className="card stack" aria-labelledby="sso-roles-h">
          <div className="stack-xs">
            <h2 id="sso-roles-h">{t("3. Roles")}</h2>
            <span className="muted small">
              {t(
                "Each person gets the highest role of their matching groups or roles, again at every sign-in. Red team accounts are always local.",
              )}
            </span>
          </div>
          {entra ? (
            <div className="sso-choice-row" role="radiogroup" aria-label={t("Roles come from")}>
              <span className="sso-choice-label">{t("Roles come from")}</span>
              <div className="sso-segmented">
                {(["roles", "groups"] as const).map((c) => (
                  <label key={c} className={"sso-segment" + (form.role_claim === c ? " is-on" : "")}>
                    <input
                      type="radio"
                      name="sso-claim"
                      checked={form.role_claim === c}
                      disabled={readOnly}
                      onChange={() => update({ role_claim: c })}
                    />
                    {c === "roles" ? t("App roles (recommended)") : t("Security groups")}
                  </label>
                ))}
              </div>
            </div>
          ) : (
            <label className="field">
              {t("Claim with the groups or roles")}
              <input
                className="input mono"
                value={form.role_claim}
                disabled={readOnly}
                spellCheck={false}
                maxLength={255}
                placeholder="groups"
                onChange={(e) => update({ role_claim: e.target.value })}
              />
              <span className="small muted">
                {t("For example groups or roles. A dotted path reaches nested claims, e.g. realm_access.roles.")}
              </span>
            </label>
          )}
          {entra && (
            <p className="small muted" style={{ margin: 0 }}>
              {groups
                ? t(
                    "Token configuration → Add groups claim → Security groups, ID token: Group ID. Entra ID sends group object IDs, not names (Groups → the group → Object ID). Users in more than 200 groups are looked up in Microsoft Graph.",
                  )
                : t(
                    "Create the app roles in the app registration (App roles), then assign people or groups to them under Enterprise applications → Users and groups. Enter the role values here.",
                  )}
            </p>
          )}

          <div className="stack-sm">
            {form.role_map.length === 0 && <p className="muted small" style={{ margin: 0 }}>{t("No mappings yet.")}</p>}
            {form.role_map.map((m, i) => (
              <div key={i} className="var-row">
                <label className="field grow">
                  <span className="sr-only">{groups ? t("Group object ID") : t("Group or role value")}</span>
                  <input
                    className={"input mono" + (groupNames.includes(m.value.trim()) ? " is-invalid" : "")}
                    value={m.value}
                    disabled={readOnly}
                    required
                    spellCheck={false}
                    maxLength={256}
                    placeholder={groups ? "6c1f6d32-0e0c-4a4b-9c7e-0b1d2a3c4d5e" : entra ? "Vulcan.Analyst" : "SOC-Analysts"}
                    onChange={(e) => setMapping(i, { value: e.target.value })}
                  />
                </label>
                <span aria-hidden="true">→</span>
                <label className="field">
                  <span className="sr-only">{t("App role")}</span>
                  <select
                    className="input"
                    value={m.role}
                    disabled={readOnly}
                    onChange={(e) => setMapping(i, { role: e.target.value as SsoRole })}
                  >
                    {ROLES.map((r) => (
                      <option key={r.value} value={r.value}>
                        {r.label}
                      </option>
                    ))}
                  </select>
                </label>
                {!readOnly && (
                  <button
                    type="button"
                    className="btn btn-sm"
                    aria-label={t("Remove the mapping {value}", { value: m.value })}
                    onClick={() => update({ role_map: form.role_map.filter((_, j) => j !== i) })}
                  >
                    {t("Remove")}
                  </button>
                )}
              </div>
            ))}
            {groupNames.length > 0 && (
              <span className="field-error">
                {t("Entra ID sends group object IDs, not names, so these never match: {values}", { values: groupNames.join(", ") })}
              </span>
            )}
            {!readOnly && (
              <div className="row-actions start">
                <button type="button" className="btn btn-sm" onClick={() => update({ role_map: [...form.role_map, { value: "", role: "analyst" }] })}>
                  {t("+ Add mapping")}
                </button>
                {entra && !groups && form.role_map.length === 0 && (
                  <button type="button" className="btn btn-sm" onClick={() => update({ role_map: SUGGESTED_APP_ROLES })}>
                    {t("Add Vulcan.Admin, Vulcan.Analyst and Vulcan.Auditor")}
                  </button>
                )}
              </div>
            )}
          </div>

          <label className="field sso-default-role">
            {t("Without a matching group or role")}
            <select
              className="input"
              value={form.default_role ?? ""}
              disabled={readOnly}
              onChange={(e) => update({ default_role: (e.target.value || null) as SsoRole | null })}
            >
              <option value="">{t("No access (recommended)")}</option>
              {ROLES.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </select>
          </label>
        </section>

        {/* ---- advanced */}
        <details className="card sso-advanced">
          <summary>{t("Advanced")}</summary>
          <div className="stack">
            <div className="form-grid">
              <label className="field">
                {t("Scopes")}
                <input
                  className="input mono"
                  value={form.scopes}
                  disabled={readOnly}
                  spellCheck={false}
                  maxLength={255}
                  onChange={(e) => update({ scopes: e.target.value })}
                />
              </label>
              <label className="field">
                {t("User name claim")}
                <input
                  className="input mono"
                  value={form.username_claim}
                  disabled={readOnly}
                  spellCheck={false}
                  maxLength={255}
                  onChange={(e) => update({ username_claim: e.target.value })}
                />
              </label>
              <label className="field">
                {t("Button label")}
                <input
                  className="input"
                  value={form.button_label}
                  disabled={readOnly}
                  maxLength={80}
                  placeholder={defaultLabel(form.provider)}
                  onChange={(e) => update({ button_label: e.target.value })}
                />
              </label>
            </div>
            <p className="small muted" style={{ margin: 0 }}>
              {t(
                "The user name comes from the user name claim, else from preferred_username, email or sub. Accounts are matched by the token's subject, so a renamed user keeps their account.",
              )}
            </p>
          </div>
        </details>

        {/* ---- 4. test and turn on */}
        <section className="card stack" id="sso-test" aria-labelledby="sso-test-h">
          <div className="stack-xs">
            <h2 id="sso-test-h">{t("4. Test and turn on")}</h2>
            <span className="muted small">
              {t(
                "A test sign-in shows what the identity provider sends and which role that gives. It creates no account and keeps you signed in as yourself.",
              )}
            </span>
          </div>
          <div className="row-actions start">
            <a
              className={"btn" + (canTest ? "" : " disabled")}
              href={canTest ? "/api/auth/oidc/test" : undefined}
              aria-disabled={!canTest}
              onClick={(e) => {
                if (!canTest) e.preventDefault();
              }}
            >
              {entra && <MicrosoftLogo size={16} />}
              {t("Test sign-in")}
            </a>
            {!canTest && (
              <span className="small muted">
                {dirty ? t("Save your changes first.") : t("Fill in step 2 and save first.")}
              </span>
            )}
          </div>
          <ErrorNote error={test.error} />
          {test.data && <TestResult r={test.data} />}

          <div className="stack-xs">
            <label className="check">
              <input type="checkbox" checked={form.enabled} disabled={readOnly} onChange={(e) => update({ enabled: e.target.checked })} />
              {t("Show “{label}” on the sign-in page", { label })}
            </label>
            <span className="small muted">
              {t("Local accounts keep working unless LOCAL_LOGIN_ENABLED=false, so an admin can always sign in.")}
            </span>
          </div>
        </section>

        <ErrorNote error={error} />
        <div className="row-actions sso-save">
          {s.updated_by && s.updated_at && (
            <span className="small muted grow">
              {t("Last changed by {user} on {date}", { user: s.updated_by, date: fmtDate(s.updated_at) })}
            </span>
          )}
          {notice && (
            <span className="saved-tick" role="status">
              {notice}
            </span>
          )}
          {!readOnly && (
            <button type="submit" className="btn btn-primary" disabled={busy || !dirty}>
              {t("Save")}
            </button>
          )}
        </div>
      </form>
    </>
  );
}
