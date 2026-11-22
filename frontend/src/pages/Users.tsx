import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type Role, type User } from "../api";
import { ROLE_LABEL, useAuth } from "../auth";
import { confirmDialog, ErrorNote, Modal } from "../components/ui";
import { locale, t } from "../i18n";

const ROLES: Role[] = ["admin", "analyst", "auditor", "red_team"];

function fmt(ts: string | null): string {
  return ts ? new Date(ts).toLocaleString(locale()) : t("never");
}

export default function Users() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pwUser, setPwUser] = useState<User | null>(null);
  const [form, setForm] = useState({
    username: "",
    display_name: "",
    role: "analyst" as Role,
    password: "",
    follows: true,
    expires: "",
  });
  const [expiryUser, setExpiryUser] = useState<User | null>(null);

  const reload = useCallback(() => {
    api
      .users()
      .then(setUsers)
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(reload, [reload]);

  async function run(action: () => Promise<unknown>, ok: string) {
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(ok);
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("Failed"));
    }
  }

  async function create(e: FormEvent) {
    e.preventDefault();
    const red = form.role === "red_team";
    await run(
      () =>
        api.createUser({
          username: form.username,
          display_name: form.display_name,
          role: form.role,
          password: form.password,
          ...(red
            ? { expiry_follows_campaign: form.follows, expires_at: form.expires ? new Date(form.expires + "T23:59:59").toISOString() : null }
            : {}),
        }),
      t("User {user} created", { user: form.username }),
    );
    setForm({ username: "", display_name: "", role: "analyst", password: "", follows: true, expires: "" });
  }

  async function changeRole(u: User, role: Role) {
    const ok = await confirmDialog(
      t("Change the role of {user} from {old} to {new}? They are signed out everywhere and sign in again with the new role.", {
        user: u.username,
        old: ROLE_LABEL[u.role],
        new: ROLE_LABEL[role],
      }),
      { title: t("Change role"), confirmLabel: t("Change role") },
    );
    if (ok) await run(() => api.updateUser(u.id, { role }), t("Role of {user} changed", { user: u.username }));
  }

  async function toggleActive(u: User) {
    if (u.active) {
      const ok = await confirmDialog(
        t("Disable {user}? They are signed out and cannot sign in until the account is enabled again.", {
          user: u.username,
        }),
        { title: t("Disable account"), confirmLabel: t("Disable"), danger: true },
      );
      if (!ok) return;
    }
    await run(
      () => api.updateUser(u.id, { active: !u.active }),
      u.active ? t("{user} disabled", { user: u.username }) : t("{user} enabled", { user: u.username }),
    );
  }

  async function remove(u: User) {
    const ok = await confirmDialog(
      t("Delete the account {user}? What they did stays in the audit log under their name. This cannot be undone; to only block the sign-in, disable the account instead.", {
        user: u.username,
      }),
      { title: t("Delete account"), confirmLabel: t("Delete"), danger: true },
    );
    if (ok) await run(() => api.deleteUser(u.id), t("{user} deleted", { user: u.username }));
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Users")}</h1>
          <div className="subtitle">
            {t(
              "Local accounts and roles. SSO users appear after their first login; their role comes from the IdP groups and is updated at every sign-in.",
            )}
          </div>
        </div>
      </header>

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="form-notice" role="status">
          {notice}
        </p>
      )}

      <section className="card table-card" aria-label={t("User list")}>
        <table className="table">
          <thead>
            <tr>
              <th>{t("User")}</th>
              <th>{t("Role")}</th>
              <th>{t("Login")}</th>
              <th>{t("Last login")}</th>
              <th>{t("Status")}</th>
              <th aria-label={t("Actions")} />
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>
                  <div style={{ fontWeight: 600 }}>{u.display_name || u.username}</div>
                  <div className="muted mono" style={{ fontSize: 12 }}>
                    {u.username}
                  </div>
                </td>
                <td>
                  <label className="sr-only" htmlFor={`role-${u.id}`}>
                    {t("Role of")} {u.username}
                  </label>
                  <select
                    id={`role-${u.id}`}
                    className="input input-sm"
                    value={u.role}
                    disabled={u.auth_source === "sso"}
                    title={
                      u.auth_source === "sso"
                        ? t("The role of an SSO account comes from the groups at the identity provider")
                        : undefined
                    }
                    onChange={(e) => void changeRole(u, e.target.value as Role)}
                  >
                    {ROLES.filter((r) => r !== "red_team" || u.role === "red_team").map((r) => (
                      <option key={r} value={r} disabled={r === "red_team"}>
                        {ROLE_LABEL[r]}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  {u.auth_source === "sso" ? "SSO" : u.auth_source === "service" ? t("API token") : t("Local")}
                  {u.totp_enabled && <span className="chip chip-info chip-2fa">2FA</span>}
                </td>
                <td>{fmt(u.last_login_at)}</td>
                <td>
                  <span className={"pill " + (u.active ? "pill-ok" : "pill-warn")}>
                    {u.active ? t("Active") : t("Disabled")}
                  </span>
                  {u.role === "red_team" && (
                    <div className="small" style={{ marginTop: 6 }}>
                      {u.effective_expires_at && new Date(u.effective_expires_at) < new Date() ? (
                        <span className="pill pill-poor">{t("Expired {date}", { date: fmt(u.effective_expires_at).split(",")[0] ?? "" })}</span>
                      ) : (
                        <span className="muted">
                          {u.effective_expires_at ? t("Ends {date}", { date: fmt(u.effective_expires_at).split(",")[0] ?? "" }) : t("No end date")}
                        </span>
                      )}{" "}
                      <span className="muted">· {u.expiry_follows_campaign ? t("follows the campaign") : t("fixed")}</span>
                    </div>
                  )}
                </td>
                <td>
                  <div className="row-actions">
                    {u.role === "red_team" && (
                      <button type="button" className="btn btn-sm" onClick={() => setExpiryUser(u)}>
                        {t("Change expiry")}
                      </button>
                    )}
                    {u.auth_source === "local" && (
                      <button type="button" className="btn btn-sm" onClick={() => setPwUser(u)}>
                        {t("Reset password")}
                      </button>
                    )}
                    {u.totp_enabled && u.id !== me?.id && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={async () => {
                          const ok = await confirmDialog(
                            t("Turn off two-factor login for {user}?", { user: u.username }),
                            { title: t("Reset 2FA"), confirmLabel: t("Turn off"), danger: true },
                          );
                          if (ok)
                            void run(
                              () => api.resetTotp(u.id),
                              t("Two-factor login of {user} turned off", { user: u.username }),
                            );
                        }}
                      >
                        {t("Reset 2FA")}
                      </button>
                    )}
                    {u.id !== me?.id && (
                      <button type="button" className="btn btn-sm" onClick={() => void toggleActive(u)}>
                        {u.active ? t("Disable") : t("Enable")}
                      </button>
                    )}
                    {u.id !== me?.id && (
                      <button type="button" className="btn btn-sm btn-danger" onClick={() => void remove(u)}>
                        {t("Delete")}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card" aria-labelledby="new-user">
        <h2 id="new-user" style={{ marginBottom: 14 }}>
          {t("Add local user")}
        </h2>
        <form className="form-grid" onSubmit={create}>
          <label className="field">
            {t("Username")}
            <input
              className="input"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              required
              pattern="[A-Za-z0-9._@\-]{2,64}"
            />
          </label>
          <label className="field">
            {t("Display name")}
            <input
              className="input"
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
            />
          </label>
          <label className="field">
            {t("Role")}
            <select
              className="input"
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value as Role })}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            {t("Initial password")}
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              minLength={12}
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              required
            />
          </label>
          {form.role === "red_team" && (
            <fieldset className="fieldset" style={{ gridColumn: "1 / -1" }}>
              <legend>{t("Account ends")}</legend>
              <label className="check">
                <input type="radio" name="expiry" checked={form.follows} onChange={() => setForm({ ...form, follows: true })} />
                {t("When the assigned campaigns end (set as soon as a campaign is assigned)")}
              </label>
              <label className="check">
                <input type="radio" name="expiry" checked={!form.follows} onChange={() => setForm({ ...form, follows: false })} />
                {t("On a fixed date")}
              </label>
              <label className="field">
                {form.follows ? t("Until a campaign is assigned, the account ends on") : t("Date")} *
                <input className="input" type="date" required value={form.expires} onChange={(e) => setForm({ ...form, expires: e.target.value })} />
              </label>
            </fieldset>
          )}
          <div style={{ display: "flex", alignItems: "flex-end" }}>
            <button type="submit" className="btn btn-primary">
              {t("Add user")}
            </button>
          </div>
        </form>
      </section>

      {expiryUser && (
        <ExpiryDialog
          user={expiryUser}
          onClose={() => setExpiryUser(null)}
          onSaved={() => {
            setNotice(t("Expiry of {user} changed", { user: expiryUser.username }));
            reload();
          }}
        />
      )}
      {pwUser && (
        <PasswordDialog
          user={pwUser}
          onClose={() => setPwUser(null)}
          onSaved={() => {
            setNotice(t("Password of {user} changed", { user: pwUser.username }));
            reload();
          }}
        />
      )}
    </>
  );
}

/** Set a new password for someone: typed twice and hidden, instead of a browser prompt. */
function PasswordDialog({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const [pw, setPw] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (pw !== again) {
      setError(t("The two passwords are not the same."));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.updateUser(user.id, { password: pw });
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={t("Reset password of {user}", { user: user.username })} open onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <p className="muted" style={{ margin: 0 }}>
          {t("The account is unlocked and signed out everywhere. Give the new password to the person in a safe way.")}
        </p>
        <ErrorNote error={error} />
        <label className="field">
          {t("New password (at least 12 characters)")}
          <input
            className="input"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
            autoFocus
            value={pw}
            onChange={(e) => setPw(e.target.value)}
          />
        </label>
        <label className="field">
          {t("Repeat the password")}
          <input
            className="input"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
            value={again}
            onChange={(e) => setAgain(e.target.value)}
          />
        </label>
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? t("Saving…") : t("Set password")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ExpiryDialog({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const [follows, setFollows] = useState(!!user.expiry_follows_campaign);
  const [date, setDate] = useState((user.expires_at ?? user.effective_expires_at ?? "").slice(0, 10));
  const [error, setError] = useState<string | null>(null);
  const past = !!date && new Date(date + "T23:59:59") < new Date();
  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await api.updateUser(user.id, {
        expiry_follows_campaign: follows,
        ...(date ? { expires_at: new Date(date + "T23:59:59").toISOString() } : {}),
      });
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <Modal title={t("Expiry of {user}", { user: user.username })} open onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error} />
        <label className="check">
          <input type="radio" name="follows" checked={follows} onChange={() => setFollows(true)} />
          {t("Follow the assigned campaigns (latest planned end)")}
        </label>
        <label className="check">
          <input type="radio" name="follows" checked={!follows} onChange={() => setFollows(false)} />
          {t("Fixed date")}
        </label>
        <label className="field">
          {follows ? t("Used until a campaign is assigned") : t("Date")}
          <input className="input" type="date" required={!follows} value={date} onChange={(e) => setDate(e.target.value)} />
        </label>
        {past && <p className="form-error" role="status">{t("This date is in the past: the account is locked at once.")}</p>}
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>{t("Cancel")}</button>
          <button type="submit" className="btn btn-primary">{t("Save")}</button>
        </div>
      </form>
    </Modal>
  );
}
