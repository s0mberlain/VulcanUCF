import { useState, type FormEvent } from "react";
import { api, type TotpSetup } from "../api";
import { useAuth } from "../auth";
import { ErrorNote } from "../components/ui";
import { fmtDate } from "../lib/format";
import { t } from "../i18n";

const ROLE_TEXT = {
  admin: "Admin: manages users and everything else.",
  analyst: "Analyst: edits use cases, rules, configs and verifications.",
  auditor: "Auditor: reads everything, changes nothing.",
  red_team: "Red team: runs the tests of the campaigns it is assigned to.",
};

export default function Account() {
  const { user } = useAuth();
  if (!user) return null;
  const local = user.auth_source === "local";
  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Account")}</h1>
          <div className="subtitle">
            {user.display_name || user.username} · {local ? t("local account") : t("single sign-on")}
          </div>
        </div>
      </header>
      <div className="account-grid">
        <div className="stack-lg">
          <section className="card stack" aria-labelledby="who">
            <h2 id="who">{t("Profile")}</h2>
            <dl className="facts">
              <dt>{t("Username")}</dt>
              <dd className="mono">{user.username}</dd>
              <dt>{t("Role")}</dt>
              <dd>{ROLE_TEXT[user.role]}</dd>
              <dt>{t("Sign-in")}</dt>
              <dd>{local ? t("Username and password") : t("Your organisation's identity provider")}</dd>
              <dt>{t("Last sign-in")}</dt>
              <dd>{fmtDate(user.last_login_at)}</dd>
            </dl>
          </section>
          {local && <PasswordCard />}
        </div>
        {local ? (
          <TwoFactor />
        ) : (
          <section className="card stack">
            <h2>{t("Password and two-factor login")}</h2>
            <p className="muted" style={{ margin: 0 }}>
              {t("Your password and second factor are managed by your identity provider.")}
            </p>
          </section>
        )}
      </div>
    </>
  );
}

function PasswordCard() {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setDone(false);
    if (next !== again) {
      setError(t("The new passwords do not match."));
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(cur, next);
      setDone(true);
      setCur("");
      setNext("");
      setAgain("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card stack" aria-labelledby="pw">
      <h2 id="pw">{t("Password")}</h2>
      <form className="stack" onSubmit={submit}>
        <label className="field">
          {t("Current password")}
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            required
            value={cur}
            onChange={(e) => setCur(e.target.value)}
          />
        </label>
        <div className="form-grid two">
          <label className="field">
            {t("New password")}
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
          </label>
          <label className="field">
            {t("Repeat new password")}
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              required
              value={again}
              onChange={(e) => setAgain(e.target.value)}
            />
          </label>
        </div>
        <ErrorNote error={error} />
        {done && <p className="text-ok small">{t("Password changed.")}</p>}
        <div className="row-actions start">
          <button type="submit" className="btn" disabled={busy}>
            {t("Change password")}
          </button>
        </div>
      </form>
    </section>
  );
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const text = codes.join("\n");
  return (
    <div className="stack-sm">
      <div className="form-notice stack-xs">
        <strong>{t("Save these recovery codes now.")}</strong>
        <span>{t("Each code signs you in once if you lose your phone. They are not shown again.")}</span>
      </div>
      <ul className="recovery-codes mono">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="row-actions start">
        <button type="button" className="btn" onClick={() => void navigator.clipboard?.writeText(text)}>
          {t("Copy")}
        </button>
        <a
          className="btn"
          download="magma-recovery-codes.txt"
          href={`data:text/plain;charset=utf-8,${encodeURIComponent(text + "\n")}`}
        >
          {t("Download .txt")}
        </a>
        <button type="button" className="btn btn-primary" onClick={onDone}>
          {t("I saved them")}
        </button>
      </div>
    </div>
  );
}

function TwoFactor() {
  const { user, refresh } = useAuth();
  const [step, setStep] = useState<"idle" | "password" | "scan" | "codes" | "manage">("idle");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const on = !!user?.totp_enabled;

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const reset = () => {
    setStep("idle");
    setPassword("");
    setCode("");
    setSetup(null);
  };

  return (
    <section className="card stack" aria-labelledby="tf">
      <div className="section-head">
        <h2 id="tf">{t("Two-factor login")}</h2>
        <span className={on ? "pill pill-ok" : "pill pill-warn"}>{on ? t("On") : t("Off")}</span>
      </div>
      <ErrorNote error={error} />

      {step === "codes" && (
        <RecoveryCodes
          codes={codes}
          onDone={() => {
            setCodes([]);
            reset();
          }}
        />
      )}

      {!on && step === "idle" && (
        <>
          <p className="muted" style={{ margin: 0 }}>
            {t(
              "Ask for a 6-digit code from an authenticator app (for example Microsoft Authenticator, Google Authenticator, 1Password or Aegis) in addition to your password.",
            )}
          </p>
          <div className="row-actions start">
            <button type="button" className="btn btn-primary" onClick={() => setStep("password")}>
              {t("Set up")}
            </button>
          </div>
        </>
      )}

      {!on && step === "password" && (
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              setSetup(await api.totpSetup(password));
              setPassword("");
              setStep("scan");
            });
          }}
        >
          <label className="field">
            {t("Confirm with your password")}
            <input
              className="input"
              type="password"
              autoComplete="current-password"
              required
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <div className="row-actions start">
            <button type="button" className="btn" onClick={reset}>
              {t("Cancel")}
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {t("Continue")}
            </button>
          </div>
        </form>
      )}

      {!on && step === "scan" && setup && (
        <form
          className="totp-setup"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              const r = await api.totpEnable(code);
              setCodes(r.recovery_codes);
              setCode("");
              setStep("codes");
              await refresh();
            });
          }}
        >
          <div className="qr" dangerouslySetInnerHTML={{ __html: setup.qr_svg }} aria-label={t("QR code to scan")} />
          <div className="stack-sm">
            <ol className="steps">
              <li>{t("Scan the QR code with your authenticator app.")}</li>
              <li>
                {t("Or type this key:")}{" "}
                <span className="mono key">{setup.secret.replace(/(.{4})/g, "$1 ").trim()}</span>
              </li>
              <li>{t("Enter the 6-digit code the app shows.")}</li>
            </ol>
            <label className="field">
              {t("Code")}
              <input
                className="input mono"
                inputMode="numeric"
                autoComplete="one-time-code"
                required
                autoFocus
                maxLength={7}
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </label>
            <div className="row-actions start">
              <button type="button" className="btn" onClick={reset}>
                {t("Cancel")}
              </button>
              <button type="submit" className="btn btn-primary" disabled={busy}>
                {t("Turn on")}
              </button>
            </div>
          </div>
        </form>
      )}

      {on && step !== "codes" && (
        <>
          <p className="muted" style={{ margin: 0 }}>
            {t(
              "You sign in with your password and a code from your authenticator app. Changing this needs your password and a current code (or a recovery code).",
            )}
          </p>
          {step !== "manage" ? (
            <div className="row-actions start">
              <button type="button" className="btn" onClick={() => setStep("manage")}>
                {t("Manage")}
              </button>
            </div>
          ) : (
            <form className="stack" onSubmit={(e) => e.preventDefault()}>
              <div className="form-grid two">
                <label className="field">
                  {t("Password")}
                  <input
                    className="input"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </label>
                <label className="field">
                  {t("Code")}
                  <input
                    className="input mono"
                    autoComplete="one-time-code"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                  />
                </label>
              </div>
              <div className="row-actions start">
                <button type="button" className="btn" onClick={reset}>
                  {t("Cancel")}
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={busy || !password || !code}
                  onClick={() =>
                    void run(async () => {
                      const r = await api.totpNewCodes(password, code);
                      setCodes(r.recovery_codes);
                      setPassword("");
                      setCode("");
                      setStep("codes");
                    })
                  }
                >
                  {t("New recovery codes")}
                </button>
                <button
                  type="button"
                  className="btn btn-danger"
                  disabled={busy || !password || !code}
                  onClick={() =>
                    void run(async () => {
                      await api.totpDisable(password, code);
                      reset();
                      await refresh();
                    })
                  }
                >
                  {t("Turn off")}
                </button>
              </div>
            </form>
          )}
        </>
      )}
    </section>
  );
}
