import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type CampaignAccount, type CampaignRow } from "../api";
import { useAuth } from "../auth";
import { ErrorNote, Modal, useLoad } from "../components/ui";
import { fmtDate } from "../lib/format";
import { CAMPAIGN_LABEL, CAMPAIGN_PILL, OUTCOMES, OUTCOME_LABEL, OUTCOME_PILL } from "../lib/tests";
import { t } from "../i18n";

export default function Campaigns() {
  const { user, can } = useAuth();
  const editor = can("admin", "analyst");
  const list = useLoad<CampaignRow[]>(() => api.campaigns());
  const [creating, setCreating] = useState(false);
  const red = user?.role === "red_team";
  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Campaigns")}</h1>
          <div className="subtitle">
            {red
              ? t("The campaigns you are assigned to.")
              : t("Planned test scenarios. The red team runs the tests, the blue team records the results.")}
          </div>
        </div>
        {editor && (
          <div className="row-actions">
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              {t("+ New campaign")}
            </button>
          </div>
        )}
      </header>
      <ErrorNote error={list.error} />
      {list.data && !list.data.length && (
        <div className="empty">
          <h3>{red ? t("No campaign is assigned to you yet.") : t("No campaigns yet")}</h3>
          {!red && (
            <p>
              {t("A campaign groups the tests of a scenario. For a single test without planning, use a quick test.")}
            </p>
          )}
          {editor && (
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              {t("+ New campaign")}
            </button>
          )}
        </div>
      )}
      {list.data && list.data.length > 0 && (
        <section className="card table-card">
          <div className="scroll-x">
            <table className="table">
              <thead>
                <tr>
                  <th>{t("Campaign")}</th>
                  <th>{t("Status")}</th>
                  <th>{t("Planned")}</th>
                  <th className="num">{t("Tests")}</th>
                  <th>{t("Results")}</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <Link to={`/verification/campaigns/${c.id}`} className="strong-500">
                        {c.name}
                      </Link>
                      {c.open_points > 0 && (
                        <div className="small">
                          <span className="pill pill-fair">{t("{n} to link", { n: c.open_points })}</span>
                        </div>
                      )}
                    </td>
                    <td>
                      <span className={`pill ${CAMPAIGN_PILL[c.status]}`}>{CAMPAIGN_LABEL[c.status]}</span>
                    </td>
                    <td className="small">
                      {fmtDate(c.planned_start)} – {fmtDate(c.planned_end)}
                    </td>
                    <td className="num">{c.tests}</td>
                    <td>
                      {c.outcomes ? (
                        <span className="outcome-counts">
                          {OUTCOMES.filter((o) => c.outcomes![o] > 0).map((o) => (
                            <span key={o} className={`pill ${OUTCOME_PILL[o]}`}>
                              {OUTCOME_LABEL[o]} {c.outcomes![o]}
                            </span>
                          ))}
                          {OUTCOMES.every((o) => c.outcomes![o] === 0) && <span className="muted">–</span>}
                        </span>
                      ) : (
                        <span className="muted small">{t("Shown when the campaign is closed")}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      {creating && <CampaignDialog campaign={null} onClose={() => setCreating(false)} />}
    </>
  );
}

export function CampaignDialog({
  campaign,
  onClose,
  onSaved,
}: {
  campaign: CampaignRow | null;
  onClose: () => void;
  onSaved?: () => void;
}) {
  const navigate = useNavigate();
  const accounts = useLoad<CampaignAccount[]>(() => api.redTeamAccounts());
  const [form, setForm] = useState({
    name: campaign?.name ?? "",
    description: campaign?.description ?? "",
    planned_start: campaign?.planned_start ?? new Date().toISOString().slice(0, 10),
    planned_end: campaign?.planned_end ?? "",
    account_ids: campaign?.accounts.map((a) => a.id) ?? ([] as number[]),
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (campaign) {
        await api.updateCampaign(campaign.id, form);
        onSaved?.();
        onClose();
      } else {
        const c = await api.createCampaign(form);
        navigate(`/verification/campaigns/${c.id}`);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title={campaign ? t("Change campaign") : t("New campaign")} open onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error} />
        <label className="field">
          {t("Name")} *
          <input className="input" required maxLength={200} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </label>
        <div className="form-grid">
          <label className="field">
            {t("Planned start")} *
            <input className="input" type="date" required value={form.planned_start} onChange={(e) => setForm({ ...form, planned_start: e.target.value })} />
          </label>
          <label className="field">
            {t("Planned end")} *
            <input className="input" type="date" required min={form.planned_start} value={form.planned_end} onChange={(e) => setForm({ ...form, planned_end: e.target.value })} />
          </label>
        </div>
        <label className="field">
          {t("Description (optional)")}
          <textarea className="input textarea" rows={3} maxLength={10000} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </label>
        <fieldset className="fieldset">
          <legend>{t("Red team accounts")}</legend>
          {accounts.data && !accounts.data.length && (
            <p className="muted small">{t("There are no red team accounts yet. An admin creates them on the Users page.")}</p>
          )}
          {accounts.data?.map((a) => (
            <label key={a.id} className="check">
              <input
                type="checkbox"
                checked={form.account_ids.includes(a.id)}
                onChange={(e) =>
                  setForm({ ...form, account_ids: e.target.checked ? [...form.account_ids, a.id] : form.account_ids.filter((x) => x !== a.id) })
                }
              />
              {a.display_name || a.username} <span className="muted small mono">{a.username}</span>
            </label>
          ))}
        </fieldset>
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>{t("Cancel")}</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{t("Save")}</button>
        </div>
      </form>
    </Modal>
  );
}
