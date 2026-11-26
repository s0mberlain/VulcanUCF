import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, REQUEST_STATUSES, type RequestState, type RequestStatus } from "../api";
import { t } from "../i18n";
import { fmtTime } from "../lib/format";
import { Markdown } from "./Markdown";
import { ErrorNote, Modal } from "./ui";

/** Detection request status (PROJ-1): chip, details and the dialog that changes it. */

export const statusLabel = (s: RequestStatus): string =>
  ({
    open: t("Open"),
    in_progress: t("In progress"),
    implemented: t("Implemented"),
    rejected: t("Rejected"),
    not_feasible: t("Not feasible"),
  })[s];

/** The statuses that need a reason. */
export const needsNote = (s: RequestStatus) => s === "rejected" || s === "not_feasible";

export function StatusChip({ status }: { status: RequestStatus }) {
  return <span className={`pill req-status-${status}`}>{statusLabel(status)}</span>;
}

/** Reason, what implemented the request and who changed the status last. */
export function StatusDetails({ r }: { r: RequestState }) {
  const link = r.link;
  if (!r.status_note && !link && !r.status_by) return null;
  return (
    <div className="req-status-details small muted">
      {r.status_note && <div className="req-note">{r.status_note}</div>}
      {link && (
        <div>
          {t("Implemented by")}{" "}
          {link.deleted ? (
            <span>
              {link.code} ({t("deleted")})
            </span>
          ) : (
            <Link to={link.l3_id ? `/usecases/l3/${encodeURIComponent(link.code)}` : `/usecases?l2=${encodeURIComponent(link.code)}`}>
              {link.code}
            </Link>
          )}
        </div>
      )}
      {r.status_by && (
        <div>{t("Last changed by {user} on {time}", { user: r.status_by, time: fmtTime(r.status_at) })}</div>
      )}
    </div>
  );
}

/** Resolves a use case code the analyst typed: an L3 rule (AO-ACC-02) or an L2 use case (AO-ACC). */
async function resolveLink(code: string): Promise<{ l2_id?: number; l3_id?: number }> {
  const c = code.trim().toUpperCase();
  try {
    if (c.split("-").length >= 3) return { l3_id: (await api.l3(c)).id };
    return { l2_id: (await api.l2(c)).id };
  } catch {
    throw new Error(t("There is no use case or rule with the code {code}.", { code: c }));
  }
}

export function StatusDialog({
  systemId,
  title,
  current,
  onClose,
  onSaved,
}: {
  systemId: number;
  /** request key and title */
  title: { key: string; title: string };
  current: RequestState;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [status, setStatus] = useState<RequestStatus>(current.status);
  const [note, setNote] = useState(current.status_note);
  const [code, setCode] = useState(current.link?.code ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const noteMissing = needsNote(status) && !note.trim();

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const link = status === "implemented" && code.trim() ? await resolveLink(code) : {};
      await api.setRequestStatus(systemId, title.key, { status, note: note.trim(), ...link });
      onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={t("Status of the detection request")} open onClose={onClose}>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (!noteMissing) void submit();
        }}
      >
        <p style={{ margin: 0 }} className="strong">
          {title.title}
        </p>
        <label className="field">
          {t("Status")}
          <select className="input" value={status} onChange={(e) => setStatus(e.target.value as RequestStatus)}>
            {REQUEST_STATUSES.map((s) => (
              <option key={s} value={s}>
                {statusLabel(s)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          {needsNote(status) ? t("Reason (required)") : t("Note (optional)")}
          <textarea
            className="textarea"
            rows={3}
            maxLength={2000}
            value={note}
            aria-invalid={noteMissing}
            onChange={(e) => setNote(e.target.value)}
          />
        </label>
        {status === "implemented" && (
          <label className="field">
            {t("Implemented by (code of the use case or rule, optional)")}
            <input className="input" value={code} maxLength={64} placeholder="AO-ACC-02" onChange={(e) => setCode(e.target.value)} />
          </label>
        )}
        {status !== "implemented" && current.link && (
          <p className="small muted" style={{ margin: 0 }}>
            {t("The link to {code} is removed.", { code: current.link.code })}
          </p>
        )}
        <ErrorNote error={error} />
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy || noteMissing}>
            {t("Save")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Still to do: the request counts as a gap. */
export const isTodo = (s: RequestStatus) => s === "open" || s === "in_progress";

/**
 * One detection request as a card, like the use case cards of the interview: title and status in
 * the head, threat and description below, then reason, link and who changed it. `actions` are
 * more buttons for the head (edit, remove).
 */
export function RequestCard({
  systemId,
  r,
  where,
  canSetStatus,
  onChanged,
  actions,
}: {
  systemId: number;
  r: RequestState & { key: string; title: string; description: string };
  /** component and threat, e.g. "Web front end / Spoofing" */
  where: string;
  canSetStatus: boolean;
  onChanged: () => void;
  actions?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const long = r.description.length > 200 || r.description.split("\n").length > 3;
  return (
    <div className={"iv-proposal req-card" + (isTodo(r.status) ? "" : " req-closed")}>
      <div className="iv-proposal-head">
        <span className="req-title">{r.title}</span>
        <span className="grow" />
        <StatusChip status={r.status} />
      </div>
      <div className="small muted">
        {t("Threat")}: {where}
      </div>
      {r.description &&
        (long ? (
          <details className="req-more">
            <summary className="small">{t("Description")}</summary>
            <Markdown text={r.description} className="req-desc small" />
          </details>
        ) : (
          <Markdown text={r.description} className="req-desc small" />
        ))}
      <StatusDetails r={r} />
      {(canSetStatus || actions) && (
        <div className="row-actions start">
          {canSetStatus && (
            <button type="button" className="btn btn-sm" onClick={() => setOpen(true)}>
              {t("Change status")}
            </button>
          )}
          {actions}
        </div>
      )}
      {open && (
        <StatusDialog
          systemId={systemId}
          title={{ key: r.key, title: r.title }}
          current={r}
          onClose={() => setOpen(false)}
          onSaved={onChanged}
        />
      )}
    </div>
  );
}
