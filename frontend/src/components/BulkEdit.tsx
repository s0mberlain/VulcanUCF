import { useState, type FormEvent } from "react";
import {
  api,
  LIFECYCLES,
  type BulkL2Update,
  type BulkResult,
  type BusinessDriver,
  type ComplianceSource,
  type Lifecycle,
  type LifecycleMeta,
} from "../api";
import { STATUS_LABEL } from "../lib/format";
import { businessOptions, complianceOptions } from "./Drivers";
import { DRIVER_TYPE_LABEL, loadMeta } from "./LifecyclePanel";
import { ErrorNote, Modal, MultiSelect, useLoad } from "./ui";
import { t } from "../i18n";
import { translateServer } from "../serverTexts";

export type BulkAction = "fields" | "lifecycle" | "verify";

/** Bar under the use case tree while L2 use cases are selected (issue #73). */
export function BulkBar({
  count,
  onAction,
  onClear,
}: {
  count: number;
  onAction: (a: BulkAction) => void;
  onClear: () => void;
}) {
  return (
    <div className="bulk-bar" role="region" aria-label={t("Bulk edit")}>
      <strong aria-live="polite">{t("{n} selected", { n: count })}</strong>
      <button type="button" className="link-btn small" disabled={!count} onClick={onClear}>
        {t("Clear selection")}
      </button>
      <span className="bulk-break" />
      <button type="button" className="btn btn-sm" disabled={!count} onClick={() => onAction("fields")}>
        {t("Edit fields")}
      </button>
      <button type="button" className="btn btn-sm" disabled={!count} onClick={() => onAction("lifecycle")}>
        {t("Change status")}
      </button>
      <button type="button" className="btn btn-sm" disabled={!count} onClick={() => onAction("verify")}>
        {t("Verify")}
      </button>
    </div>
  );
}

/** Result list after a bulk change: what was changed and what was skipped, with the reason. */
function Results({ result, onClose }: { result: BulkResult; onClose: () => void }) {
  const failed = result.results.filter((r) => !r.ok);
  return (
    <div className="stack">
      <p className="form-notice" role="status">
        {t("{n} use cases changed.", { n: result.changed })}
        {failed.length > 0 && " " + t("{n} skipped:", { n: failed.length })}
      </p>
      {failed.length > 0 && (
        <ul className="bulk-failed">
          {failed.map((r) => (
            <li key={r.code}>
              <span className="mono">{r.code}</span> · {translateServer(r.error ?? "").replace(`${r.code} `, "")}
            </li>
          ))}
        </ul>
      )}
      <div className="row-actions">
        <button type="button" className="btn btn-primary" onClick={onClose}>
          {t("Close")}
        </button>
      </div>
    </div>
  );
}

const KEEP = "__keep";

/** One dialog for the three bulk actions on the selected L2 use cases. */
export function BulkDialog({
  action,
  codes,
  drivers,
  sources,
  onClose,
  onSaved,
}: {
  action: BulkAction;
  codes: string[];
  drivers: BusinessDriver[];
  sources: ComplianceSource[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<BulkResult | null>(null);
  const title =
    action === "fields"
      ? t("Edit {n} use cases", { n: codes.length })
      : action === "lifecycle"
        ? t("Change status of {n} use cases", { n: codes.length })
        : t("Verify {n} use cases", { n: codes.length });

  async function run(call: () => Promise<BulkResult>) {
    setBusy(true);
    setError(null);
    try {
      const r = await call();
      setResult(r);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={title} open onClose={onClose}>
      {result ? (
        <Results result={result} onClose={onClose} />
      ) : (
        <>
          <p className="muted small bulk-codes">{codes.join(", ")}</p>
          <ErrorNote error={error} />
          {action === "fields" && (
            <FieldsForm drivers={drivers} sources={sources} busy={busy} onCancel={onClose} onSubmit={(b) => run(() => api.bulkUpdateL2({ ...b, codes }))} />
          )}
          {action === "lifecycle" && (
            <LifecycleForm busy={busy} onCancel={onClose} onSubmit={(b) => run(() => api.bulkLifecycleL2({ ...b, codes }))} />
          )}
          {action === "verify" && (
            <VerifyForm busy={busy} onCancel={onClose} onSubmit={(b) => run(() => api.bulkVerifyL2({ ...b, codes }))} />
          )}
        </>
      )}
    </Modal>
  );
}

function Actions({ busy, disabled, label, onCancel }: { busy: boolean; disabled?: boolean; label: string; onCancel: () => void }) {
  return (
    <div className="row-actions">
      <button type="button" className="btn" onClick={onCancel}>
        {t("Cancel")}
      </button>
      <button type="submit" className="btn btn-primary" disabled={busy || disabled}>
        {busy ? t("Saving…") : label}
      </button>
    </div>
  );
}

function FieldsForm({
  drivers,
  sources,
  busy,
  onCancel,
  onSubmit,
}: {
  drivers: BusinessDriver[];
  sources: ComplianceSource[];
  busy: boolean;
  onCancel: () => void;
  onSubmit: (b: Omit<BulkL2Update, "codes">) => void;
}) {
  const actors = useLoad(() => api.refs("threat_actor"));
  const [risk, setRisk] = useState(KEEP);
  const [target, setTarget] = useState(KEEP);
  const [targetValue, setTargetValue] = useState("");
  const [bdAdd, setBdAdd] = useState<string[]>([]);
  const [bdRemove, setBdRemove] = useState<string[]>([]);
  const [cdAdd, setCdAdd] = useState<string[]>([]);
  const [cdRemove, setCdRemove] = useState<string[]>([]);
  const [taAdd, setTaAdd] = useState<string[]>([]);
  const [taRemove, setTaRemove] = useState<string[]>([]);
  const actorOptions = (actors.data ?? []).map((a) => ({ value: a.name, label: a.name }));

  const body: Omit<BulkL2Update, "codes"> = {};
  if (risk !== KEEP) body.risk_level = risk ? Number(risk) : null;
  if (target === "set" && targetValue !== "") body.target_implementation = Number(targetValue) / 100;
  if (target === "clear") body.target_implementation = null;
  if (bdAdd.length || bdRemove.length) body.business_drivers = { add: bdAdd, remove: bdRemove };
  if (cdAdd.length || cdRemove.length)
    body.compliance_driver_ids = { add: cdAdd.map(Number), remove: cdRemove.map(Number) };
  if (taAdd.length || taRemove.length) body.actors = { add: taAdd, remove: taRemove };
  const empty = Object.keys(body).length === 0;

  return (
    <form
      className="stack"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        onSubmit(body);
      }}
    >
      <p className="muted small">{t("Only what you change here is applied. Lists keep their other entries.")}</p>
      <div className="form-grid">
        <label className="field">
          {t("Risk level (1–5)")}
          <select className="input" value={risk} onChange={(e) => setRisk(e.target.value)}>
            <option value={KEEP}>{t("Keep as is")}</option>
            <option value="">{t("Not set")}</option>
            {[1, 2, 3, 4, 5].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          {t("Target implementation (%)")}
          <span className="row">
            <select className="input" value={target} onChange={(e) => setTarget(e.target.value)} aria-label={t("Target implementation")}>
              <option value={KEEP}>{t("Keep as is")}</option>
              <option value="set">{t("Set to")}</option>
              <option value="clear">{t("Not set")}</option>
            </select>
            {target === "set" && (
              <input
                className="input"
                type="number"
                min={0}
                max={100}
                required
                aria-label={t("Target implementation (%)")}
                value={targetValue}
                onChange={(e) => setTargetValue(e.target.value)}
              />
            )}
          </span>
        </label>
      </div>
      <fieldset className="fieldset stack-xs">
        <legend>{t("Business drivers")}</legend>
        <div className="form-grid">
          <MultiSelect label={t("Add")} options={businessOptions(drivers)} value={bdAdd} onChange={setBdAdd} />
          <MultiSelect label={t("Remove")} options={businessOptions(drivers)} value={bdRemove} onChange={setBdRemove} />
        </div>
      </fieldset>
      <fieldset className="fieldset stack-xs">
        <legend>{t("Compliance drivers")}</legend>
        <div className="form-grid">
          <MultiSelect label={t("Add")} options={complianceOptions(sources)} value={cdAdd} onChange={setCdAdd} />
          <MultiSelect label={t("Remove")} options={complianceOptions(sources)} value={cdRemove} onChange={setCdRemove} />
        </div>
      </fieldset>
      <fieldset className="fieldset stack-xs">
        <legend>{t("Threat actors")}</legend>
        <div className="form-grid">
          <MultiSelect label={t("Add")} options={actorOptions} value={taAdd} onChange={setTaAdd} />
          <MultiSelect label={t("Remove")} options={actorOptions} value={taRemove} onChange={setTaRemove} />
        </div>
      </fieldset>
      <Actions busy={busy} disabled={empty} label={t("Apply")} onCancel={onCancel} />
    </form>
  );
}

function LifecycleForm({
  busy,
  onCancel,
  onSubmit,
}: {
  busy: boolean;
  onCancel: () => void;
  onSubmit: (b: { to_status: Lifecycle; driver_type: string; driver: string; note: string }) => void;
}) {
  const meta = useLoad<LifecycleMeta>(loadMeta);
  const [to, setTo] = useState<Lifecycle>("operational");
  const [driverType, setDriverType] = useState("operational");
  const [driver, setDriver] = useState("");
  const [note, setNote] = useState("");
  const m = meta.data;
  const driverKey = driver || m?.drivers[driverType]?.[0]?.key || "";
  return (
    <form
      className="stack"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        onSubmit({ to_status: to, driver_type: driverType, driver: driverKey, note });
      }}
    >
      <ErrorNote error={meta.error} />
      <label className="field">
        {t("To")}
        <select className="input" value={to} onChange={(e) => setTo(e.target.value as Lifecycle)}>
          {LIFECYCLES.map((x) => (
            <option key={x} value={x}>
              {STATUS_LABEL[x]}
            </option>
          ))}
        </select>
      </label>
      {m && (
        <fieldset className="field fieldset">
          <legend>{t("Change driver")}</legend>
          <div className="radio-row">
            {Object.keys(m.drivers).map((k) => (
              <label key={k}>
                <input
                  type="radio"
                  name="bulk-driver-type"
                  checked={driverType === k}
                  onChange={() => {
                    setDriverType(k);
                    setDriver("");
                  }}
                />
                {DRIVER_TYPE_LABEL[k] ?? k}
              </label>
            ))}
          </div>
          <select className="input" aria-label={t("Driver")} value={driverKey} onChange={(e) => setDriver(e.target.value)}>
            {m.drivers[driverType].map((d) => (
              <option key={d.key} value={d.key}>
                {t(d.label)}
              </option>
            ))}
          </select>
        </fieldset>
      )}
      <label className="field">
        {t("Note")}
        <textarea
          className="input textarea"
          rows={3}
          value={note}
          placeholder={t("What happened and why the status changes")}
          onChange={(e) => setNote(e.target.value)}
        />
      </label>
      <p className="form-notice">
        {t(
          "Use cases where this step is not allowed, or whose definition of done is incomplete, are skipped and listed afterwards. Skipping the definition of done is only possible one use case at a time.",
        )}
      </p>
      <Actions busy={busy} disabled={!m} label={t("Set to {status}", { status: STATUS_LABEL[to] })} onCancel={onCancel} />
    </form>
  );
}

function VerifyForm({
  busy,
  onCancel,
  onSubmit,
}: {
  busy: boolean;
  onCancel: () => void;
  onSubmit: (b: { result: "ok" | "issues"; note: string; verified_at?: string }) => void;
}) {
  const [result, setResult] = useState<"ok" | "issues">("ok");
  const [note, setNote] = useState("");
  const [when, setWhen] = useState("");
  return (
    <form
      className="stack"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        onSubmit({ result, note, ...(when ? { verified_at: when } : {}) });
      }}
    >
      <fieldset className="radio-row">
        <legend>{t("Result")}</legend>
        <label>
          <input type="radio" checked={result === "ok"} onChange={() => setResult("ok")} /> {t("Works as expected")}
        </label>
        <label>
          <input type="radio" checked={result === "issues"} onChange={() => setResult("issues")} /> {t("Issues found")}
        </label>
      </fieldset>
      <label className="field">
        {t("Note")}
        <textarea className="input textarea" rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
      </label>
      <label className="field">
        {t("Date (leave empty for today)")}
        <input className="input" type="date" value={when} onChange={(e) => setWhen(e.target.value)} />
      </label>
      <Actions busy={busy} label={t("Save verification")} onCancel={onCancel} />
    </form>
  );
}
