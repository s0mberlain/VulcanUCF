import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Link, useBlocker } from "react-router-dom";
import { isLeavingSession, type Lifecycle } from "../api";
import { STATUS_LABEL } from "../lib/format";
import { t } from "../i18n";

/** Load data on mount and when deps change; `reload` refetches. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(fn, deps);
  const reload = useCallback(() => {
    setLoading(true);
    return load()
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [load]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { data, error, loading, reload, setData };
}

export function StatusPill({ status }: { status: Lifecycle }) {
  return <span className={`pill status-${status}`}>{STATUS_LABEL[status]}</span>;
}

/** Chips; with `href` each chip is a link (e.g. to the use cases that share the entry). */
export function Chips({
  items,
  tone = "info",
  href,
  title,
}: {
  items: string[];
  tone?: "info" | "neutral";
  href?: (item: string) => string;
  title?: (item: string) => string;
}) {
  if (!items.length) return <span className="muted">–</span>;
  return (
    <div className="chips">
      {items.map((s) =>
        href ? (
          <Link key={s} to={href(s)} className={`chip chip-${tone} chip-link`} title={title?.(s)}>
            {s}
          </Link>
        ) : (
          <span key={s} className={`chip chip-${tone}`}>
            {s}
          </span>
        ),
      )}
    </div>
  );
}

export function MetricBars({ e, i, c }: { e: number | null; i: number | null; c: number | null }) {
  const bar = (v: number | null, cls: string, label: string) => (
    <div className="bar" title={`${label}: ${v === null ? "–" : Math.round(v * 100) + " %"}`}>
      <div className={cls} style={{ width: `${Math.round((v ?? 0) * 100)}%` }} />
    </div>
  );
  return (
    <div className="metric-bars">
      {bar(e, "d1", t("Effectiveness"))}
      {bar(i, "d2", t("Implementation"))}
      {bar(c, "d3", t("Coverage"))}
    </div>
  );
}

export function MetricLegend() {
  return (
    <div className="legend">
      <span>
        <i className="d1" />
        {t("Effectiveness")}
      </span>
      <span>
        <i className="d2" />
        {t("Implementation")}
      </span>
      <span>
        <i className="d3" />
        {t("Coverage")}
      </span>
    </div>
  );
}

export function GapBadge({ children = t("Detection gap") }: { children?: ReactNode }) {
  return <span className="badge-gap">{children}</span>;
}

/** Modal dialog using the native <dialog> element (focus trap and Esc for free). */
export function Modal({
  title,
  open,
  onClose,
  children,
  wide,
}: {
  title: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      d.showModal();
      // the first field gets the focus, not the close button
      d.querySelector<HTMLElement>("input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled])")?.focus();
    }
    if (!open && d.open) d.close();
  }, [open]);
  // Rendered into <body>: a dialog opened from inside a page <form> (the rule editor) would otherwise
  // nest its own <form> in it, and submitting the dialog would submit (and reload) the page form.
  // React still bubbles events through the component tree, so submit events stop at the dialog.
  return createPortal(
    <dialog
      ref={ref}
      className={"modal" + (wide ? " modal-wide" : "")}
      aria-labelledby={id}
      onClose={onClose}
      onCancel={onClose}
      onSubmit={(e) => e.stopPropagation()}
      onReset={(e) => e.stopPropagation()}
    >
      {open && (
        <>
          <div className="modal-head">
            <h2 id={id}>{title}</h2>
            <button type="button" className="icon-btn" aria-label={t("Close")} onClick={onClose}>
              ×
            </button>
          </div>
          {children}
        </>
      )}
    </dialog>,
    document.body,
  );
}

/** Checkbox list in a disclosure, for picking several entries from a reference list. */
export function MultiSelect({
  label,
  options,
  value,
  onChange,
  disabled,
  onCreate,
}: {
  label: string;
  /** options with a `group` are listed under that heading (in the order the groups appear) */
  options: { value: string; label: string; group?: string }[];
  value: string[];
  onChange: (v: string[]) => void;
  disabled?: boolean;
  /** When set, a new entry can be typed in at the end of the list; it is created (e.g. in a
   * reference list), then selected. Resolves to the value of the created option. */
  onCreate?: (name: string) => Promise<string>;
}) {
  const id = useId();
  const toggle = (v: string) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
  const chosen = options.filter((o) => value.includes(o.value));
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [find, setFind] = useState("");
  const box = useRef<HTMLDetailsElement>(null);
  // Escape or a click outside closes the list; Escape returns to the summary
  useEffect(() => {
    const d = box.current;
    if (!d) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && d.open) {
        d.open = false;
        d.querySelector("summary")?.focus();
        e.stopPropagation();
      }
    };
    const onDown = (e: MouseEvent) => {
      if (d.open && !d.contains(e.target as Node)) d.open = false;
    };
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("mousedown", onDown);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("mousedown", onDown);
    };
  }, []);
  const shown = find.trim() ? options.filter((o) => o.label.toLowerCase().includes(find.trim().toLowerCase())) : options;

  async function create() {
    const name = draft.trim();
    if (!name || !onCreate || busy) return;
    setError(null);
    // an entry with that name exists already: just select it
    const existing = options.find((o) => o.value.toLowerCase() === name.toLowerCase());
    if (existing) {
      if (!value.includes(existing.value)) onChange([...value, existing.value]);
      setDraft("");
      return;
    }
    setBusy(true);
    try {
      const created = await onCreate(name);
      onChange([...value, created]);
      setDraft("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="field">
      <span id={id}>{label}</span>
      <details className="multi" ref={box}>
        <summary className={"input multi-summary" + (disabled ? " is-disabled" : "")} aria-labelledby={id}>
          {chosen.length ? (
            <span className="chips">
              {chosen.map((o) => (
                <span key={o.value} className="chip chip-info">
                  {o.label}
                </span>
              ))}
            </span>
          ) : (
            <span className="muted">{t("None")}</span>
          )}
        </summary>
        {!disabled && (
          <fieldset className="multi-list" aria-labelledby={id}>
            {options.length > 8 && (
              <input
                className="input input-sm"
                type="search"
                value={find}
                placeholder={t("Search…")}
                aria-label={t("Search in {list}", { list: label })}
                onChange={(e) => setFind(e.target.value)}
              />
            )}
            {[...new Set(shown.map((o) => o.group ?? ""))].map((g) => (
              <div key={g} className="multi-group" role="group" aria-label={g || undefined}>
                {g && <span className="multi-group-head">{g}</span>}
                {shown
                  .filter((o) => (o.group ?? "") === g)
                  .map((o) => (
                    <label key={o.value}>
                      <input type="checkbox" checked={value.includes(o.value)} onChange={() => toggle(o.value)} />
                      {o.label}
                    </label>
                  ))}
              </div>
            ))}
            {!options.length && <span className="muted">{t("The reference list is empty.")}</span>}
            {onCreate && (
              <div className="multi-add">
                <input
                  className="input input-sm grow"
                  value={draft}
                  maxLength={200}
                  placeholder={t("New entry…")}
                  aria-label={t("New entry for {list}", { list: label })}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    // Enter adds the entry instead of submitting the surrounding form
                    if (e.key === "Enter") {
                      e.preventDefault();
                      void create();
                    }
                  }}
                />
                <button type="button" className="btn btn-sm" disabled={!draft.trim() || busy} onClick={() => void create()}>
                  {t("Add")}
                </button>
                {error && (
                  <span className="form-error small" role="alert">
                    {error}
                  </span>
                )}
              </div>
            )}
          </fieldset>
        )}
      </details>
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null }) {
  return error ? (
    <p className="form-error" role="alert">
      {error}
    </p>
  ) : null;
}

/* ------------------------------------------------------------------ confirm dialog */

export interface ConfirmOptions {
  title?: string;
  /** extra content under the question, e.g. the list of what is affected */
  body?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
}

interface Pending extends ConfirmOptions {
  message: string;
  resolve: (ok: boolean) => void;
}

let ask: ((message: string, opts?: ConfirmOptions) => Promise<boolean>) | null = null;

/** The app's own "are you sure" dialog (instead of the browser's confirm box). */
export function confirmDialog(message: string, opts?: ConfirmOptions): Promise<boolean> {
  return ask ? ask(message, opts) : Promise.resolve(window.confirm(message));
}

/** Rendered once at the top of the app; shows the dialogs opened with confirmDialog(). */
export function ConfirmHost() {
  const [pending, setPending] = useState<Pending | null>(null);
  useEffect(() => {
    ask = (message, opts) => new Promise<boolean>((resolve) => setPending({ message, ...opts, resolve }));
    return () => {
      ask = null;
    };
  }, []);
  if (!pending) return null;
  const answer = (ok: boolean) => {
    pending.resolve(ok);
    setPending(null);
  };
  return (
    <Modal title={pending.title ?? t("Please confirm")} open onClose={() => answer(false)}>
      <div className="stack">
        <p className="confirm-text">{pending.message}</p>
        {pending.body}
        <div className="row-actions">
          <button type="button" className="btn" onClick={() => answer(false)}>
            {pending.cancelLabel ?? t("Cancel")}
          </button>
          <button
            type="button"
            className={"btn " + (pending.danger ? "btn-danger-solid" : "btn-primary")}
            autoFocus
            onClick={() => answer(true)}
          >
            {pending.confirmLabel ?? t("Continue")}
          </button>
        </div>
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------ unsaved changes */

/** Ask before leaving a page (link, back button, reload, closing the tab) with unsaved changes. */
export function useUnsavedGuard(dirty: boolean) {
  const blocker = useBlocker(() => dirty && !isLeavingSession());
  useEffect(() => {
    if (blocker.state !== "blocked") return;
    void confirmDialog(t("You have unsaved changes on this page. Leave and discard them?"), {
      title: t("Unsaved changes"),
      confirmLabel: t("Discard changes"),
      cancelLabel: t("Stay on the page"),
      danger: true,
    }).then((ok) => (ok ? blocker.proceed() : blocker.reset()));
  }, [blocker]);
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
}

/* ------------------------------------------------------------------ long lists */

/** Show a long list in steps: `shown` rows now, `more()` adds the next step. */
export function useShowMore<T>(items: T[], step = 50) {
  const [limit, setLimit] = useState(step);
  return {
    shown: items.slice(0, limit),
    rest: Math.max(0, items.length - limit),
    more: () => setLimit((n) => n + step),
    all: () => setLimit(items.length),
  };
}

export function ShowMore({ rest, more, all }: { rest: number; more: () => void; all: () => void }) {
  if (!rest) return null;
  return (
    <div className="show-more">
      <button type="button" className="btn btn-sm" onClick={more}>
        {t("Show more")}
      </button>
      <button type="button" className="link-btn small" onClick={all}>
        {t("Show all ({n} more)", { n: rest })}
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ unsaved drafts (#53) */

interface StoredDraft<T> {
  at: number;
  base: string;
  value: T;
}

/**
 * Keeps an unsaved form in this tab's sessionStorage, so it survives an expired session: after
 * signing in again the page offers to restore it. `base` names the server version the edits
 * started from; a draft for another version is not offered. Call `clear()` after saving or
 * discarding.
 */
export function useDraftBackup<T>(key: string, value: T | null, dirty: boolean, base: string | null) {
  const [offer, setOffer] = useState<StoredDraft<T> | null>(null);
  const checked = useRef<string | null>(null);

  useEffect(() => {
    if (base === null || checked.current === key) return;
    checked.current = key;
    try {
      const raw = sessionStorage.getItem(key);
      const d = raw ? (JSON.parse(raw) as StoredDraft<T>) : null;
      if (d && d.base === base) setOffer(d);
      else if (d) sessionStorage.removeItem(key);
    } catch {
      /* storage blocked: nothing to offer */
    }
  }, [key, base]);

  useEffect(() => {
    if (!dirty || value === null || base === null || offer) return;
    try {
      sessionStorage.setItem(key, JSON.stringify({ at: Date.now(), base, value }));
    } catch {
      /* storage full or blocked */
    }
  }, [key, value, dirty, base, offer]);

  const clear = () => {
    setOffer(null);
    try {
      sessionStorage.removeItem(key);
    } catch {
      /* ignore */
    }
  };
  return { offer, clear, dismiss: () => setOffer(null) };
}

/** "Unsaved changes from {time} were kept" with Restore and Discard. */
export function DraftRestoreBanner({ at, onRestore, onDiscard }: { at: number; onRestore: () => void; onDiscard: () => void }) {
  return (
    <div className="note-box draft-restore" role="status">
      <span>
        {t("Unsaved changes from {time} were kept when your session ended.", {
          time: new Date(at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        })}
      </span>
      <span className="grow" />
      <button type="button" className="btn btn-sm btn-primary" onClick={onRestore}>
        {t("Restore")}
      </button>
      <button type="button" className="btn btn-sm" onClick={onDiscard}>
        {t("Discard")}
      </button>
    </div>
  );
}
