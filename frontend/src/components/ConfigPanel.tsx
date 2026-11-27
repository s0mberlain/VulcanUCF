import { useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  ConflictError,
  type ConfigCommit,
  type ConfigDiff,
  type DiffLine,
  type Level,
  type ConfigCheck,
} from "../api";
import { fmtDate } from "../lib/format";
import { confirmDialog, ErrorNote, useLoad } from "./ui";
import { t } from "../i18n";

type Tab = "editor" | "history" | "diff";

function when(iso: string) {
  const d = new Date(iso);
  return `${fmtDate(iso)} ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

export function DiffView({ lines, empty = t("No differences.") }: { lines: DiffLine[]; empty?: string }) {
  if (!lines.length) return <p className="muted small">{empty}</p>;
  return (
    <div className="diff" role="table" aria-label={t("Changes")}>
      {lines.map((l, i) =>
        l.kind === "hunk" ? (
          <div key={i} className="diff-hunk" role="row">
            {l.text}
          </div>
        ) : (
          <div key={i} className={`diff-line diff-${l.kind}`} role="row">
            <span className="diff-no">{l.old ?? ""}</span>
            <span className="diff-no">{l.new ?? ""}</span>
            <span
              className="diff-mark"
              aria-label={l.kind === "add" ? "added" : l.kind === "del" ? "removed" : undefined}
            >
              {l.kind === "add" ? "+" : l.kind === "del" ? "−" : " "}
            </span>
            <span className="diff-text">{l.text || " "}</span>
          </div>
        ),
      )}
    </div>
  );
}

function CodeEditor({
  value,
  onChange,
  readOnly,
  errorLine,
  label,
}: {
  value: string;
  onChange: (v: string) => void;
  readOnly: boolean;
  errorLine: number | null;
  label: string;
}) {
  const gutter = useRef<HTMLDivElement>(null);
  const count = Math.max(1, value.split("\n").length);
  return (
    <div className="code">
      <div className="code-gutter" ref={gutter} aria-hidden="true">
        {Array.from({ length: count }, (_, i) => (
          <div key={i} className={errorLine === i + 1 ? "code-err" : ""}>
            {i + 1}
          </div>
        ))}
      </div>
      <textarea
        className="code-text"
        aria-label={label}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        wrap="off"
        readOnly={readOnly}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onScroll={(e) => {
          if (gutter.current) gutter.current.scrollTop = e.currentTarget.scrollTop;
        }}
        onKeyDown={(e) => {
          if (e.key === "Tab" && !readOnly) {
            e.preventDefault();
            const tt = e.currentTarget;
            const { selectionStart: a, selectionEnd: b } = tt;
            const next = value.slice(0, a) + "  " + value.slice(b);
            onChange(next);
            requestAnimationFrame(() => tt.setSelectionRange(a + 2, a + 2));
          }
        }}
      />
    </div>
  );
}

// Free-form JSON: store whatever describes this detection, e.g. the query, thresholds,
// schedule, owner or response playbook.
const TEMPLATE = `{
  "owner": "soc",
  "severity": "medium",
  "detection": {
    "query": "",
    "threshold": 1
  }
}
`;

export default function ConfigPanel({
  level,
  code,
  editor,
  onDirtyChange,
}: {
  level: Level;
  code: string;
  editor: boolean;
  /** Unsaved text in the editor (the untouched template of a new configuration does not count). */
  onDirtyChange?: (dirty: boolean) => void;
}) {
  const state = useLoad(() => api.config(level, code), [level, code]);
  const hist = useLoad(() => api.configHistory(level, code), [level, code]);
  const [tab, setTab] = useState<Tab>("editor");
  const [text, setText] = useState("");
  const [base, setBase] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [check, setCheck] = useState<ConfigCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [conflict, setConflict] = useState<ConflictError | null>(null);
  const [busy, setBusy] = useState(false);
  const [diffSel, setDiffSel] = useState<{ from: string; to: string } | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const head = state.data?.head ?? null;
  const original = state.data?.content ?? "";
  const dirty = text !== original;
  // what the editor starts with: the stored content, or the template for a new configuration
  const initial = state.data ? state.data.content || (editor ? TEMPLATE : "") : text;
  const unsaved = editor && text !== initial;
  useEffect(() => {
    onDirtyChange?.(unsaved);
  }, [unsaved, onDirtyChange]);
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);

  useEffect(() => {
    if (!state.data) return;
    setText(state.data.content || (editor ? TEMPLATE : ""));
    setBase(state.data.head?.sha ?? null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.data]);

  // debounced JSON check while typing
  // only the answer for the current text counts: an older, slower one must not overwrite it
  const checkSeq = useRef(0);
  useEffect(() => {
    if (!editor) return;
    const n = ++checkSeq.current;
    const tt = setTimeout(() => {
      api
        .validateConfig(text)
        .then((c) => n === checkSeq.current && setCheck(c))
        .catch(() => n === checkSeq.current && setCheck(null));
    }, 350);
    return () => clearTimeout(tt);
  }, [text, editor]);

  const reload = () => {
    void state.reload();
    void hist.reload();
  };

  async function commit() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const c = await api.saveConfig(level, code, {
        content: text,
        message: message.trim() || (head ? t("Update configuration") : t("Initial configuration")),
        base_sha: base,
      });
      setMessage("");
      setConflict(null);
      setNotice(t("Committed r{rev} ({short}).", { rev: c.rev, short: c.short }));
      reload();
    } catch (e) {
      if (e instanceof ConflictError) setConflict(e);
      else setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function restore(c: ConfigCommit) {
    const ok = await confirmDialog(
      t("Restore r{rev}? This adds a new commit with the content of r{rev}.", { rev: c.rev }),
      { title: t("Restore configuration"), confirmLabel: t("Restore") },
    );
    if (!ok) return;
    setError(null);
    try {
      const n = await api.restoreConfig(level, code, c.sha);
      setNotice(t("Restored r{rev} as r{new}.", { rev: c.rev, new: n.rev }));
      setTab("editor");
      reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function tag(c: ConfigCommit) {
    const name = window.prompt(t("Tag for r{rev} (e.g. prod or reviewed-2026-11)", { rev: c.rev }));
    if (!name) return;
    try {
      await api.tagConfig(level, code, name.trim(), c.sha);
      void hist.reload();
      void state.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  function upload(file: File) {
    file.text().then((tt) => {
      setText(tt);
      setMessage(t("Upload {name}", { name: file.name }));
      setTab("editor");
    });
  }

  const tagsLine = useMemo(() => {
    const tags = (hist.data ?? []).flatMap((c) => c.tags.map((tt) => `${tt.name} on r${c.rev}`));
    return tags.slice(0, 2).join(" · ");
  }, [hist.data]);

  return (
    <section className="card config" aria-labelledby={`cfg-${code}`}>
      <div className="config-head">
        <div className="stack-xs">
          <h2 id={`cfg-${code}`}>{t("Configuration (JSON)")}</h2>
          <span className="small muted">
            {head
              ? `HEAD r${head.rev} · ${head.short} · ${head.author}, ${when(head.created_at)}${tagsLine ? ` · ${t("tag")} ${tagsLine}` : ""}`
              : t("No configuration committed yet")}
          </span>
        </div>
        <div className="row-actions">
          {head && (
            <a className="btn btn-sm" href={api.configDownloadUrl(level, code)} download>
              {t("Download .json")}
            </a>
          )}
          {editor && (
            <>
              <button type="button" className="btn btn-sm" onClick={() => fileInput.current?.click()}>
                {t("Upload")}
              </button>
              <input
                ref={fileInput}
                type="file"
                accept=".json,application/json,text/plain"
                hidden
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) upload(f);
                  e.target.value = "";
                }}
              />
            </>
          )}
        </div>
      </div>

      <div role="tablist" aria-label={t("Configuration views")} className="tabs config-tabs">
        {(["editor", "history", "diff"] as Tab[]).map((tt) => (
          <button
            key={tt}
            type="button"
            role="tab"
            aria-selected={tab === tt}
            className={"tab" + (tab === tt ? " active" : "")}
            onClick={() => {
              setTab(tt);
              setNotice(null);
            }}
          >
            {tt === "editor"
              ? editor
                ? t("Editor")
                : t("Current")
              : tt === "history"
                ? t("History ({n})", { n: hist.data?.length ?? 0 })
                : t("Diff")}
          </button>
        ))}
      </div>

      <div className="config-body">
        <ErrorNote error={error ?? state.error ?? hist.error} />
        {notice && (
          <p className="form-notice" role="status">
            {notice}
          </p>
        )}

        {tab === "editor" && (
          <>
            {conflict && (
              <div className="conflict" role="alert">
                <p className="form-error">{conflict.message}</p>
                <span className="small muted">{t("Changes between the latest version (−) and your text (+):")}</span>
                <DiffView lines={conflict.diff.lines} />
                <div className="row-actions start">
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => {
                      setConflict(null);
                      void state.reload();
                    }}
                  >
                    {t("Load latest (discard mine)")}
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    onClick={() => {
                      setBase(conflict.head?.sha ?? null);
                      setConflict(null);
                      void hist.reload();
                    }}
                  >
                    {t("I merged by hand, commit mine on top")}
                  </button>
                </div>
              </div>
            )}
            {!editor && !head ? (
              <p className="muted">{t("No configuration has been committed for this use case.")}</p>
            ) : (
              <CodeEditor
                value={text}
                onChange={setText}
                readOnly={!editor}
                errorLine={check && !check.valid ? check.line : null}
                label={t("JSON configuration of {code}", { code })}
              />
            )}
            {editor && (
              <div className="commit-row">
                <span className={"small " + (check && !check.valid ? "text-err" : "text-ok")}>
                  {check === null
                    ? t("Checking…")
                    : check.valid
                      ? `✓ ${t("Valid JSON")}${head ? ` · ${t("based on r{rev} ({short})", { rev: head.rev, short: head.short })}` : ""}`
                      : `✗ ${check.line ? `${t("Line {n}", { n: check.line })}: ` : ""}${check.error}`}
                </span>
                <label className="sr-only" htmlFor={`msg-${code}`}>
                  {t("Commit message")}
                </label>
                <input
                  id={`msg-${code}`}
                  className="input input-sm grow"
                  placeholder={head ? t("Commit message, e.g. Lower threshold") : t("Initial configuration")}
                  value={message}
                  maxLength={500}
                  onChange={(e) => setMessage(e.target.value)}
                />
                {dirty && head && (
                  <button type="button" className="btn btn-sm" onClick={() => setText(original)}>
                    {t("Discard")}
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  disabled={busy || !check?.valid || (!!head && !dirty)}
                  onClick={commit}
                >
                  {t("Commit r")}
                  {(head?.rev ?? 0) + 1}
                </button>
              </div>
            )}
          </>
        )}

        {tab === "history" && (
          <ul className="commits">
            {hist.data?.map((c) => (
              <li key={c.sha}>
                <span className="mono small accent">r{c.rev}</span>
                <span className="mono small muted">{c.short}</span>
                <span className="stack-xs grow">
                  <span className="strong-500">
                    {c.message}
                    {c.source === "git" && (
                      <span className="chip chip-git" title={t("Committed directly in the git repository")}>
                        {t("from git")}
                      </span>
                    )}
                  </span>
                  <span className="small muted">
                    {c.author} · {when(c.created_at)}
                    {c.git_sha && (
                      <span title={`git ${c.git_sha}`}>
                        {" "}
                        {t("· in git")} {c.git_sha.slice(0, 7)}
                      </span>
                    )}
                    {c.restored_from && ` · ${t("restored from {sha}", { sha: c.restored_from.slice(0, 7) })}`}
                  </span>
                </span>
                <span className="chips">
                  {c.tags.map((tt) => (
                    <span key={tt.name} className="chip chip-tag" title={t("by {user}", { user: tt.created_by })}>
                      {tt.name}
                    </span>
                  ))}
                </span>
                <span className="row-actions">
                  {c.rev > 1 && (
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => {
                        setDiffSel({ from: `r${c.rev - 1}`, to: `r${c.rev}` });
                        setTab("diff");
                      }}
                    >
                      {t("Diff")}
                    </button>
                  )}
                  <a className="btn btn-sm" href={api.configDownloadUrl(level, code, c.sha)} download>
                    {t(".json")}
                  </a>
                  {editor && (
                    <>
                      <button type="button" className="btn btn-sm" onClick={() => tag(c)}>
                        {t("Tag")}
                      </button>
                      {c.sha !== head?.sha && (
                        <button type="button" className="btn btn-sm" onClick={() => restore(c)}>
                          {t("Restore")}
                        </button>
                      )}
                    </>
                  )}
                </span>
              </li>
            ))}
            {hist.data && !hist.data.length && <li className="muted">{t("No commits yet.")}</li>}
          </ul>
        )}

        {tab === "diff" && (
          <DiffTab level={level} code={code} commits={hist.data ?? []} sel={diffSel} onSel={setDiffSel} />
        )}
      </div>
    </section>
  );
}

function DiffTab({
  level,
  code,
  commits,
  sel,
  onSel,
}: {
  level: Level;
  code: string;
  commits: ConfigCommit[];
  sel: { from: string; to: string } | null;
  onSel: (s: { from: string; to: string }) => void;
}) {
  const latest = commits[0];
  const current = sel ?? (latest ? { from: latest.rev > 1 ? `r${latest.rev - 1}` : "", to: `r${latest.rev}` } : null);
  const [diff, setDiff] = useState<ConfigDiff | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!current) return;
    api
      .configDiff(level, code, current.to, current.from || undefined)
      .then((d) => {
        setDiff(d);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [level, code, current?.from, current?.to]);

  if (!current) return <p className="muted">{t("Nothing to compare yet.")}</p>;
  const opt = (c: ConfigCommit) => (
    <option key={c.sha} value={`r${c.rev}`}>
      r{c.rev} · {c.short} · {c.message.slice(0, 40)}
    </option>
  );
  return (
    <div className="stack">
      <div className="diff-pick">
        <label className="field">
          {t("From")}
          <select
            className="input input-sm"
            value={current.from}
            onChange={(e) => onSel({ ...current, from: e.target.value })}
          >
            <option value="">{t("(empty)")}</option>
            {commits.map(opt)}
          </select>
        </label>
        <span aria-hidden="true">→</span>
        <label className="field">
          {t("To")}
          <select
            className="input input-sm"
            value={current.to}
            onChange={(e) => onSel({ ...current, to: e.target.value })}
          >
            {commits.map(opt)}
          </select>
        </label>
        {diff && (
          <span className="small">
            <span className="text-ok">+{diff.added}</span> <span className="text-err">−{diff.removed}</span>
          </span>
        )}
      </div>
      <ErrorNote error={error} />
      {diff && <DiffView lines={diff.lines} />}
    </div>
  );
}
