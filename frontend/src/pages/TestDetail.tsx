import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  type TestDetail as Detail,
  type TestEvent,
  type TestOutcome,
  type TestRound,
  type TestStatus,
} from "../api";
import { useAuth } from "../auth";
import { confirmDialog, ErrorNote, MultiSelect, useLoad } from "../components/ui";
import { Markdown } from "../components/Markdown";
import { OutcomePill, Technique } from "../components/TestParts";
import { fmtSize, fmtTime, refHref } from "../lib/format";
import {
  CAMPAIGN_LABEL,
  EXEC_LABEL,
  fmtTtd,
  fromInput,
  OUTCOMES,
  OUTCOME_HINT,
  OUTCOME_LABEL,
  OUTCOME_PILL,
  ROUND_LABEL,
  ROUND_PILL,
  toInput,
} from "../lib/tests";
import { t } from "../i18n";

/** One test: its definition, the rounds (red and blue side by side) and the history. */
export default function TestDetail() {
  const { id } = useParams();
  const tid = Number(id);
  const { user } = useAuth();
  const load = useLoad<Detail>(() => api.testDetail(tid), [tid]);
  const [d, setD] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (load.data) setD(load.data);
  }, [load.data]);

  /** Run a call that returns the changed test; show an error (a 409 asks for a reload). */
  async function run(call: () => Promise<Detail>): Promise<boolean> {
    setError(null);
    try {
      setD(await call());
      return true;
    } catch (e) {
      setError((e as Error).message);
      return false;
    }
  }

  if (!d) return <><ErrorNote error={load.error} />{!load.error && <p className="muted">{t("Loading…")}</p>}</>;
  const back = d.campaign_id
    ? { to: `/verification/campaigns/${d.campaign_id}`, label: d.campaign_name ?? t("Campaigns") }
    : { to: "/verification/quick-tests", label: t("Quick tests") };

  async function newRound() {
    await run(() => api.openRound(tid));
  }
  async function dropRound(n: number) {
    if (!(await confirmDialog(t("Delete round {n}? It has no entries yet.", { n }), { danger: true, confirmLabel: t("Delete") }))) return;
    await run(() => api.deleteRound(tid, n));
  }

  return (
    <>
      <nav className="crumbs" aria-label={t("Breadcrumb")}>
        <Link to={back.to}>{back.label}</Link> / <span>{d.title}</span>
      </nav>
      <header className="page-header">
        <div>
          <h1>{d.title}</h1>
          <div className="subtitle test-meta">
            <Technique id={d.technique} name={d.technique_name} />
            {d.collaboration && user?.role !== "red_team" && (
              <span className="muted">
                {d.collaboration === "open" ? t("Blue team results are visible to the red team") : t("Blue team results are hidden from the red team until the campaign is closed")}
              </span>
            )}
          </div>
        </div>
      </header>
      <ErrorNote error={error ?? load.error} />
      <div className="test-meta small muted">
        {d.links.length > 0
          ? d.links.map((l) => (
              <span key={l.l3_code} className="test-rule">
                {l.deleted ? t("Rule deleted: {code}", { code: l.l3_code }) : <Link to={`/usecases/l3/${l.l3_code}`} className="mono">{l.l3_code}</Link>}
                {l.scopes.length > 0 && <span> ({l.scopes.join(", ")})</span>}
              </span>
            ))
          : user?.role !== "red_team" && <span>{t("No rule linked")}</span>}
      </div>

      <StatusRow d={d} onNewRound={() => void newRound()} editor={user?.role === "admin" || user?.role === "analyst"} />

      <DefinitionFold d={d} />

      <section className="stack" aria-labelledby="roundsh">
        <div className="section-head">
          <h2 id="roundsh">{t("Rounds ({n})", { n: d.rounds.length })}</h2>
        </div>
        {[...d.rounds].reverse().map((r) => (
          <RoundCard key={r.number} d={d} r={r} run={run} onDelete={() => void dropRound(r.number)} onReload={() => void load.reload()} />
        ))}
      </section>

      <History d={d} run={run} />
    </>
  );
}

/** Where the test stands and the one thing to do next. */
function StatusRow({ d, onNewRound, editor }: { d: Detail; onNewRound: () => void; editor: boolean }) {
  const latest = d.rounds[d.rounds.length - 1];
  const gap = d.outcome === "logged" || d.outcome === "not_detected";
  const hint =
    latest.state === "waiting"
      ? t("Waiting for the blue team to record the result.")
      : latest.state === "open"
        ? t("The red team records the execution.")
        : gap
          ? t("The last result is a gap. Run another round once the detection is fixed, or accept the gap.")
          : d.outcome
            ? t("The last result verifies the rule.")
            : t("This round is closed without a result.");
  return (
    <section className="status-row" aria-label={t("Status")}>
      <div className="status-main">
        <span className="status-round">{t("Round {n}", { n: latest.number })}</span>
        <span className={`pill ${ROUND_PILL[latest.state]}`}>{ROUND_LABEL[latest.state]}</span>
        {d.outcome && (
          <span className="status-result">
            {t("Last result")} <OutcomePill outcome={d.outcome} />
          </span>
        )}
        <span className="muted small">{hint}</span>
      </div>
      <div className="row-actions">
        {d.can_open_round && (
          <button type="button" className="btn btn-primary" onClick={onNewRound}>
            {t("+ New round")}
          </button>
        )}
        {gap && editor && d.open_gaps > 0 && (
          <Link className="btn" to="/verification/gaps">
            {t("Review gap")}
          </Link>
        )}
      </div>
    </section>
  );
}

function DefinitionFold({ d }: { d: Detail }) {
  const has = d.description || d.procedure || d.tools || d.prerequisites || d.expected_detection;
  if (!has) return null;
  return (
    <details className="fold">
      <summary>{t("Test definition")}</summary>
      <div className="stack-sm">
        {d.description && <Markdown text={d.description} className="test-description" />}
        {d.procedure && <pre className="code-block test-procedure">{d.procedure}</pre>}
        <dl className="facts">
          {d.tools && (<><dt>{t("Tools")}</dt><dd>{d.tools}</dd></>)}
          {d.prerequisites && (<><dt>{t("Prerequisites and cleanup")}</dt><dd className="pre-line">{d.prerequisites}</dd></>)}
          {d.expected_detection && (<><dt>{t("Expected detection")}</dt><dd>{d.expected_detection}</dd></>)}
        </dl>
      </div>
    </details>
  );
}

// ------------------------------------------------------------------ one round

type Run = (call: () => Promise<Detail>) => Promise<boolean>;

function RoundCard({ d, r, run, onDelete, onReload }: { d: Detail; r: TestRound; run: Run; onDelete: () => void; onReload: () => void }) {
  const [editRed, setEditRed] = useState(false);
  const [editBlue, setEditBlue] = useState(false);
  const latest = r.number === d.rounds[d.rounds.length - 1].number;
  return (
    <article className={"round-card" + (latest ? " is-latest" : "")} aria-label={t("Round {n}", { n: r.number })}>
      <div className="round-head">
        <h3>{t("Round {n}", { n: r.number })}</h3>
        <span className={`pill ${ROUND_PILL[r.state]}`}>{ROUND_LABEL[r.state]}</span>
        <span className="muted small">{t("opened by {user}", { user: r.opened_by })} · {fmtTime(r.opened_at)}</span>
        <span className="grow" />
        {r.can_delete && (
          <button type="button" className="btn btn-sm btn-danger" onClick={onDelete}>
            {t("Delete round")}
          </button>
        )}
      </div>
      <div className="round-cols">
        <section className="side side-red" aria-label={t("Red team")}>
          <header className="side-head">
            <h4>{t("Red team")}</h4>
            {r.can_record_red && !editRed && (
              <button type="button" className={"btn btn-sm" + (r.red_by ? "" : " btn-primary")} onClick={() => setEditRed(true)}>
                {r.red_by ? t("Edit") : t("Record execution")}
              </button>
            )}
          </header>
          {editRed ? (
            <RedForm d={d} r={r} run={run} onDone={() => setEditRed(false)} />
          ) : (
            <RedView r={r} />
          )}
          <Files d={d} r={r} side="red" onChanged={onReload} />
        </section>
        <section className="side side-blue" aria-label={t("Blue team")}>
          <header className="side-head">
            <h4>{t("Blue team")}</h4>
            {r.can_record_blue && !editBlue && (
              <button type="button" className={"btn btn-sm" + (r.blue_by ? "" : " btn-primary")} onClick={() => setEditBlue(true)}>
                {r.blue_by ? t("Edit") : t("Record result")}
              </button>
            )}
          </header>
          {r.blue_hidden ? (
            <p className="muted small">{t("Hidden until the campaign is closed.")}</p>
          ) : editBlue ? (
            <BlueForm r={r} d={d} run={run} onDone={() => setEditBlue(false)} />
          ) : (
            <BlueView r={r} />
          )}
          {!r.blue_hidden && <Files d={d} r={r} side="blue" onChanged={onReload} />}
        </section>
      </div>
    </article>
  );
}

function RedView({ r }: { r: TestRound }) {
  if (r.exec_status === "not_run") return <p className="muted small">{t("Not run yet.")}</p>;
  return (
    <dl className="facts">
      <dt>{t("Execution")}</dt>
      <dd>{EXEC_LABEL[r.exec_status]}</dd>
      {r.started_at && (<><dt>{t("Started")}</dt><dd>{fmtTime(r.started_at)}</dd></>)}
      {r.ended_at && (<><dt>{t("Ended")}</dt><dd>{fmtTime(r.ended_at)}</dd></>)}
      {r.executed_what && (<><dt>{t("What was executed")}</dt><dd className="pre-line">{r.executed_what}</dd></>)}
      {r.red_notes && (<><dt>{t("Red team notes")}</dt><dd className="pre-line">{r.red_notes}</dd></>)}
      {r.red_by && (<><dt>{t("Recorded by")}</dt><dd>{r.red_by}{r.red_at ? ` · ${fmtTime(r.red_at)}` : ""}</dd></>)}
    </dl>
  );
}

function BlueView({ r }: { r: TestRound }) {
  if (!r.outcome && !r.blue_notes) return <p className="muted small">{r.exec_status === "executed" ? t("Waiting for the blue team.") : t("No result yet.")}</p>;
  return (
    <dl className="facts">
      <dt>{t("Result")}</dt>
      <dd><OutcomePill outcome={r.outcome} /></dd>
      {r.detected_at && (<><dt>{t("Detected at")}</dt><dd>{fmtTime(r.detected_at)}</dd></>)}
      {r.time_to_detect_seconds !== null && (<><dt>{t("Time to detect")}</dt><dd>{fmtTtd(r.time_to_detect_seconds)}</dd></>)}
      {r.detected_by.length > 0 && (
        <>
          <dt>{t("Detected by")}</dt>
          <dd className="chip-row">
            {r.detected_by.map((x) =>
              x.item_id ? (
                <Link key={x.name} className="chip chip-neutral" to={refHref("detection_technology", x.name)}>{x.name}</Link>
              ) : (
                <span key={x.name} className="chip chip-neutral" title={t("Removed from the reference list")}>{x.name}</span>
              ),
            )}
          </dd>
        </>
      )}
      {r.blue_notes && (<><dt>{t("Blue team notes")}</dt><dd className="pre-line">{r.blue_notes}</dd></>)}
      {r.blue_by && (<><dt>{t("Recorded by")}</dt><dd>{r.blue_by}{r.blue_at ? ` · ${fmtTime(r.blue_at)}` : ""}</dd></>)}
    </dl>
  );
}

function RedForm({ d, r, run, onDone }: { d: Detail; r: TestRound; run: Run; onDone: () => void }) {
  const [status, setStatus] = useState<TestStatus>(r.exec_status === "not_run" ? "executed" : r.exec_status);
  const [start, setStart] = useState(toInput(r.started_at) || toInput(new Date().toISOString()));
  const [end, setEnd] = useState(toInput(r.ended_at));
  const [what, setWhat] = useState(r.executed_what);
  const [notes, setNotes] = useState(r.red_notes);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    const ok = await run(() =>
      api.recordRoundRed(d.id, r.number, {
        exec_status: status,
        started_at: status === "executed" ? fromInput(start) : null,
        ended_at: status === "executed" ? fromInput(end) : null,
        executed_what: what,
        red_notes: notes,
        expected_version: r.red_version,
      }),
    );
    setBusy(false);
    if (ok) onDone();
  }
  return (
    <form className="stack-sm" onSubmit={submit}>
      <div className="form-grid two">
        <label className="field">
          {t("Execution")}
          <select className="input" value={status} onChange={(e) => setStatus(e.target.value as TestStatus)}>
            {(["executed", "not_executable"] as TestStatus[]).map((s) => <option key={s} value={s}>{EXEC_LABEL[s]}</option>)}
          </select>
        </label>
        {status === "executed" && (
          <>
            <label className="field">
              {t("Started")} *
              <input className="input" type="datetime-local" required value={start} onChange={(e) => setStart(e.target.value)} />
            </label>
            <label className="field">
              {t("Ended")}
              <input className="input" type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
            </label>
          </>
        )}
      </div>
      <label className="field">
        {t("What was executed")}
        <textarea className="input textarea" rows={3} maxLength={10000} value={what} onChange={(e) => setWhat(e.target.value)} />
      </label>
      <label className="field">
        {t("Red team notes")}
        <textarea className="input textarea" rows={3} maxLength={10000} value={notes} onChange={(e) => setNotes(e.target.value)} />
      </label>
      <div className="row-actions">
        <button type="button" className="btn btn-sm" onClick={onDone}>{t("Cancel")}</button>
        <button type="submit" className="btn btn-sm btn-primary" disabled={busy}>{t("Save")}</button>
      </div>
    </form>
  );
}

function BlueForm({ d, r, run, onDone }: { d: Detail; r: TestRound; run: Run; onDone: () => void }) {
  const refs = useLoad(() => api.refs("detection_technology"), []);
  const [outcome, setOutcome] = useState<TestOutcome | "">(r.outcome ?? "");
  const [at, setAt] = useState(toInput(r.detected_at));
  const [by, setBy] = useState<string[]>(r.detected_by.map((x) => x.name));
  const [notes, setNotes] = useState(r.blue_notes ?? "");
  const [busy, setBusy] = useState(false);
  const executed = r.exec_status === "executed";
  const names = new Set((refs.data ?? []).map((x) => x.name));
  // an entry that is no longer in the list stays selectable so it is not dropped by accident
  const options = [...(refs.data ?? []).map((x) => ({ value: x.name, label: x.name })), ...by.filter((n) => !names.has(n)).map((n) => ({ value: n, label: n }))];
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    const ok = await run(() =>
      api.recordRoundBlue(d.id, r.number, {
        outcome: outcome || null,
        detected_at: outcome === "blocked" || outcome === "alerted" ? fromInput(at) : null,
        detected_by: by,
        blue_notes: notes,
        expected_version: r.blue_version,
      }),
    );
    setBusy(false);
    if (ok) onDone();
  }
  return (
    <form className="stack-sm" onSubmit={submit}>
      {!executed && <p className="note-box">{t("A result needs an executed round. The red team records the execution first.")}</p>}
      <fieldset className="fieldset">
        <legend>{t("Result")}</legend>
        <div className="result-choices" role="radiogroup" aria-label={t("Result")}>
          {OUTCOMES.map((o) => (
            <label key={o} className={"result-choice" + (outcome === o ? " is-on" : "")}>
              <input type="radio" name={`outcome-${r.number}`} checked={outcome === o} onChange={() => setOutcome(o)} />
              <span className={`pill ${OUTCOME_PILL[o]}`}>{OUTCOME_LABEL[o]}</span>
              <span className="small muted">{OUTCOME_HINT[o]}</span>
            </label>
          ))}
        </div>
      </fieldset>
      {(outcome === "blocked" || outcome === "alerted") && (
        <label className="field">
          {t("Detected at")}
          <input className="input" type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} />
        </label>
      )}
      <MultiSelect
        label={t("Detected by")}
        hint={t("Detection technologies from the reference list.")}
        options={options}
        value={by}
        onChange={setBy}
        onCreate={async (name) => {
          const item = await api.createRef("detection_technology", { name, description: "" });
          await refs.reload();
          return item.name;
        }}
      />
      <label className="field">
        {t("Blue team notes")}
        <textarea className="input textarea" rows={3} maxLength={10000} value={notes} onChange={(e) => setNotes(e.target.value)} />
      </label>
      <div className="row-actions">
        <button type="button" className="btn btn-sm" onClick={onDone}>{t("Cancel")}</button>
        <button type="submit" className="btn btn-sm btn-primary" disabled={busy || !executed}>{t("Save")}</button>
      </div>
    </form>
  );
}

function Files({ d, r, side, onChanged }: { d: Detail; r: TestRound; side: "red" | "blue"; onChanged: () => void }) {
  const { user } = useAuth();
  const file = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mine = side === "red" ? r.can_record_red : r.can_record_blue;
  const items = r.attachments.filter((a) => a.side === side);
  if (!items.length && !mine) return null;
  async function upload(f: File) {
    setBusy(true);
    setError(null);
    try {
      await api.uploadTestAttachment(d.id, f, r.number);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function remove(id: number) {
    try {
      await api.deleteTestAttachment(id);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <div className="stack-sm">
      <ErrorNote error={error} />
      {items.length > 0 && (
        <ul className="plain-list test-files">
          {items.map((a) => (
            <li key={a.id}>
              <a href={api.testAttachmentUrl(a.id, !a.viewable)} target="_blank" rel="noopener noreferrer">{a.filename}</a>{" "}
              <span className="muted small">· {fmtSize(a.size)} · {a.uploaded_by}</span>
              {a.uploaded_by === user?.username && mine && (
                <button type="button" className="link-btn small" style={{ marginLeft: 8 }} onClick={() => void remove(a.id)}>{t("Remove")}</button>
              )}
            </li>
          ))}
        </ul>
      )}
      {mine && (
        <>
          <input
            ref={file}
            type="file"
            hidden
            accept=".pdf,.png,.jpg,.jpeg,.vsd,.vsdx,.dia,.excalidraw,.tm7"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void upload(f);
              e.target.value = "";
            }}
          />
          <div className="row-actions start">
            <button type="button" className="btn btn-sm" disabled={busy} onClick={() => file.current?.click()}>{t("Attach file")}</button>
          </div>
        </>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ history

function eventText(e: TestEvent): string {
  const to = (e.data.new ?? e.data.to) as string | undefined;
  switch (e.kind) {
    case "round_opened":
      return t("opened the round");
    case "round_deleted":
      return t("deleted the round");
    case "execution":
      return e.data.status === "not_executable"
        ? t("recorded: not executable")
        : e.data.first ? t("recorded the execution") : t("changed the execution");
    case "result":
      return t("recorded the result {result}", { result: OUTCOME_LABEL[to as TestOutcome] ?? "" });
    case "result_changed":
      return t("changed the result from {old} to {new}", {
        old: OUTCOME_LABEL[e.data.old as TestOutcome] ?? "",
        new: OUTCOME_LABEL[to as TestOutcome] ?? "",
      });
    case "collaboration":
      return to === "open" ? t("made the blue team results visible to the red team") : t("hid the blue team results from the red team");
    case "campaign_status":
      return t("set the campaign to {status}", { status: CAMPAIGN_LABEL[to as keyof typeof CAMPAIGN_LABEL] ?? String(to) });
    case "file_added":
      return t("added the file {file}", { file: String(e.data.file ?? "") });
    case "file_removed":
      return t("removed the file {file}", { file: String(e.data.file ?? "") });
    default:
      return e.kind;
  }
}

function History({ d, run }: { d: Detail; run: Run }) {
  const [text, setText] = useState("");
  const [round, setRound] = useState<number | "">("");
  const [busy, setBusy] = useState(false);
  const [more, setMore] = useState<TestEvent[]>([]);
  const [hasMore, setHasMore] = useState(d.events_more);
  const events = [...more, ...d.events];
  async function send(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    const ok = await run(() => api.addComment(d.id, text, round === "" ? null : round));
    setBusy(false);
    if (ok) setText("");
  }
  async function older() {
    const first = events[0];
    if (!first) return;
    const page = await api.testEvents(d.id, first.id);
    setMore([...page, ...more]);
    if (page.length === 0) setHasMore(false);
  }
  async function remove(id: number) {
    if (!(await confirmDialog(t("Remove this comment? The history keeps a note that it was removed."), { danger: true, confirmLabel: t("Remove") }))) return;
    await run(() => api.removeComment(d.id, id));
  }
  return (
    <section className="card stack-sm" aria-labelledby="historyh">
      <h2 id="historyh">{t("History")}</h2>
      {hasMore && (
        <button type="button" className="link-btn" onClick={() => void older()}>{t("Show older entries")}</button>
      )}
      {events.length === 0 && <p className="muted small">{t("No entries yet.")}</p>}
      <ol className="timeline">
        {events.map((e) => (
          <li key={e.id} className={`tl-item tl-${e.side} tl-${e.kind === "comment" ? "comment" : "system"}`}>
            <div className="tl-meta small muted">
              <strong className="tl-author">{e.author}</strong>
              {e.side !== "system" && <span className={`pill ${e.side === "red" ? "pill-poor" : "pill-ok"}`}>{e.side === "red" ? t("Red team") : t("Blue team")}</span>}
              <span>{fmtTime(e.at)}</span>
              {e.round_number !== null && <span>· {t("Round {n}", { n: e.round_number })}</span>}
              {e.can_remove && (
                <button type="button" className="link-btn small" onClick={() => void remove(e.id)}>{t("Remove")}</button>
              )}
            </div>
            {e.kind === "comment" ? (
              e.removed ? (
                <p className="muted small">{t("Comment removed by {user}", { user: e.removed_by ?? "" })}</p>
              ) : (
                <Markdown text={e.text} className="tl-text" />
              )
            ) : (
              <p className="small tl-sys">{eventText(e)}</p>
            )}
          </li>
        ))}
      </ol>
      {d.can_comment ? (
        <form className="stack-sm" onSubmit={send}>
          <label className="field">
            {t("Comment")}
            <textarea className="input textarea" rows={3} maxLength={10000} required value={text} onChange={(e) => setText(e.target.value)} />
          </label>
          <div className="row-actions">
            <select className="input" aria-label={t("Round")} style={{ width: "auto" }} value={round} onChange={(e) => setRound(e.target.value === "" ? "" : Number(e.target.value))}>
              <option value="">{t("No round")}</option>
              {d.rounds.map((r) => <option key={r.number} value={r.number}>{t("Round {n}", { n: r.number })}</option>)}
            </select>
            <button type="submit" className="btn btn-primary" disabled={busy || !text.trim()}>{t("Add comment")}</button>
          </div>
        </form>
      ) : (
        <p className="muted small">{t("Comments can be added while the campaign is running.")}</p>
      )}
    </section>
  );
}
