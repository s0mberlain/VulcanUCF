import { useState, type FormEvent } from "react";
import { api, type TestTemplate } from "../api";
import { useAuth } from "../auth";
import { confirmDialog, ErrorNote, Modal, useLoad } from "../components/ui";
import { Markdown, MarkdownField } from "../components/Markdown";
import { Technique } from "../components/TestParts";
import { fmtDate } from "../lib/format";
import { TECHNIQUE_PATTERN } from "../lib/tests";
import { t } from "../i18n";

export default function TestLibrary() {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const [technique, setTechnique] = useState("");
  const [q, setQ] = useState("");
  const list = useLoad<TestTemplate[]>(() => api.library({ technique: technique.trim(), q: q.trim() }), [technique, q]);
  const [editing, setEditing] = useState<TestTemplate | "new" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function remove(x: TestTemplate) {
    if (!(await confirmDialog(t("Delete the template {title}? Tests made from it stay as they are.", { title: x.title }), { danger: true, confirmLabel: t("Delete") }))) return;
    try {
      await api.deleteTemplate(x.id);
      await list.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Test library")}</h1>
          <div className="subtitle">{t("Reusable test scripts. A test made from a template is a copy.")}</div>
        </div>
        {editor && (
          <div className="row-actions">
            <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
              {t("+ New template")}
            </button>
          </div>
        )}
      </header>
      <ErrorNote error={error ?? list.error} />
      <section className="card uc-filters" aria-label={t("Filter templates")}>
        <label className="sr-only" htmlFor="lib-q">{t("Search")}</label>
        <input id="lib-q" className="input input-sm" placeholder={t("Search title and procedure")} value={q} onChange={(e) => setQ(e.target.value)} />
        <label className="sr-only" htmlFor="lib-t">{t("ATT&CK technique")}</label>
        <input id="lib-t" className="input input-sm" placeholder={t("Technique, e.g. T1059")} value={technique} onChange={(e) => setTechnique(e.target.value.toUpperCase())} />
      </section>
      {list.data && !list.data.length && (
        <div className="empty">
          <h2>{technique || q ? t("No template matches.") : t("The library is empty")}</h2>
          {!(technique || q) && <p>{t("Save a test as a template, or create one here, to reuse its procedure.")}</p>}
        </div>
      )}
      {list.data && list.data.length > 0 && (
        <section className="card table-card">
          <div className="scroll-x">
            <table className="table">
              <thead>
                <tr>
                  <th>{t("Template")}</th>
                  <th>{t("ATT&CK technique")}</th>
                  <th className="num">{t("Used")}</th>
                  <th>{t("Created")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.data.map((x) => (
                  <tr key={x.id}>
                    <td>
                      <div className="strong-500">{x.title}</div>
                      {x.tools && <div className="small muted">{x.tools}</div>}
                    </td>
                    <td><Technique id={x.technique} name={x.technique_name} /></td>
                    <td className="num">{x.uses}</td>
                    <td className="small">{fmtDate(x.created_at)} · {x.created_by}</td>
                    <td className="num">
                      <button type="button" className="btn btn-sm" onClick={() => setEditing(x)}>{editor ? t("Change") : t("Show")}</button>
                      {editor && (
                        <button type="button" className="btn btn-sm btn-danger" style={{ marginLeft: 6 }} onClick={() => void remove(x)}>
                          {t("Delete")}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      {editing && <TemplateDialog template={editing === "new" ? null : editing} readOnly={!editor} onClose={() => setEditing(null)} onSaved={() => void list.reload()} />}
    </>
  );
}

function TemplateDialog({ template, readOnly, onClose, onSaved }: { template: TestTemplate | null; readOnly: boolean; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({
    title: template?.title ?? "",
    technique: template?.technique ?? "",
    description: template?.description ?? "",
    procedure: template?.procedure ?? "",
    tools: template?.tools ?? "",
    prerequisites: template?.prerequisites ?? "",
    expected_detection: template?.expected_detection ?? "",
  });
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      if (template) await api.updateTemplate(template.id, f);
      else await api.createTemplate(f);
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <Modal title={template ? template.title : t("New template")} open onClose={onClose} wide>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error} />
        <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0 }} disabled={readOnly}>
          <div className="form-grid">
            <label className="field grow-2">
              {t("Title")} *
              <input className="input" required maxLength={200} value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} />
            </label>
            <label className="field">
              {t("ATT&CK technique")} *
              <input className="input mono" required pattern={TECHNIQUE_PATTERN} placeholder="T1059.001" value={f.technique} onChange={(e) => setF({ ...f, technique: e.target.value.trim().toUpperCase() })} />
            </label>
          </div>
          {readOnly ? (
            f.description && <Markdown text={f.description} />
          ) : (
            <MarkdownField label={t("Description")} value={f.description} onChange={(v) => setF({ ...f, description: v })} />
          )}
          <label className="field">
            {t("Procedure")}
            <textarea className="input textarea mono" rows={6} maxLength={10000} value={f.procedure} onChange={(e) => setF({ ...f, procedure: e.target.value })} />
          </label>
          <div className="form-grid">
            <label className="field">
              {t("Tools")}
              <input className="input" maxLength={500} value={f.tools} onChange={(e) => setF({ ...f, tools: e.target.value })} />
            </label>
            <label className="field">
              {t("Expected detection (optional)")}
              <input className="input" value={f.expected_detection} onChange={(e) => setF({ ...f, expected_detection: e.target.value })} />
            </label>
          </div>
          <label className="field">
            {t("Prerequisites and cleanup (optional)")}
            <textarea className="input textarea" rows={2} value={f.prerequisites} onChange={(e) => setF({ ...f, prerequisites: e.target.value })} />
          </label>
        </fieldset>
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>{readOnly ? t("Close") : t("Cancel")}</button>
          {!readOnly && <button type="submit" className="btn btn-primary">{t("Save")}</button>}
        </div>
      </form>
    </Modal>
  );
}
