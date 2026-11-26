import DOMPurify from "dompurify";
import { marked } from "marked";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { t } from "../i18n";

marked.setOptions({ gfm: true, breaks: true });

// Links in user text open in a new tab and never pass the referrer or window handle.
DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  if (node.tagName === "A" && node.getAttribute("href")) {
    node.setAttribute("target", "_blank");
    node.setAttribute("rel", "noopener noreferrer nofollow");
  }
});

/** Markdown (GitHub flavour) to sanitised HTML; raw HTML, scripts and images are removed. */
export function markdownToHtml(src: string): string {
  const html = marked.parse(src, { async: false }) as string;
  return DOMPurify.sanitize(html, {
    FORBID_TAGS: ["img", "style", "form", "input", "button", "iframe"],
    FORBID_ATTR: ["style"],
  });
}

/**
 * Code blocks (```lang … ```) get a head row with the language and a copy button (#84), so
 * queries and log samples in a text read like code and can be taken over as they are.
 */
function decorateCodeBlocks(root: HTMLElement) {
  for (const pre of Array.from(root.querySelectorAll("pre"))) {
    if (pre.parentElement?.classList.contains("md-code")) continue;
    const code = pre.querySelector("code");
    const lang = /(?:^|\s)language-([\w+#.-]+)/.exec(code?.className ?? "")?.[1] ?? "";
    const box = document.createElement("div");
    box.className = "md-code";
    const head = document.createElement("div");
    head.className = "md-code-head";
    const label = document.createElement("span");
    label.className = "md-code-lang";
    label.textContent = lang || t("Code");
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "md-code-copy";
    copy.textContent = t("Copy");
    copy.addEventListener("click", () => {
      const done = (ok: boolean) => {
        copy.textContent = ok ? t("Copied") : t("Copy failed");
        window.setTimeout(() => (copy.textContent = t("Copy")), 1500);
      };
      navigator.clipboard?.writeText((code ?? pre).textContent ?? "").then(() => done(true), () => done(false)) ?? done(false);
    });
    head.append(label, copy);
    pre.replaceWith(box);
    box.append(head, pre);
  }
}

/** Read-only Markdown text. */
export function Markdown({ text, className = "" }: { text: string; className?: string }) {
  const html = useMemo(() => markdownToHtml(text), [text]);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) decorateCodeBlocks(ref.current);
  }, [html]);
  return <div ref={ref} className={"md " + className} dangerouslySetInnerHTML={{ __html: html }} />;
}

/**
 * Text area that stores Markdown: "Write" edits the source, "Preview" shows it rendered.
 * Read-only users only see the rendered text.
 */
export function MarkdownField({
  label,
  value,
  onChange,
  readOnly = false,
  rows = 3,
  placeholder,
  hint,
  maxLength,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  readOnly?: boolean;
  rows?: number;
  placeholder?: string;
  /** Replaces the default Markdown hint below the text area. */
  hint?: string;
  maxLength?: number;
}) {
  const id = useId();
  // Until the user picks a tab, text shows rendered and an empty field opens for writing
  // (also when the text arrives after the first render).
  const [picked, setPreview] = useState<boolean | null>(null);
  const preview = picked ?? !!value.trim();
  const showPreview = readOnly || preview;

  return (
    <div className="field md-field">
      <div className="md-head">
        <label htmlFor={showPreview ? undefined : id} id={id + "-l"}>
          {label}
        </label>
        {!readOnly && (
          <div className="md-tabs" role="group" aria-label={t("Markdown view")}>
            <button
              type="button"
              className={"md-tab" + (!preview ? " active" : "")}
              aria-pressed={!preview}
              onClick={() => setPreview(false)}
            >
              {t("Write")}
            </button>
            <button
              type="button"
              className={"md-tab" + (preview ? " active" : "")}
              aria-pressed={preview}
              onClick={() => setPreview(true)}
            >
              {t("Preview")}
            </button>
          </div>
        )}
      </div>
      {showPreview ? (
        <div
          className="md-preview"
          role="region"
          aria-labelledby={id + "-l"}
          onDoubleClick={readOnly ? undefined : () => setPreview(false)}
          title={readOnly ? undefined : t("Double-click to edit")}
        >
          {value.trim() ? <Markdown text={value} /> : <span className="muted small">{t("Nothing written yet.")}</span>}
        </div>
      ) : (
        <>
          <textarea
            id={id}
            className="input textarea"
            rows={rows}
            value={value}
            placeholder={placeholder}
            maxLength={maxLength}
            onChange={(ev) => {
              if (picked === null) setPreview(false);
              onChange(ev.target.value);
            }}
          />
          <span className="small muted">{hint ?? t("Markdown: **bold**, *italic*, `code`, - lists, [link](https://…)")}</span>
        </>
      )}
    </div>
  );
}
