/**
 * Small i18n layer for English, German and Dutch.
 *
 * The English text is the key: `t("Use cases")`. German and Dutch come from `locales/*.json`;
 * a text missing there falls back to English. Placeholders: `t("{n} rules", { n: 3 })`.
 * Changing the language reloads the page, so plain `t()` calls are enough everywhere (also in
 * module-level label maps) and no hook or context is needed.
 *
 * Only the dictionary of the current language is downloaded: main.tsx awaits loadLanguage()
 * before it imports the app, so module-level `t()` calls already see it.
 */

export type Lang = "en" | "de" | "nl";

export const LANGUAGES: { code: Lang; label: string }[] = [
  { code: "en", label: "English" },
  { code: "de", label: "Deutsch" },
  { code: "nl", label: "Nederlands" },
];

// Check that every text is translated: npm run i18n:check
const LOADERS: Record<Lang, () => Promise<Record<string, string>>> = {
  en: async () => ({}),
  de: () => import("./locales/de.json").then((m) => m.default),
  nl: () => import("./locales/nl.json").then((m) => m.default),
};
let dict: Record<string, string> = {};
const STORAGE_KEY = "magma.lang";

function isLang(v: unknown): v is Lang {
  return v === "en" || v === "de" || v === "nl";
}

function initialLang(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (isLang(saved)) return saved;
  } catch {
    /* storage blocked */
  }
  const nav = (typeof navigator !== "undefined" ? navigator.language : "en").slice(0, 2).toLowerCase();
  return isLang(nav) ? nav : "en";
}

const current: Lang = initialLang();

export function getLang(): Lang {
  return current;
}

/** BCP 47 tag for Intl formatters. */
export function locale(): string {
  return { en: "en-GB", de: "de-DE", nl: "nl-NL" }[current];
}

/** Switch the language; reloads the page when it changes. Returns true when it reloads. */
export function setLang(lang: string | null | undefined): boolean {
  if (!isLang(lang) || lang === current) return false;
  try {
    localStorage.setItem(STORAGE_KEY, lang);
    if (localStorage.getItem(STORAGE_KEY) !== lang) return false;
  } catch {
    return false; // storage blocked: a reload would not keep the choice (and could loop)
  }
  window.location.reload();
  return true;
}

/** Load the current language's texts; English (the keys) when that fails. */
export async function loadLanguage(): Promise<void> {
  try {
    dict = await LOADERS[current]();
  } catch {
    dict = {};
  }
}

export function t(text: string, vars?: Record<string, string | number | null | undefined>): string {
  let out = dict[text] ?? text;
  if (vars) out = out.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k] ?? "") : m));
  return out;
}

if (typeof document !== "undefined") document.documentElement.lang = current;
