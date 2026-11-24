import { t } from "../i18n";

export default function NotFound() {
  return (
    <>
      <header className="page-header">
        <h1>{t("Page not found")}</h1>
      </header>
      <div className="empty">
        <p>{t("This page does not exist.")}</p>
      </div>
    </>
  );
}
