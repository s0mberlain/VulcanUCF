import { t } from "../i18n";
export default function Placeholder({ title, milestone }: { title: string; milestone?: string }) {
  return (
    <>
      <header className="page-header">
        <h1>{title}</h1>
      </header>
      <div className="empty">
        <h3>{t("Not built yet")}</h3>
        <p>
          {milestone
            ? t("This screen is planned for milestone {m}.", { m: milestone })
            : t("This page does not exist.")}
        </p>
      </div>
    </>
  );
}
