/** Navigation icons: one 24 px grid, 1.7 px round stroke, drawn for this menu. */
const PATHS: Record<string, string> = {
  dashboard: "M4 4h6v7H4zM14 4h6v4h-6zM14 12h6v8h-6zM4 15h6v5H4z",
  usecases: "M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5M3 17.5l9 5 9-5",
  requests: "M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01",
  verification: "M12 21a9 9 0 100-18 9 9 0 000 18zM8 12.5l3 3 5-6",
  priorities: "M4 6h16M4 12h11M4 18h6",
  threat: "M12 3l8 3v6c0 4.6-3.2 7.8-8 9-4.8-1.2-8-4.4-8-9V6l8-3z",
  attack: "M12 8a4 4 0 100 8 4 4 0 000-8zM12 2v4M12 18v4M2 12h4M18 12h4",
  output: "M5 20V11M12 20V4M19 20v-7",
  history: "M12 21a9 9 0 100-18 9 9 0 000 18zM12 7v5l3.5 2",
  drivers: "M5 21V4M5 4h12l-2.5 4 2.5 4H5",
  stride: "M6 3v12M6 15a3 3 0 100 6 3 3 0 000-6zM18 9a3 3 0 100-6 3 3 0 000 6zM18 9c0 5-12 2-12 6",
  references: "M6 3h12v18H6zM9.5 8h5M9.5 12h5M9.5 16h3",
  transfer: "M7 20V5M7 5L4 8M7 5l3 3M17 4v15M17 19l-3-3M17 19l3-3",
  integrations: "M9 3v5M15 3v5M6 8h12v3a6 6 0 01-12 0V8zM12 17v4",
  audit: "M11 4a7 7 0 100 14 7 7 0 000-14zM20 20l-4.2-4.2M8.5 11h5M11 8.5v5",
  users: "M9 11a3.5 3.5 0 100-7 3.5 3.5 0 000 7zM2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6M17 4.5a3 3 0 010 6M18 14.3c2.3.5 3.5 2.4 3.5 5.7",
  settings: "M4 7h9M17 7h3M4 17h3M11 17h9M15 5v4h2V5zM9 15v4h2v-4z",
  signout: "M10 4H5v16h5M15 8l4 4-4 4M19 12H9",
};

export type NavIconKey = keyof typeof PATHS;

export default function NavIcon({ name }: { name: NavIconKey }) {
  return (
    <svg className="nav-ico" width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d={PATHS[name]} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
