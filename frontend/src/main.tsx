import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import "./fonts.css";
import "./styles.css";
import { loadLanguage } from "./i18n";

async function start() {
  // the texts first: the app's modules translate labels when they are loaded
  await loadLanguage();
  const { default: App } = await import("./App");
  // A data router (one catch-all route around the app's own <Routes>) so pages can hold back a
  // navigation while a form has unsaved changes (useBlocker).
  const router = createBrowserRouter([{ path: "*", element: <App /> }]);
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <RouterProvider router={router} />
    </React.StrictMode>,
  );
}

void start();
