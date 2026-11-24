import { lazy, type ComponentType } from "react";

const RELOADED = "magma.chunk-reload";

/**
 * A page loaded on first visit (its own JS file). After a new release an open tab may ask for a
 * file of the old build that no longer exists: then the page reloads once to get the new build.
 */
export function lazyPage(load: () => Promise<{ default: ComponentType }>) {
  return lazy(() =>
    load().then(
      (m) => {
        try {
          sessionStorage.removeItem(RELOADED);
        } catch {
          /* storage blocked */
        }
        return m;
      },
      (err: unknown) => {
        let first = false;
        try {
          first = !sessionStorage.getItem(RELOADED);
          if (first) sessionStorage.setItem(RELOADED, "1");
        } catch {
          /* storage blocked: no reload, so it cannot loop */
        }
        if (first) {
          window.location.reload();
          return new Promise<never>(() => undefined);
        }
        throw err;
      },
    ),
  );
}
