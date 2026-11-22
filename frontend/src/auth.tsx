import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { api, setLeavingSession, setUnauthorizedHandler, type Role, type User } from "./api";
import { setLang, t } from "./i18n";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string, otp?: string) => Promise<void>;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
  can: (...roles: Role[]) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api
      .me()
      .then((u) => {
        if (!setLang(u.locale)) setUser(u);
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      // remember the page, so signing in again brings the person back to it
      const from = window.location.pathname + window.location.search;
      navigate("/login", { replace: true, state: { from, expired: true } });
    });
  }, [navigate]);

  const login = useCallback(async (username: string, password: string, otp?: string) => {
    const u = await api.login(username, password, otp);
    setLeavingSession(false);
    if (!setLang(u.locale)) setUser(u);
  }, []);

  const refresh = useCallback(async () => {
    setUser(await api.me());
  }, []);

  const logout = useCallback(async () => {
    setLeavingSession(true);
    await api.logout().catch(() => undefined);
    setUser(null);
    navigate("/login", { replace: true });
  }, [navigate]);

  const can = useCallback((...roles: Role[]) => !!user && roles.includes(user.role), [user]);

  return <AuthContext.Provider value={{ user, loading, login, logout, can, refresh }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

export function RequireAuth({ children, roles }: { children: ReactNode; roles?: Role[] }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  // red team accounts only have their campaigns and their account
  if (user.role === "red_team" && !/^\/(verification\/(campaigns|tests)|account)/.test(location.pathname)) {
    return <Navigate to="/verification/campaigns" replace />;
  }
  if (roles && !roles.includes(user.role)) {
    return (
      <div className="empty">
        <h3>{t("No access")}</h3>
        <p>{t("Your role ({role}) cannot open this page.", { role: user.role })}</p>
      </div>
    );
  }
  return <>{children}</>;
}

export const ROLE_LABEL: Record<Role, string> = {
  admin: t("Admin"),
  analyst: t("Analyst"),
  auditor: t("Auditor (read-only)"),
  red_team: t("Red team"),
};
