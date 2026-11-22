import { Route, Routes } from "react-router-dom";
import { AuthProvider, RequireAuth } from "./auth";
import Layout from "./components/Layout";
import AttackPage from "./pages/AttackPage";
import AuditLog from "./pages/AuditLog";
import Dashboard from "./pages/Dashboard";
import DetectionRequests from "./pages/DetectionRequests";
import Drivers from "./pages/Drivers";
import Account from "./pages/Account";
import History from "./pages/History";
import Priorities from "./pages/Priorities";
import ImportExport from "./pages/ImportExport";
import Login from "./pages/Login";
import Integrations from "./pages/Integrations";
import OutputPage from "./pages/OutputPage";
import Placeholder from "./pages/Placeholder";
import References from "./pages/References";
import RuleDetail from "./pages/RuleDetail";
import UseCases from "./pages/UseCases";
import Users from "./pages/Users";
import Settings from "./pages/Settings";
import Systems from "./pages/Systems";
import SystemDetail from "./pages/SystemDetail";
import Interview from "./pages/Interview";
import StrideMappingPage from "./pages/StrideMappingPage";
import Verification from "./pages/Verification";
import { NAV_ITEMS } from "./nav";
import Campaigns from "./pages/Campaigns";
import CampaignDetail from "./pages/CampaignDetail";
import Gaps from "./pages/Gaps";
import QuickTests from "./pages/QuickTests";
import TestLibrary from "./pages/TestLibrary";
import TestDetail from "./pages/TestDetail";
import { t } from "./i18n";
import { ConfirmHost } from "./components/ui";

export default function App() {
  return (
    <AuthProvider>
      <ConfirmHost />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="usecases" element={<UseCases />} />
          <Route path="usecases/l3/:code" element={<RuleDetail />} />
          <Route path="usecases/requests" element={<DetectionRequests />} />
          <Route path="verification" element={<Verification />} />
          <Route path="verification/campaigns" element={<Campaigns />} />
          <Route path="verification/campaigns/:id" element={<CampaignDetail />} />
          <Route path="verification/quick-tests" element={<QuickTests />} />
          <Route path="verification/gaps" element={<Gaps />} />
          <Route path="verification/library" element={<TestLibrary />} />
          <Route path="verification/tests/:id" element={<TestDetail />} />
          <Route path="drivers" element={<Drivers />} />
          <Route path="systems" element={<Systems />} />
          <Route path="systems/:id" element={<SystemDetail />} />
          <Route path="interviews/:id" element={<Interview />} />
          <Route path="stride-mapping" element={<StrideMappingPage />} />
          <Route path="references" element={<References />} />
          <Route path="import-export" element={<ImportExport />} />
          <Route path="history" element={<History />} />
          <Route path="priorities" element={<Priorities />} />
          <Route path="attack" element={<AttackPage />} />
          <Route path="output" element={<OutputPage />} />
          <Route path="integrations" element={<Integrations />} />
          <Route path="account" element={<Account />} />
          <Route
            path="audit"
            element={
              <RequireAuth roles={["admin", "auditor"]}>
                <AuditLog />
              </RequireAuth>
            }
          />
          <Route
            path="settings"
            element={
              <RequireAuth roles={["admin"]}>
                <Settings />
              </RequireAuth>
            }
          />
          <Route
            path="admin/users"
            element={
              <RequireAuth roles={["admin"]}>
                <Users />
              </RequireAuth>
            }
          />
          {NAV_ITEMS.filter((n) => n.milestone).map((n) => (
            <Route
              key={n.path}
              path={n.path.slice(1)}
              element={<Placeholder title={n.label} milestone={n.milestone} />}
            />
          ))}
          <Route path="*" element={<Placeholder title={t("Page not found")} />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
