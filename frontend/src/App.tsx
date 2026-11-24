import { Route, Routes } from "react-router-dom";
import { AuthProvider, RequireAuth } from "./auth";
import Layout from "./components/Layout";
import { ConfirmHost } from "./components/ui";
import { lazyPage } from "./lazyPage";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";

// Every other screen is its own file, loaded when it is first opened.
const Account = lazyPage(() => import("./pages/Account"));
const AttackPage = lazyPage(() => import("./pages/AttackPage"));
const AuditLog = lazyPage(() => import("./pages/AuditLog"));
const CampaignDetail = lazyPage(() => import("./pages/CampaignDetail"));
const Campaigns = lazyPage(() => import("./pages/Campaigns"));
const DetectionRequests = lazyPage(() => import("./pages/DetectionRequests"));
const Drivers = lazyPage(() => import("./pages/Drivers"));
const Gaps = lazyPage(() => import("./pages/Gaps"));
const History = lazyPage(() => import("./pages/History"));
const ImportExport = lazyPage(() => import("./pages/ImportExport"));
const Integrations = lazyPage(() => import("./pages/Integrations"));
const Interview = lazyPage(() => import("./pages/Interview"));
const OutputPage = lazyPage(() => import("./pages/OutputPage"));
const Priorities = lazyPage(() => import("./pages/Priorities"));
const QuickTests = lazyPage(() => import("./pages/QuickTests"));
const References = lazyPage(() => import("./pages/References"));
const RuleDetail = lazyPage(() => import("./pages/RuleDetail"));
const Settings = lazyPage(() => import("./pages/Settings"));
const StrideMappingPage = lazyPage(() => import("./pages/StrideMappingPage"));
const SystemDetail = lazyPage(() => import("./pages/SystemDetail"));
const Systems = lazyPage(() => import("./pages/Systems"));
const TestDetail = lazyPage(() => import("./pages/TestDetail"));
const Tasks = lazyPage(() => import("./pages/Tasks"));
const TestLibrary = lazyPage(() => import("./pages/TestLibrary"));
const UseCases = lazyPage(() => import("./pages/UseCases"));
const Users = lazyPage(() => import("./pages/Users"));
const Verification = lazyPage(() => import("./pages/Verification"));

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
          <Route path="tasks" element={<Tasks />} />
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
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
