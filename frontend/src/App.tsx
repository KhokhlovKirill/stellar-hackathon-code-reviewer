import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AuthProvider } from "./context/AuthContext";
import { SettingsProvider } from "./context/SettingsContext";
import { ThemeProvider } from "./context/ThemeContext";
import { ChatPage } from "./pages/ChatPage";
import { SettingsPage } from "./pages/SettingsPage";
import { DashboardPage } from "./pages/DashboardPage";
import { KnowledgePage } from "./pages/KnowledgePage";
import { LandingPage } from "./pages/LandingPage";
import { LoginPage } from "./pages/LoginPage";
import { ProjectPage } from "./pages/ProjectPage";
import { QuickConnectDonePage } from "./pages/QuickConnectDonePage";
import { RegisterPage } from "./pages/RegisterPage";
import { ReviewPage } from "./pages/ReviewPage";
import { ScanPage } from "./pages/ScanPage";

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
      <SettingsProvider>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<LandingPage />} />
            <Route path="login" element={<LoginPage />} />
            <Route path="register" element={<RegisterPage />} />
            <Route path="dashboard" element={<DashboardPage />} />
            <Route path="projects/:projectId" element={<ProjectPage />} />
            <Route
              path="projects/:projectId/connected"
              element={<QuickConnectDonePage />}
            />
            <Route path="chat" element={<ChatPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="knowledge" element={<KnowledgePage />} />
            <Route path="review" element={<ReviewPage />} />
            <Route path="scans/:scanId" element={<ScanPage />} />
          </Route>
        </Routes>
      </AuthProvider>
      </SettingsProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}
