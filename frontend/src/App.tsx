import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { ThemeProvider } from "./context/ThemeContext";
import { ChatPage } from "./pages/ChatPage";
import { DashboardPage } from "./pages/DashboardPage";
import { KnowledgePage } from "./pages/KnowledgePage";
import { LoginPage } from "./pages/LoginPage";
import { ProjectPage } from "./pages/ProjectPage";
import { QuickConnectDonePage } from "./pages/QuickConnectDonePage";
import { RegisterPage } from "./pages/RegisterPage";
import { ReviewPage } from "./pages/ReviewPage";
import { ScanPage } from "./pages/ScanPage";

function HomeRedirect() {
  const { user, loading } = useAuth();
  if (loading) return null;
  return <Navigate to={user ? "/dashboard" : "/login"} replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<HomeRedirect />} />
            <Route path="login" element={<LoginPage />} />
            <Route path="register" element={<RegisterPage />} />
            <Route path="dashboard" element={<DashboardPage />} />
            <Route path="projects/:projectId" element={<ProjectPage />} />
            <Route
              path="projects/:projectId/connected"
              element={<QuickConnectDonePage />}
            />
            <Route path="chat" element={<ChatPage />} />
            <Route path="knowledge" element={<KnowledgePage />} />
            <Route path="review" element={<ReviewPage />} />
            <Route path="scans/:scanId" element={<ScanPage />} />
          </Route>
        </Routes>
      </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}
