import { useEffect, useState } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";
import { useTheme } from "../context/ThemeContext";
import { AegisLogo } from "./AegisLogo";

function LangToggle() {
  const { lang, setLang } = useSettings();
  return (
    <button
      type="button"
      onClick={() => setLang(lang === "ru" ? "en" : "ru")}
      title={lang === "ru" ? "Switch to English" : "Переключить на русский"}
      className="px-2 py-1.5 rounded-lg text-xs font-bold text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
    >
      {lang === "ru" ? "RU" : "EN"}
    </button>
  );
}

function SunIcon() {
  return (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="5" />
      <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" strokeLinecap="round" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
      <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button
      type="button"
      onClick={toggle}
      title={theme === "dark" ? "Светлая тема" : "Тёмная тема"}
      className="p-2 rounded-lg text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
    >
      {theme === "dark" ? <SunIcon /> : <MoonIcon />}
    </button>
  );
}

function NavLink({
  to,
  children,
  onClick,
}: {
  to: string;
  children: React.ReactNode;
  onClick?: () => void;
}) {
  const loc = useLocation();
  const active = loc.pathname === to || (to !== "/" && loc.pathname.startsWith(to + "/"));
  return (
    <Link
      to={to}
      onClick={onClick}
      className={`px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150 ${
        active
          ? "bg-indigo-500/15 text-indigo-600 dark:text-indigo-300"
          : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800"
      }`}
    >
      {children}
    </Link>
  );
}

export function Layout() {
  const { user, logout } = useAuth();
  const { t } = useSettings();
  const loc = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  // Close mobile menu on navigation
  useEffect(() => { setMobileOpen(false); }, [loc.pathname]);

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-[#020617] text-slate-900 dark:text-white transition-colors duration-200">
      {/* Navbar */}
      <header className="sticky top-0 z-50 border-b border-slate-200 dark:border-slate-800/60 bg-white/90 dark:bg-[#020617]/90 backdrop-blur-xl transition-colors duration-200">
        <div className="mx-auto max-w-7xl px-4 sm:px-6">
          <div className="flex h-16 items-center justify-between gap-4">
            {/* Logo */}
            <Link to="/" className="flex items-center gap-2.5 shrink-0 group">
              <AegisLogo size={30} />
              <span className="text-xl font-black tracking-tighter bg-gradient-to-r from-indigo-500 to-violet-500 dark:from-indigo-300 dark:to-violet-300 bg-clip-text text-transparent group-hover:from-indigo-600 group-hover:to-violet-600 dark:group-hover:from-white dark:group-hover:to-indigo-200 transition-all">
                AEGIS
              </span>
            </Link>

            {/* Desktop nav */}
            <nav className="hidden md:flex items-center gap-1 flex-1 justify-center">
              <NavLink to="/">{t("nav.product")}</NavLink>
              <NavLink to="/review">{t("nav.review")}</NavLink>
              {user && <NavLink to="/dashboard">{t("nav.projects")}</NavLink>}
              {user && <NavLink to="/chat">{t("nav.chat")}</NavLink>}
              {user && <NavLink to="/knowledge">{t("nav.knowledge")}</NavLink>}
              {user && <NavLink to="/settings">{t("nav.settings")}</NavLink>}
            </nav>

            {/* Right controls */}
            <div className="flex items-center gap-1 shrink-0">
              <LangToggle />
              <ThemeToggle />
              {/* Desktop auth */}
              <div className="hidden md:flex items-center gap-1">
                {user ? (
                  <>
                    <span className="hidden lg:block text-xs text-slate-400 dark:text-slate-500 max-w-[160px] truncate mx-2">
                      {user.email}
                    </span>
                    <button
                      type="button"
                      onClick={() => void logout()}
                      className="px-3 py-1.5 rounded-lg text-sm text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
                    >
                      {t("nav.logout")}
                    </button>
                  </>
                ) : (
                  <>
                    <Link
                      to="/login"
                      className="px-3 py-2 rounded-lg text-sm text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
                    >
                      {t("nav.login")}
                    </Link>
                    <Link
                      to="/register"
                      className="ml-1 px-4 py-2 rounded-lg text-sm font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-lg shadow-indigo-500/20"
                    >
                      {t("nav.register")}
                    </Link>
                  </>
                )}
              </div>

              {/* Mobile hamburger */}
              <button
                type="button"
                onClick={() => setMobileOpen((v) => !v)}
                className="md:hidden p-2 rounded-lg text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
                aria-label="Меню"
              >
                {mobileOpen ? (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
                  </svg>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Mobile dropdown menu */}
        {mobileOpen && (
          <div className="md:hidden border-t border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-[#020617]/95 backdrop-blur-xl px-4 py-3">
            <nav className="space-y-1 mb-3">
              <NavLink to="/" onClick={() => setMobileOpen(false)}>{t("nav.product")}</NavLink>
              <NavLink to="/review" onClick={() => setMobileOpen(false)}>{t("nav.review")}</NavLink>
              {user && <NavLink to="/dashboard" onClick={() => setMobileOpen(false)}>{t("nav.projects")}</NavLink>}
              {user && <NavLink to="/chat" onClick={() => setMobileOpen(false)}>{t("nav.chat")}</NavLink>}
              {user && <NavLink to="/knowledge" onClick={() => setMobileOpen(false)}>{t("nav.knowledge")}</NavLink>}
              {user && <NavLink to="/settings" onClick={() => setMobileOpen(false)}>{t("nav.settings")}</NavLink>}
            </nav>
            <div className="border-t border-slate-100 dark:border-slate-800 pt-3">
              {user ? (
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400 dark:text-slate-500 truncate max-w-[200px]">{user.email}</span>
                  <button
                    type="button"
                    onClick={() => { void logout(); setMobileOpen(false); }}
                    className="px-3 py-1.5 rounded-lg text-sm text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
                  >
                    {t("nav.logout")}
                  </button>
                </div>
              ) : (
                <div className="flex gap-2">
                  <Link
                    to="/login"
                    onClick={() => setMobileOpen(false)}
                    className="flex-1 text-center px-3 py-2 rounded-lg text-sm text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white border border-slate-200 dark:border-slate-700 transition-all"
                  >
                    {t("nav.login")}
                  </Link>
                  <Link
                    to="/register"
                    onClick={() => setMobileOpen(false)}
                    className="flex-1 text-center px-4 py-2 rounded-lg text-sm font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-all"
                  >
                    {t("nav.register")}
                  </Link>
                </div>
              )}
            </div>
          </div>
        )}
      </header>

      <main className="flex-1">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-800/40 transition-colors duration-200">
        <div className="mx-auto max-w-7xl px-4 py-5 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-600">
          <div className="flex items-center gap-2">
            <AegisLogo size={14} />
            <span>Aegis © 2026 — AI-анализ безопасности кода</span>
          </div>
        </div>
        <div className="border-t border-slate-800 bg-slate-950 py-5 flex justify-center">
          <img
            src="/partner-logo.png"
            alt="Партнёры"
            className="h-8 object-contain opacity-80 hover:opacity-100 transition-opacity"
          />
        </div>
      </footer>
    </div>
  );
}
