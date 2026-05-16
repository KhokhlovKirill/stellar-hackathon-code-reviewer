import { useState } from "react";
import { RequireAuth } from "../context/AuthContext";
import { useSettings, type Lang } from "../context/SettingsContext";
import { useTheme } from "../context/ThemeContext";

// ── Saved toast ───────────────────────────────────────────────────────────────

function SavedToast({ visible }: { visible: boolean }) {
  return (
    <div
      className={`fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl bg-emerald-500 text-white text-sm font-semibold shadow-xl shadow-emerald-500/30 transition-all duration-300 ${
        visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4 pointer-events-none"
      }`}
    >
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
      </svg>
      Сохранено
    </div>
  );
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function Section({
  icon,
  title,
  desc,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  desc: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden">
      <div className="px-6 pt-6 pb-5 border-b border-slate-100 dark:border-slate-800/80 flex items-start gap-4">
        <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-500 dark:text-indigo-400 shrink-0 mt-0.5">
          {icon}
        </div>
        <div>
          <h2 className="font-bold text-slate-900 dark:text-white text-base">{title}</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">{desc}</p>
        </div>
      </div>
      <div className="px-6 py-5">{children}</div>
    </div>
  );
}

// ── Language option ───────────────────────────────────────────────────────────

function LangOption({
  active,
  flag,
  name,
  subtitle,
  onClick,
}: {
  active: boolean;
  flag: string;
  name: string;
  subtitle: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex-1 flex items-center gap-4 px-5 py-4 rounded-xl border-2 text-left transition-all duration-150 ${
        active
          ? "border-indigo-500 bg-indigo-50 dark:bg-indigo-500/10"
          : "border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 hover:border-indigo-300 dark:hover:border-indigo-500/40"
      }`}
    >
      <span className="text-3xl select-none">{flag}</span>
      <div className="flex-1 min-w-0">
        <div className={`font-bold text-sm ${active ? "text-indigo-700 dark:text-indigo-300" : "text-slate-700 dark:text-slate-200"}`}>
          {name}
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{subtitle}</div>
      </div>
      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 transition-all ${
        active
          ? "border-indigo-500 bg-indigo-500"
          : "border-slate-300 dark:border-slate-600"
      }`}>
        {active && (
          <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3">
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        )}
      </div>
    </button>
  );
}

// ── Theme option ──────────────────────────────────────────────────────────────

function ThemeOption({
  active,
  mode,
  onClick,
}: {
  active: boolean;
  mode: "light" | "dark";
  onClick: () => void;
}) {
  const isLight = mode === "light";
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex-1 rounded-xl border-2 overflow-hidden transition-all duration-150 text-left ${
        active
          ? "border-indigo-500 shadow-lg shadow-indigo-500/15"
          : "border-slate-200 dark:border-slate-700 hover:border-indigo-300 dark:hover:border-indigo-500/40"
      }`}
    >
      {/* Preview */}
      <div className={`h-24 p-3 ${isLight ? "bg-slate-50" : "bg-[#020617]"}`}>
        <div className={`h-3 w-20 rounded-md mb-2 ${isLight ? "bg-slate-200" : "bg-slate-700"}`} />
        <div className={`h-2 w-32 rounded-md mb-1.5 ${isLight ? "bg-slate-150" : "bg-slate-800"}`} />
        <div className={`h-2 w-24 rounded-md mb-3 ${isLight ? "bg-slate-150" : "bg-slate-800"}`} />
        <div className="flex gap-1.5">
          <div className={`h-5 w-14 rounded-md ${isLight ? "bg-indigo-500" : "bg-indigo-600"}`} />
          <div className={`h-5 w-16 rounded-md ${isLight ? "bg-slate-200" : "bg-slate-700"}`} />
        </div>
      </div>
      {/* Label */}
      <div className={`flex items-center gap-3 px-4 py-3 border-t ${
        isLight
          ? "bg-white border-slate-100"
          : "bg-[#0f172a] border-slate-800"
      }`}>
        <span className="text-lg">{isLight ? "☀️" : "🌙"}</span>
        <span className={`text-sm font-semibold ${isLight ? "text-slate-700" : "text-slate-200"}`}>
          {isLight ? "Светлая" : "Тёмная"}
        </span>
        {active && (
          <div className="ml-auto w-5 h-5 rounded-full bg-indigo-500 flex items-center justify-center">
            <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </div>
        )}
      </div>
    </button>
  );
}

// ── Model badge ───────────────────────────────────────────────────────────────

function ModelBadge({
  name,
  role,
  provider,
  color,
}: {
  name: string;
  role: string;
  provider: string;
  color: string;
}) {
  return (
    <div className={`flex items-start gap-3 p-4 rounded-xl border ${color}`}>
      <div className="flex-1 min-w-0">
        <div className="font-semibold text-sm text-slate-900 dark:text-white truncate">{name}</div>
        <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{role}</div>
      </div>
      <span className="text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 shrink-0">
        {provider}
      </span>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function SettingsPage() {
  return (
    <RequireAuth>
      <SettingsContent />
    </RequireAuth>
  );
}

function SettingsContent() {
  const { lang, setLang } = useSettings();
  const { theme, toggle } = useTheme();
  const [saved, setSaved] = useState(false);

  function flash() {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  function handleLang(l: Lang) {
    setLang(l);
    flash();
  }

  function handleTheme(mode: "light" | "dark") {
    if (theme !== mode) {
      toggle();
      flash();
    }
  }

  const isRu = lang === "ru";

  return (
    <div className="mx-auto max-w-2xl px-4 sm:px-6 py-10 space-y-6">
      <SavedToast visible={saved} />

      {/* Header */}
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 flex items-center justify-center shadow-lg shadow-indigo-500/25">
          <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
        </div>
        <div>
          <h1 className="text-2xl font-black text-slate-900 dark:text-white">
            {isRu ? "Настройки" : "Settings"}
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {isRu
              ? "Язык интерфейса, тема оформления и конфигурация AI-моделей"
              : "Interface language, color theme and AI model configuration"}
          </p>
        </div>
      </div>

      {/* Language */}
      <Section
        icon={
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129" />
          </svg>
        }
        title={isRu ? "Язык" : "Language"}
        desc={
          isRu
            ? "Язык интерфейса и язык, на котором Aegis AI отвечает в чате, итогах сканирования и ревью."
            : "Interface language and the language Aegis AI uses in chat, scan summaries and reviews."
        }
      >
        <div className="flex gap-3">
          <LangOption
            active={lang === "ru"}
            flag="🇷🇺"
            name="Русский"
            subtitle="Интерфейс и AI-ответы на русском"
            onClick={() => handleLang("ru")}
          />
          <LangOption
            active={lang === "en"}
            flag="🇬🇧"
            name="English"
            subtitle="Interface and AI responses in English"
            onClick={() => handleLang("en")}
          />
        </div>

        {/* Live preview */}
        <div className="mt-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 p-4">
          <p className="text-[11px] uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-2.5 font-semibold">
            {isRu ? "Предпросмотр интерфейса" : "Interface preview"}
          </p>
          <div className="flex flex-wrap gap-2">
            {[
              isRu ? "Анализ" : "Review",
              isRu ? "Проекты" : "Projects",
              isRu ? "Чат" : "Chat",
              isRu ? "База знаний" : "Knowledge",
              isRu ? "Выйти" : "Sign out",
            ].map((label) => (
              <span
                key={label}
                className="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-xs font-medium text-slate-600 dark:text-slate-300"
              >
                {label}
              </span>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            {isRu
              ? "AI отвечает: «Обнаружена SQL-инъекция в строке 42. Используйте параметризованный запрос...»"
              : "AI responds: \"SQL injection detected at line 42. Use a parameterized query...\""}
          </p>
        </div>
      </Section>

      {/* Theme */}
      <Section
        icon={
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
          </svg>
        }
        title={isRu ? "Тема оформления" : "Color theme"}
        desc={isRu ? "Светлый или тёмный интерфейс — выбор сохраняется между сессиями." : "Light or dark interface — your choice persists across sessions."}
      >
        <div className="flex gap-4">
          <ThemeOption active={theme === "light"} mode="light" onClick={() => handleTheme("light")} />
          <ThemeOption active={theme === "dark"} mode="dark" onClick={() => handleTheme("dark")} />
        </div>
      </Section>

      {/* AI models */}
      <Section
        icon={
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17H3a2 2 0 01-2-2V5a2 2 0 012-2h14a2 2 0 012 2v10a2 2 0 01-2 2h-2" />
          </svg>
        }
        title={isRu ? "AI-модели" : "AI models"}
        desc={
          isRu
            ? "Ансамбль из трёх языковых моделей: два детектора ищут уязвимости параллельно, судья оценивает и объединяет результаты."
            : "An ensemble of three language models: two detectors search for vulnerabilities in parallel, a judge evaluates and merges the results."
        }
      >
        <div className="space-y-2">
          <ModelBadge
            name="DeepSeek V4 Flash"
            role={isRu ? "Детектор A — анализ уязвимостей" : "Detector A — vulnerability analysis"}
            provider="OpenRouter"
            color="bg-violet-50 dark:bg-violet-500/5 border-violet-200 dark:border-violet-500/20"
          />
          <ModelBadge
            name="MiMo-V2-Flash"
            role={isRu ? "Детектор B — перекрёстная проверка" : "Detector B — cross-check"}
            provider="OpenRouter"
            color="bg-pink-50 dark:bg-pink-500/5 border-pink-200 dark:border-pink-500/20"
          />
          <ModelBadge
            name="MiMo-V2-Flash"
            role={isRu ? "Судья — итоговая оценка и ранжирование" : "Judge — final scoring and ranking"}
            provider="OpenRouter"
            color="bg-amber-50 dark:bg-amber-500/5 border-amber-200 dark:border-amber-500/20"
          />
        </div>

        <div className="mt-4 flex items-start gap-3 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700">
          <svg className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            {isRu
              ? "Модели выбираются автоматически из конфигурации сервера. Смена моделей доступна через переменные окружения на стороне backend."
              : "Models are selected automatically from the server configuration. Changing models is available via environment variables on the backend."}
          </p>
        </div>
      </Section>
    </div>
  );
}
