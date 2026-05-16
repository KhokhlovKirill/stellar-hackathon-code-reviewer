import { Chat } from "../components/Chat";
import type { QuickQuestion } from "../components/Chat";
import { RequireAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";

const QUICK: Record<"ru" | "en", QuickQuestion[]> = {
  ru: [
    { icon: "🔐", label: "Что такое SAST?", question: "Что такое SAST-анализ и чем он отличается от DAST?" },
    { icon: "🛡️", label: "LLM в безопасности", question: "Как Aegis использует LLM-модели для анализа кода?" },
    { icon: "⚡", label: "Настроить webhook", question: "Как шаг за шагом настроить webhook для GitHub репозитория?" },
    { icon: "📋", label: "OWASP Top 10", question: "Объясни OWASP Top 10 — самые распространённые уязвимости" },
    { icon: "📊", label: "Risk Score", question: "Как интерпретировать Risk Score от 0 до 100?" },
    { icon: "💉", label: "SQL инъекция", question: "Что такое SQL-инъекция и как защитить код от неё?" },
    { icon: "🔧", label: "Исправить XSS", question: "Как обнаружить и исправить XSS-уязвимость в JavaScript?" },
    { icon: "🔑", label: "Хранение секретов", question: "Лучшие практики безопасного хранения токенов и паролей?" },
  ],
  en: [
    { icon: "🔐", label: "What is SAST?", question: "What is SAST analysis and how does it differ from DAST?" },
    { icon: "🛡️", label: "LLMs for security", question: "How does Aegis use LLM models to analyze code?" },
    { icon: "⚡", label: "Set up webhook", question: "How do I set up a GitHub repository webhook step by step?" },
    { icon: "📋", label: "OWASP Top 10", question: "Explain the OWASP Top 10 — the most common vulnerabilities" },
    { icon: "📊", label: "Risk Score", question: "How should I interpret a Risk Score from 0 to 100?" },
    { icon: "💉", label: "SQL injection", question: "What is SQL injection and how do I protect code against it?" },
    { icon: "🔧", label: "Fix XSS", question: "How do I detect and fix an XSS vulnerability in JavaScript?" },
    { icon: "🔑", label: "Secret storage", question: "Best practices for securely storing tokens and passwords?" },
  ],
};

const TOPICS: Record<"ru" | "en", { icon: string; label: string; desc: string }[]> = {
  ru: [
    { icon: "🛡️", label: "Уязвимости", desc: "Типы атак, CWE, CVE" },
    { icon: "🔧", label: "Исправления", desc: "Как писать безопасный код" },
    { icon: "⚙️", label: "Интеграция", desc: "Webhooks, API, CI/CD" },
    { icon: "📊", label: "Аналитика", desc: "Risk Score, отчёты" },
  ],
  en: [
    { icon: "🛡️", label: "Vulnerabilities", desc: "Attack types, CWE, CVE" },
    { icon: "🔧", label: "Fixes", desc: "Writing secure code" },
    { icon: "⚙️", label: "Integration", desc: "Webhooks, API, CI/CD" },
    { icon: "📊", label: "Analytics", desc: "Risk Score, reports" },
  ],
};

export function ChatPage() {
  const { lang } = useSettings();
  const isRu = lang === "ru";

  return (
    <RequireAuth>
      <div className="mx-auto max-w-5xl px-4 sm:px-6 py-10">
        <div className="mb-8">
          <div className="inline-flex items-center gap-2 bg-indigo-50 dark:bg-indigo-500/10 border border-indigo-200 dark:border-indigo-500/20 rounded-full px-4 py-1.5 text-xs font-medium text-indigo-600 dark:text-indigo-300 mb-5">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse" />
            Aegis AI · {isRu ? "Бета" : "Beta"}
          </div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">
            {isRu ? "AI-ассистент по безопасности" : "AI security assistant"}
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-base">
            {isRu
              ? "Задайте вопрос об уязвимостях, настройке интеграций или результатах сканирования."
              : "Ask about vulnerabilities, integration setup, or scan results."}
          </p>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Chat — appears first on mobile */}
          <div className="lg:col-span-2 order-1 lg:order-none">
            <Chat quickQuestions={QUICK[lang]} className="h-[580px]" />
          </div>

          {/* Topics — appears after chat on mobile */}
          <aside className="space-y-4 order-2 lg:order-none">
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
              {isRu ? "Темы" : "Topics"}
            </p>
            <div className="grid grid-cols-2 lg:grid-cols-1 gap-2">
              {TOPICS[lang].map((c) => (
                <div
                  key={c.label}
                  className="flex items-center gap-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-3"
                >
                  <span className="text-xl">{c.icon}</span>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-900 dark:text-white">
                      {c.label}
                    </p>
                    <p className="text-xs text-slate-500 hidden sm:block">{c.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </aside>
        </div>
      </div>
    </RequireAuth>
  );
}
