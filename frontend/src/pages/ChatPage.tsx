import { Chat } from "../components/Chat";
import { RequireAuth } from "../context/AuthContext";
import type { QuickQuestion } from "../components/Chat";

const QUICK_QUESTIONS: QuickQuestion[] = [
  { icon: "🔐", label: "Что такое SAST?",       question: "Что такое SAST-анализ и чем он отличается от DAST?" },
  { icon: "🛡️", label: "LLM в безопасности",   question: "Как Aegis использует LLM-модели для анализа кода?" },
  { icon: "⚡", label: "Настроить webhook",      question: "Как шаг за шагом настроить webhook для GitHub репозитория?" },
  { icon: "📋", label: "OWASP Top 10",           question: "Объясни OWASP Top 10 — самые распространённые уязвимости" },
  { icon: "📊", label: "Risk Score",             question: "Как интерпретировать Risk Score от 0 до 100?" },
  { icon: "💉", label: "SQL инъекция",           question: "Что такое SQL-инъекция и как защитить код от неё?" },
  { icon: "🔧", label: "Исправить XSS",          question: "Как обнаружить и исправить XSS-уязвимость в JavaScript?" },
  { icon: "🔑", label: "Хранение секретов",     question: "Какие лучшие практики для безопасного хранения токенов и паролей?" },
  { icon: "🚪", label: "Broken Access Control", question: "Что такое Broken Access Control и как его предотвратить?" },
  { icon: "🏗️", label: "Secure SDLC",           question: "Как выстроить безопасный SDLC (Secure Software Development Lifecycle)?" },
];

const CATEGORIES = [
  { icon: "🛡️", label: "Уязвимости", desc: "Типы атак, CWE, CVE" },
  { icon: "🔧", label: "Исправления", desc: "Как писать безопасный код" },
  { icon: "⚙️", label: "Интеграция",  desc: "Webhooks, API, CI/CD" },
  { icon: "📊", label: "Аналитика",   desc: "Risk Score, отчёты, приоритеты" },
];

export function ChatPage() {
  return (
    <RequireAuth>
      <div className="mx-auto max-w-5xl px-4 sm:px-6 py-10">
        {/* Page header */}
        <div className="mb-8">
          <div className="inline-flex items-center gap-2 bg-indigo-50 dark:bg-indigo-500/10 border border-indigo-200 dark:border-indigo-500/20 rounded-full px-4 py-1.5 text-xs font-medium text-indigo-600 dark:text-indigo-300 mb-5">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse" />
            Aegis AI · Бета
          </div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">
            AI-ассистент по безопасности
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-base">
            Задайте вопрос об уязвимостях, настройке интеграций или получите помощь по результатам сканирования.
          </p>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Sidebar: categories */}
          <aside className="space-y-4">
            <p className="text-xs font-semibold text-slate-500 dark:text-slate-500 uppercase tracking-wider">Темы</p>
            <div className="space-y-2">
              {CATEGORIES.map((c) => (
                <div
                  key={c.label}
                  className="flex items-center gap-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-3 hover:border-indigo-200 dark:hover:border-indigo-500/40 transition-all cursor-default"
                >
                  <span className="text-xl">{c.icon}</span>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-900 dark:text-white">{c.label}</p>
                    <p className="text-xs text-slate-500">{c.desc}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Tips card */}
            <div className="bg-gradient-to-br from-indigo-50 to-violet-50 dark:from-indigo-500/10 dark:to-violet-500/5 border border-indigo-100 dark:border-indigo-500/20 rounded-xl p-4">
              <p className="text-xs font-semibold text-indigo-700 dark:text-indigo-300 mb-3 flex items-center gap-1.5">
                <span>💡</span> Советы
              </p>
              <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-400">
                <li className="flex gap-2"><span className="text-indigo-400 shrink-0">→</span>Уточните язык программирования для более точного ответа</li>
                <li className="flex gap-2"><span className="text-indigo-400 shrink-0">→</span>Вставьте код для анализа конкретного фрагмента</li>
                <li className="flex gap-2"><span className="text-indigo-400 shrink-0">→</span>Спросите о CWE-коде из результатов сканирования</li>
              </ul>
            </div>
          </aside>

          {/* Main chat */}
          <div className="lg:col-span-2">
            <Chat
              quickQuestions={QUICK_QUESTIONS}
              title="Aegis AI"
              subtitle="Привет! Я Aegis AI — ваш эксперт по безопасности кода. Выберите тему из популярных вопросов или напишите свой вопрос прямо сейчас."
              className="h-[580px]"
            />
          </div>
        </div>
      </div>
    </RequireAuth>
  );
}
