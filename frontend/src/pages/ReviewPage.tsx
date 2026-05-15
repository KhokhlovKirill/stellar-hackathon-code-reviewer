import { useState } from "react";
import { Alert } from "../components/Alert";
import { Chat } from "../components/Chat";
import type { QuickQuestion } from "../components/Chat";
import { ReviewFindings } from "../components/ReviewFindings";
import { useAuth } from "../context/AuthContext";
import { api, ApiError } from "../lib/api";
import type { ReviewResult } from "../lib/types";

function prQuickQuestions(result: ReviewResult): QuickQuestion[] {
  return [
    { icon: "📋", label: "Объясни находки",       question: `Объясни все найденные уязвимости в PR #${result.pr_number} "${result.pr_title}"` },
    { icon: "🚨", label: "Критические угрозы",     question: "Какие из найденных уязвимостей наиболее опасны и почему?" },
    { icon: "🔧", label: "Как исправить?",         question: "Дай пошаговый план исправления всех найденных проблем" },
    { icon: "📈", label: "Снизить Risk Score",     question: "Как снизить Risk Score этого PR до приемлемого уровня?" },
    { icon: "🛡️", label: "Приоритизация",         question: "В каком порядке стоит исправлять найденные уязвимости?" },
    { icon: "📝", label: "Краткий отчёт",          question: "Составь краткое резюме результатов анализа для команды" },
  ];
}

function prContext(result: ReviewResult): string {
  const counts = result.findings.reduce<Record<string, number>>((a, f) => {
    a[f.severity] = (a[f.severity] ?? 0) + 1;
    return a;
  }, {});
  return [
    `Репозиторий: ${result.repo}`,
    `PR: #${result.pr_number} — ${result.pr_title}`,
    `Автор: ${result.pr_author}`,
    `Файлов проверено: ${result.files_scanned}`,
    `Всего находок: ${result.findings.length}`,
    ...Object.entries(counts).map(([sev, n]) => `  ${sev}: ${n}`),
    result.findings.length > 0
      ? "\nНаходки:\n" +
        result.findings
          .map((f) => `- [${f.severity}] ${f.title} (${f.file}${f.line ? `:${f.line}` : ""})`)
          .join("\n")
      : "Уязвимостей не найдено.",
  ].join("\n");
}

const EXAMPLES = [
  "https://github.com/Nikita56792/Don",
  "https://github.com/owner/repo/pull/42",
];

export function ReviewPage() {
  const { user } = useAuth();
  const [url, setUrl]       = useState("");
  const [token, setToken]   = useState("");
  const [error, setError]   = useState<string | null>(null);
  const [result, setResult] = useState<ReviewResult | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setPending(true);
    try {
      setResult(await api.review(url.trim(), token.trim() || undefined));
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Ошибка анализа");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl px-4 sm:px-6 py-10 space-y-8">
      {/* Hero */}
      <div className="text-center">
        <div className="inline-flex items-center gap-2 bg-indigo-50 dark:bg-indigo-500/10 border border-indigo-200 dark:border-indigo-500/20 rounded-full px-4 py-1.5 text-xs font-medium text-indigo-600 dark:text-indigo-300 mb-5">
          <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse" />
          AI Security Review
        </div>
        <h1 className="text-4xl font-black text-slate-900 dark:text-white mb-3 tracking-tight">
          Быстрый анализ<br />
          <span className="bg-gradient-to-r from-indigo-500 to-violet-500 dark:from-indigo-400 dark:to-violet-400 bg-clip-text text-transparent">
            безопасности PR
          </span>
        </h1>
        <p className="text-slate-500 dark:text-slate-400 text-base max-w-lg mx-auto leading-relaxed">
          Вставьте ссылку на публичный репозиторий GitHub или конкретный PR.
          Aegis проверит изменения с помощью SAST + LLM ансамбля.
        </p>
      </div>

      {/* Search card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm dark:shadow-xl dark:shadow-black/20">
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
              </div>
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                placeholder="https://github.com/owner/repo  или  .../pull/42"
                className="w-full bg-slate-100 dark:bg-slate-800/80 border border-slate-300 dark:border-slate-700/80 rounded-xl pl-11 pr-4 py-3 text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/70 focus:border-indigo-500/50 transition-all text-sm"
              />
            </div>
            <button
              type="submit"
              disabled={pending}
              className="shrink-0 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white font-semibold px-5 py-3 rounded-xl transition-all duration-200 shadow-lg shadow-indigo-500/20 hover:shadow-indigo-500/30 hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none whitespace-nowrap"
            >
              {pending ? (
                <span className="flex items-center gap-2">
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
                  </svg>
                  Анализ...
                </span>
              ) : "Проверить →"}
            </button>
          </div>

          <details className="group">
            <summary className="text-xs text-slate-400 dark:text-slate-500 cursor-pointer hover:text-slate-700 dark:hover:text-slate-300 transition-colors select-none list-none flex items-center gap-1">
              <svg className="w-3 h-3 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
              </svg>
              Приватный репозиторий? Добавить токен (необязательно)
            </summary>
            <div className="mt-3 space-y-2">
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="ghp_xxxx  (права: repo + pull_requests read)"
                className="w-full bg-slate-100 dark:bg-slate-800/80 border border-slate-300 dark:border-slate-700/80 rounded-xl px-4 py-2.5 text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/70 transition-all text-sm"
              />
              <p className="text-xs text-slate-400 dark:text-slate-600">Токен используется только для этого запроса и не сохраняется.</p>
            </div>
          </details>
        </form>
      </div>

      {error && <Alert>{error}</Alert>}

      {pending && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 text-center space-y-3">
          <div className="flex justify-center gap-1.5">
            {[0, 1, 2].map((i) => (
              <div key={i} className="w-2 h-2 rounded-full bg-indigo-500 animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />
            ))}
          </div>
          <p className="text-slate-500 dark:text-slate-400 text-sm">Загрузка diff и запуск анализаторов...</p>
          <p className="text-slate-400 dark:text-slate-600 text-xs">Обычно занимает 10–30 секунд</p>
        </div>
      )}

      {result && (
        <>
          <ReviewFindings result={result} />
          {/* PR Chat — only for authenticated users */}
          {user && (
            <div className="mt-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
                <span className="text-xs text-slate-500 dark:text-slate-500 font-medium px-2">
                  Спросить AI об этом PR
                </span>
                <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
              </div>
              <Chat
                context={prContext(result)}
                quickQuestions={prQuickQuestions(result)}
                title={`AI · PR #${result.pr_number}`}
                subtitle={`Я готов ответить на вопросы по результатам анализа PR #${result.pr_number} «${result.pr_title}».`}
                className="h-[460px]"
              />
            </div>
          )}
        </>
      )}

      {!result && !error && !pending && (
        <div className="bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800/60 border-dashed rounded-2xl p-8">
          <p className="text-sm font-semibold text-slate-500 dark:text-slate-400 mb-4">Примеры для попробовать:</p>
          <div className="space-y-2">
            {EXAMPLES.map((ex) => (
              <button key={ex} type="button" onClick={() => setUrl(ex)}
                className="flex items-center gap-3 w-full text-left group hover:bg-slate-100 dark:hover:bg-slate-800/50 rounded-xl px-4 py-2.5 transition-all">
                <span className="text-indigo-500 group-hover:text-indigo-400 text-xs">→</span>
                <code className="text-slate-500 dark:text-slate-400 text-xs group-hover:text-slate-700 dark:group-hover:text-slate-200 transition-colors font-mono">{ex}</code>
              </button>
            ))}
          </div>
          <p className="text-xs text-slate-400 dark:text-slate-700 mt-5 pt-4 border-t border-slate-200 dark:border-slate-800">
            Для публичных репозиториев токен не нужен. Лимит GitHub API: 60 запросов/час с IP.
          </p>
        </div>
      )}
    </div>
  );
}
