import { useRef, useState } from "react";
import { Alert } from "../components/Alert";
import { Chat, type ChatHandle, type QuickQuestion } from "../components/Chat";
import { ReviewFindings } from "../components/ReviewFindings";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";
import { api, ApiError } from "../lib/api";
import type { ChatScan } from "../lib/chatStream";
import type { ReviewResult } from "../lib/types";

function prQuickQuestions(
  result: ReviewResult,
  lang: "ru" | "en",
): QuickQuestion[] {
  return lang === "ru"
    ? [
        { icon: "📋", label: "Объясни находки", question: `Объясни все найденные уязвимости в PR #${result.pr_number} "${result.pr_title}"` },
        { icon: "🚨", label: "Критические угрозы", question: "Какие из найденных уязвимостей наиболее опасны и почему?" },
        { icon: "🔧", label: "Как исправить?", question: "Дай пошаговый план исправления всех найденных проблем с unified diff патчами" },
        { icon: "🛡️", label: "Приоритизация", question: "В каком порядке стоит исправлять найденные уязвимости?" },
        { icon: "📝", label: "Краткий отчёт", question: "Составь краткое резюме результатов анализа для команды" },
      ]
    : [
        { icon: "📋", label: "Explain findings", question: `Explain every vulnerability found in PR #${result.pr_number} "${result.pr_title}"` },
        { icon: "🚨", label: "Critical threats", question: "Which of the findings are the most dangerous and why?" },
        { icon: "🔧", label: "How to fix?", question: "Give a step-by-step remediation plan with unified diff patches" },
        { icon: "🛡️", label: "Prioritization", question: "In what order should the findings be fixed?" },
        { icon: "📝", label: "Team summary", question: "Write a short summary of the analysis results for the team" },
      ];
}

function toChatScan(r: ReviewResult): ChatScan {
  return {
    scan_id: r.scan_id ?? "",
    repo: r.repo,
    pr_number: r.pr_number,
    pr_title: r.pr_title,
    pr_url: r.pr_url,
    pr_author: r.pr_author,
    files_scanned: r.files_scanned,
    degraded: r.degraded,
    summary: r.summary ?? null,
    findings: r.findings.map((f) => ({
      file: f.file,
      line: f.line ?? 0,
      cwe: f.cwe ?? null,
      severity: f.severity,
      title: f.title,
      rationale: f.rationale ?? "",
      fix: f.fix ?? null,
    })),
  };
}

const EXAMPLES = [
  "https://github.com/Nikita56792/Don",
  "https://github.com/owner/repo/pull/42",
];

export function ReviewPage() {
  const { user } = useAuth();
  const { lang, t } = useSettings();
  const chatRef = useRef<ChatHandle>(null);
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
      setResult(await api.review(url.trim(), token.trim() || undefined, lang));
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
                  {t("action.askScan")}
                </span>
                <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
              </div>
              <div className="flex flex-wrap gap-2 mb-3">
                <button
                  type="button"
                  onClick={() =>
                    chatRef.current?.ask(t("action.explainScan"), {
                      finding: null,
                    })
                  }
                  className="text-xs font-medium px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-indigo-300 hover:text-indigo-600 dark:hover:text-indigo-300 transition-all"
                >
                  📖 {t("action.explain")}
                </button>
                <button
                  type="button"
                  onClick={() =>
                    chatRef.current?.ask(t("action.fixScan"), { finding: null })
                  }
                  className="text-xs font-bold px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-all"
                >
                  🔧 {t("action.fix")} PR
                </button>
              </div>
              <Chat
                ref={chatRef}
                scan={toChatScan(result)}
                repo={result.repo}
                quickQuestions={prQuickQuestions(result, lang)}
                title={`Aegis · PR #${result.pr_number}`}
                subtitle={
                  lang === "ru"
                    ? `Готов ответить по результатам анализа PR #${result.pr_number} «${result.pr_title}».`
                    : `Ready to answer questions about the analysis of PR #${result.pr_number} "${result.pr_title}".`
                }
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
