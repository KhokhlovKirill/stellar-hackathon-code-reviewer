import { Link, useLocation, useParams } from "react-router-dom";
import { RequireAuth } from "../context/AuthContext";
import type { QuickConnectResult } from "../lib/types";

export function QuickConnectDonePage() {
  return <RequireAuth><QuickConnectDoneContent /></RequireAuth>;
}

function QuickConnectDoneContent() {
  const { projectId } = useParams();
  const location = useLocation();
  const result = location.state?.result as QuickConnectResult | undefined;

  if (!result) {
    return (
      <div className="mx-auto max-w-lg px-4 py-20 text-center">
        <p className="text-slate-500 text-sm mb-4">Данные подключения не найдены.</p>
        <Link to={`/projects/${projectId}`} className="text-indigo-500 hover:text-indigo-400 text-sm transition-colors">
          ← Вернуться к проекту
        </Link>
      </div>
    );
  }

  const autoHook = Boolean(result.github_hook_id);

  return (
    <div className="mx-auto max-w-xl px-4 py-12">
      {/* Header */}
      <div className="text-center mb-8">
        <div className={`inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4 ${
          autoHook ? "bg-emerald-100 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" : "bg-amber-100 dark:bg-amber-500/15 text-amber-600 dark:text-amber-400"
        }`}>
          <span className="text-3xl">{autoHook ? "✅" : "⚡"}</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Репозиторий подключён</h1>
        <p className="text-slate-500 dark:text-slate-400 text-sm font-mono">{result.slug}</p>
      </div>

      {/* Info card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden mb-5">
        <div className="px-6 py-4 border-b border-slate-100 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Данные webhook</h2>
        </div>
        <div className="divide-y divide-slate-100 dark:divide-slate-800">
          <div className="px-6 py-4 flex items-center justify-between gap-4">
            <span className="text-sm text-slate-500 shrink-0">Webhook URL</span>
            <code className="text-xs font-mono bg-slate-100 dark:bg-slate-800 px-3 py-1.5 rounded-lg text-slate-700 dark:text-slate-300 break-all text-right">
              {result.webhook_url}
            </code>
          </div>
          <div className="px-6 py-4 flex items-center justify-between gap-4">
            <span className="text-sm text-slate-500 shrink-0">Статус webhook</span>
            <span className={`text-xs font-medium px-2.5 py-1 rounded-full border ${
              autoHook
                ? "bg-emerald-50 dark:bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30"
                : "bg-amber-50 dark:bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-500/30"
            }`}>
              {autoHook ? "Зарегистрирован автоматически ✓" : "Требуется ручная настройка"}
            </span>
          </div>
          <div className="px-6 py-4 flex items-center justify-between gap-4">
            <span className="text-sm text-slate-500 shrink-0">Repo ID</span>
            <span className="text-sm font-mono text-slate-600 dark:text-slate-400">{result.repo_id}</span>
          </div>
        </div>
      </div>

      {/* Warning */}
      {!autoHook && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-2xl p-5 mb-5 space-y-4">
          <div className="flex items-start gap-3">
            <span className="text-amber-500 text-lg shrink-0">⚠️</span>
            <div>
              <p className="font-semibold text-amber-700 dark:text-amber-300 text-sm mb-1">Webhook не зарегистрирован автоматически</p>
              <p className="text-amber-600 dark:text-amber-300/70 text-xs leading-relaxed">
                Ваш токен не имеет прав <code className="bg-amber-100 dark:bg-amber-500/20 px-1 rounded">admin:repo_hook</code>. Добавьте webhook вручную:
              </p>
            </div>
          </div>
          <ol className="space-y-2 text-xs text-amber-700 dark:text-amber-300/80 ml-7">
            {[
              "Репозиторий → Settings → Webhooks → Add webhook",
              <>Payload URL: <code className="bg-amber-100 dark:bg-amber-500/20 px-1.5 py-0.5 rounded text-amber-800 dark:text-amber-200">{result.webhook_url}</code></>,
              <>Content type: <strong>application/json</strong></>,
              <>Events: <strong>Pull requests</strong></>,
            ].map((text, i) => (
              <li key={i} className="flex gap-2">
                <span className="shrink-0 font-bold text-amber-500">{i + 1}.</span>
                <span className="flex-1">{text}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {autoHook && (
        <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 rounded-2xl p-5 mb-5">
          <p className="font-semibold text-emerald-700 dark:text-emerald-300 text-sm mb-2">Webhook зарегистрирован на GitHub ✓</p>
          <p className="text-emerald-600 dark:text-emerald-300/70 text-xs leading-relaxed">
            Откройте Pull Request в <strong>{result.slug}</strong> — Aegis автоматически проверит его безопасность.
          </p>
        </div>
      )}

      {/* Next steps */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 mb-6">
        <p className="text-sm font-semibold text-slate-900 dark:text-white mb-3">Следующие шаги:</p>
        <ol className="space-y-2">
          {[
            { text: "Убедитесь, что SSH-туннель запущен:", code: "bash start_tunnel.sh" },
            { text: "Откройте Pull Request в репозитории" },
            { text: "Результаты анализа появятся на дашборде проекта" },
          ].map(({ text, code }, i) => (
            <li key={i} className="flex gap-3 text-sm text-slate-600 dark:text-slate-400">
              <span className="shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-indigo-100 dark:bg-indigo-500/20 text-indigo-600 dark:text-indigo-400 text-xs font-bold">{i + 1}</span>
              <span className="flex-1">{text}{code && <code className="ml-2 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs px-2 py-0.5 rounded-md font-mono">{code}</code>}</span>
            </li>
          ))}
        </ol>
      </div>

      <Link
        to={`/projects/${projectId}`}
        className="flex items-center justify-center gap-2 w-full bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white font-semibold py-3 px-6 rounded-xl transition-all duration-200 shadow-lg shadow-indigo-500/20"
      >
        Перейти к проекту →
      </Link>
    </div>
  );
}
