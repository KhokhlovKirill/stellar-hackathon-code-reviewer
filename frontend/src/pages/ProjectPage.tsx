import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Alert } from "../components/Alert";
import { FormField, PrimaryButton, TextInput } from "../components/FormField";
import { ProviderLogo, providerLabel } from "../components/ProviderLogo";
import { ProviderSelect } from "../components/ProviderSelect";
import { PillSelect } from "../components/PillSelect";
import { RequireAuth } from "../context/AuthContext";
import { api, ApiError } from "../lib/api";
import { riskBadge, riskLabel, riskScoreColor } from "../lib/severity";
import type { ProjectDetail, QuickConnectResult } from "../lib/types";

const DEFAULT_PUBLIC_URL = "http://localhost:8099";

const SEVERITY_OPTIONS = [
  { value: "low",      label: "Низкий",      color: "slate"  as const },
  { value: "medium",   label: "Средний",     color: "yellow" as const },
  { value: "high",     label: "Высокий",     color: "orange" as const },
  { value: "critical", label: "Критический", color: "red"    as const },
];

const MERGE_OPTIONS = [
  { value: "off",      label: "Выкл.",       color: "slate"  as const },
  { value: "critical", label: "Критич.",     color: "red"    as const },
  { value: "high",     label: "Высокий",     color: "orange" as const },
];

function statusBadge(status: string) {
  const map: Record<string, string> = {
    active:   "bg-emerald-50 dark:bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30",
    pending:  "bg-yellow-50 dark:bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/30",
    error:    "bg-red-50 dark:bg-red-500/15 text-red-700 dark:text-red-400 border-red-200 dark:border-red-500/30",
    inactive: "bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-600/50",
  };
  const label: Record<string, string> = { active: "Активен", pending: "Ожидание", error: "Ошибка", inactive: "Неактивен" };
  return (
    <span className={`inline-flex items-center text-xs font-medium px-2.5 py-1 rounded-full border ${map[status] ?? map.inactive}`}>
      {label[status] ?? status}
    </span>
  );
}

function scanStatusLabel(s: string) {
  return { done: "Готово", pending: "Ожидание", running: "Анализ", failed: "Ошибка" }[s] ?? s;
}

export function ProjectPage() {
  return <RequireAuth><ProjectContent /></RequireAuth>;
}

function ProjectContent() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const id = Number(projectId);
  const [data, setData] = useState<ProjectDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"quick" | "manual">("quick");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!Number.isFinite(id)) return;
    try { setData(await api.getProject(id)); }
    catch (err) { setError(err instanceof ApiError ? err.message : "Ошибка загрузки проекта"); }
    finally { setLoading(false); }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  function goQuickConnectDone(result: QuickConnectResult) {
    navigate(`/projects/${id}/connected`, { state: { result } });
  }

  async function onQuickConnect(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const fd = new FormData(e.currentTarget);
    try {
      const result = await api.quickConnect(id, {
        repo_url:      String(fd.get("repo_url") ?? ""),
        access_token:  String(fd.get("access_token") ?? ""),
        public_url:    String(fd.get("public_url") ?? DEFAULT_PUBLIC_URL),
        severity_gate: String(fd.get("severity_gate") ?? "medium"),
        merge_block:   String(fd.get("merge_block") ?? "critical"),
      });
      goQuickConnectDone(result);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Ошибка подключения");
    }
  }

  async function onManualConnect(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const form = e.currentTarget;
    const fd = new FormData(form);
    try {
      await api.addRepo(id, {
        provider:       String(fd.get("provider") ?? "github"),
        external_id:    String(fd.get("external_id") ?? ""),
        slug:           String(fd.get("slug") ?? ""),
        access_token:   String(fd.get("access_token") ?? ""),
        webhook_secret: String(fd.get("webhook_secret") ?? ""),
        severity_gate:  String(fd.get("severity_gate") ?? "medium"),
        merge_block:    String(fd.get("merge_block") ?? "critical"),
      });
      form.reset();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Ошибка подключения");
    }
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-7xl px-4 sm:px-6 py-10">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-slate-200 dark:bg-slate-800 rounded-xl w-1/3" />
          <div className="h-4 bg-slate-200 dark:bg-slate-800 rounded-xl w-1/4" />
        </div>
      </div>
    );
  }

  if (!data) {
    return <div className="mx-auto max-w-7xl px-4 sm:px-6 py-10"><Alert>Проект не найден</Alert></div>;
  }

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-10">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-400 dark:text-slate-600 mb-6">
        <Link to="/dashboard" className="hover:text-slate-700 dark:hover:text-slate-300 transition-colors">Проекты</Link>
        <span>/</span>
        <span className="text-slate-700 dark:text-slate-300">{data.project.name}</span>
      </div>

      {/* Header */}
      <div className="flex items-start gap-4 mb-8">
        <div className="flex items-center justify-center w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-600 to-violet-600 shadow-lg shadow-indigo-500/30">
          <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
          </svg>
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">{data.project.name}</h1>
          {data.project.description && <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">{data.project.description}</p>}
        </div>
      </div>

      {error && <div className="mb-6"><Alert>{error}</Alert></div>}

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Main content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Repos */}
          <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <h2 className="font-semibold text-slate-900 dark:text-white">Репозитории</h2>
              <span className="text-xs text-slate-500 bg-slate-100 dark:bg-slate-800 px-2.5 py-1 rounded-full">{data.repos.length}</span>
            </div>
            {data.repos.length > 0 ? (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {data.repos.map((r) => (
                  <div key={r.id} className="px-6 py-4 flex items-center gap-4">
                    <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 shrink-0">
                      <ProviderLogo provider={r.provider} size={16} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-slate-900 dark:text-white truncate">{r.slug}</p>
                      <p className="text-xs text-slate-500">{providerLabel(r.provider)}</p>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-slate-500">
                      <span className="hidden sm:block font-mono bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded-md text-slate-600 dark:text-slate-400">
                        {r.policy.severity_gate}
                      </span>
                      {statusBadge(r.status)}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="px-6 py-10 text-center">
                <p className="text-slate-400 dark:text-slate-600 text-sm">Репозиториев пока нет</p>
                <p className="text-slate-300 dark:text-slate-700 text-xs mt-1">Подключите репозиторий справа →</p>
              </div>
            )}
          </section>

          {/* Scans */}
          <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <h2 className="font-semibold text-slate-900 dark:text-white">Последние сканирования</h2>
              <span className="text-xs text-slate-500 bg-slate-100 dark:bg-slate-800 px-2.5 py-1 rounded-full">{data.scans.length}</span>
            </div>
            {data.scans.length > 0 ? (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {data.scans.map((s) => (
                  <Link key={s.id} to={`/scans/${s.id}`}
                    className="px-6 py-4 flex items-center gap-4 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors group">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono text-slate-900 dark:text-white truncate">{s.repo_slug}</p>
                      <p className="text-xs text-slate-500 mt-0.5">PR #{s.pr_id} · {new Date(s.started_at).toLocaleString("ru-RU")}</p>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <span className={`text-sm font-bold ${riskScoreColor(s.risk_score)}`}>{s.risk_score}</span>
                      <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${riskBadge(s.risk_label)}`}>{riskLabel(s.risk_label)}</span>
                      <span className="text-xs text-slate-400 dark:text-slate-500">{scanStatusLabel(s.status)}</span>
                      <svg className="w-4 h-4 text-slate-300 dark:text-slate-700 group-hover:text-indigo-400 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                      </svg>
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="px-6 py-10 text-center">
                <p className="text-slate-400 dark:text-slate-600 text-sm">Сканирований пока нет</p>
                <p className="text-slate-300 dark:text-slate-700 text-xs mt-1">Они появятся после webhook-события на подключённом репозитории</p>
              </div>
            )}
          </section>
        </div>

        {/* Connect sidebar */}
        <aside>
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden sticky top-20">
            {/* Tabs */}
            <div className="flex border-b border-slate-100 dark:border-slate-800">
              {(["quick", "manual"] as const).map((t) => (
                <button key={t} type="button" onClick={() => setTab(t)}
                  className={`flex-1 py-3 text-sm font-medium transition-all ${
                    tab === t
                      ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-300 border-b-2 border-indigo-500"
                      : "text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800/50"
                  }`}>
                  {t === "quick" ? "⚡ Быстро" : "Вручную"}
                </button>
              ))}
            </div>

            {/* Quick connect */}
            {tab === "quick" ? (
              <form onSubmit={onQuickConnect} className="p-5 space-y-4">
                <p className="text-xs text-slate-500 dark:text-slate-500 leading-relaxed">
                  Вставьте URL репозитория GitHub — Aegis сам получит ID и зарегистрирует webhook.
                </p>
                <FormField label="URL репозитория GitHub">
                  <TextInput name="repo_url" required placeholder="https://github.com/owner/repo" />
                </FormField>
                <FormField label="Токен доступа GitHub" hint="Права: repo + admin:repo_hook">
                  <TextInput name="access_token" type="password" required placeholder="ghp_xxxxxxxxxxxx" />
                </FormField>
                <FormField label="Публичный URL" hint={`Webhook: ${DEFAULT_PUBLIC_URL}/webhooks/github`}>
                  <TextInput name="public_url" required defaultValue={DEFAULT_PUBLIC_URL} />
                </FormField>
                <FormField label="Порог серьёзности">
                  <PillSelect name="severity_gate" options={SEVERITY_OPTIONS} defaultValue="medium" />
                </FormField>
                <FormField label="Блок слияния">
                  <PillSelect name="merge_block" options={MERGE_OPTIONS} defaultValue="critical" />
                </FormField>
                <PrimaryButton>⚡ Подключить автоматически</PrimaryButton>
              </form>
            ) : (
              <form onSubmit={onManualConnect} className="p-5 space-y-4">
                <FormField label="Провайдер">
                  <ProviderSelect defaultValue="github" />
                </FormField>
                <FormField label="External ID" hint="Числовой ID или UUID репозитория">
                  <TextInput name="external_id" required placeholder="123456789" />
                </FormField>
                <FormField label="Slug">
                  <TextInput name="slug" required placeholder="org/repo" />
                </FormField>
                <FormField label="Токен доступа">
                  <TextInput name="access_token" type="password" required />
                </FormField>
                <FormField label="Webhook secret">
                  <TextInput name="webhook_secret" type="password" required />
                </FormField>
                <FormField label="Порог серьёзности">
                  <PillSelect name="severity_gate" options={SEVERITY_OPTIONS} defaultValue="medium" />
                </FormField>
                <FormField label="Блок слияния">
                  <PillSelect name="merge_block" options={MERGE_OPTIONS} defaultValue="critical" />
                </FormField>
                <PrimaryButton>Подключить</PrimaryButton>
                <p className="text-xs text-slate-400 dark:text-slate-600">
                  Токены шифруются Fernet перед сохранением — открытый текст не попадает в БД.
                </p>
              </form>
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}
