import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../lib/api";
import type { Project } from "../lib/types";
import { Alert } from "../components/Alert";
import { FormField, TextInput, PrimaryButton } from "../components/FormField";

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("ru-RU", { day: "numeric", month: "long", year: "numeric" });
  } catch {
    return iso;
  }
}

function ProjectCard({ p }: { p: Project }) {
  return (
    <Link
      to={`/projects/${p.id}`}
      className="group block bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-indigo-300 dark:hover:border-indigo-500/40 rounded-2xl p-6 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xl hover:shadow-indigo-500/5"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-600 to-violet-600 shadow-lg shadow-indigo-500/25">
          <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
          </svg>
        </div>
        <svg className="w-4 h-4 text-slate-300 dark:text-slate-700 group-hover:text-indigo-400 transition-colors"
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
      </div>
      <h3 className="font-semibold text-slate-900 dark:text-white text-base mb-1 group-hover:text-indigo-600 dark:group-hover:text-indigo-200 transition-colors">
        {p.name}
      </h3>
      {p.description && (
        <p className="text-slate-500 dark:text-slate-400 text-sm mb-4 line-clamp-2">{p.description}</p>
      )}
      <div className="flex items-center gap-3 text-xs text-slate-400 dark:text-slate-600">
        <span>
          <span className="text-slate-600 dark:text-slate-500 font-medium">{p.repo_count}</span>{" "}
          {p.repo_count === 1 ? "репозиторий" : "репозиториев"}
        </span>
        <span className="text-slate-300 dark:text-slate-800">·</span>
        <span>{formatDate(p.created_at)}</span>
      </div>
    </Link>
  );
}

export function DashboardPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [showForm, setShowForm] = useState(false);

  useEffect(() => {
    api.listProjects()
      .then(setProjects)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Ошибка загрузки"))
      .finally(() => setLoading(false));
  }, []);

  async function onCreate(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const fd = new FormData(form);
    const name = String(fd.get("name") ?? "").trim();
    if (!name) { setCreateError("Введите название проекта"); return; }
    setCreateError(null);
    setCreating(true);
    try {
      const project = await api.createProject(name, String(fd.get("description") ?? ""));
      setProjects((prev) => [project, ...prev]);
      form.reset();
      setShowForm(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setCreateError("Проект с таким названием уже существует");
      } else {
        setCreateError(err instanceof ApiError ? err.message : "Ошибка создания");
      }
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-10">
      {/* Page header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white">Мои проекты</h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
            {loading ? "Загрузка..." : `${projects.length} ${projects.length === 1 ? "проект" : "проектов"}`}
          </p>
        </div>
        <button
          type="button"
          onClick={() => { setShowForm((v) => !v); setCreateError(null); }}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all ${
            showForm
              ? "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700"
              : "bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white shadow-lg shadow-indigo-500/20"
          }`}
        >
          {showForm ? <><span>✕</span><span>Отмена</span></> : <><span className="text-lg leading-none">+</span><span>Новый проект</span></>}
        </button>
      </div>

      {error && <div className="mb-6"><Alert>{error}</Alert></div>}

      {/* Create form */}
      {showForm && (
        <div className="mb-8 bg-white dark:bg-slate-900 border border-indigo-200 dark:border-indigo-500/30 rounded-2xl p-6 shadow-xl shadow-indigo-500/5">
          <h2 className="text-base font-semibold text-slate-900 dark:text-white mb-5 flex items-center gap-2">
            <span className="flex items-center justify-center w-6 h-6 rounded-md bg-indigo-100 dark:bg-indigo-500/20 text-indigo-600 dark:text-indigo-400 text-xs font-bold">+</span>
            Новый проект
          </h2>
          {createError && <div className="mb-4"><Alert>{createError}</Alert></div>}
          <form onSubmit={onCreate} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <FormField label="Название">
                <TextInput name="name" required placeholder="my-awesome-app" autoFocus />
              </FormField>
              <FormField label="Описание" hint="Необязательно">
                <TextInput name="description" placeholder="Краткое описание проекта" />
              </FormField>
            </div>
            <PrimaryButton disabled={creating} className="sm:w-auto sm:px-8">
              {creating ? "Создание..." : "Создать проект"}
            </PrimaryButton>
          </form>
        </div>
      )}

      {/* Grid */}
      {loading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 animate-pulse">
              <div className="w-10 h-10 rounded-xl bg-slate-200 dark:bg-slate-800 mb-4" />
              <div className="h-4 bg-slate-200 dark:bg-slate-800 rounded-lg w-3/4 mb-2" />
              <div className="h-3 bg-slate-200 dark:bg-slate-800 rounded-lg w-1/2" />
            </div>
          ))}
        </div>
      ) : projects.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <div className="w-16 h-16 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-center mb-5 shadow-sm">
            <svg className="w-8 h-8 text-slate-300 dark:text-slate-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-2">Проектов пока нет</h2>
          <p className="text-slate-500 dark:text-slate-500 text-sm mb-6 max-w-xs">
            Создайте первый проект и подключите репозиторий для автоматического анализа PR
          </p>
          <button type="button" onClick={() => setShowForm(true)}
            className="px-6 py-2.5 rounded-xl text-sm font-semibold bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white transition-all shadow-lg shadow-indigo-500/20">
            Создать первый проект
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {projects.map((p) => <ProjectCard key={p.id} p={p} />)}
        </div>
      )}
    </div>
  );
}
