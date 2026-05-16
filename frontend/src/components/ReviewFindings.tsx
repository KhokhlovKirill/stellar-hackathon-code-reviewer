import { useMemo, useState } from "react";
import {
  severityBadge,
  severityBorder,
  severityLabel,
} from "../lib/severity";
import type { ReviewFinding, ReviewResult } from "../lib/types";

// ── Helpers ───────────────────────────────────────────────────────────────────

function estimateEffort(
  sev: string,
  fix?: string | null,
): { label: string; hours: string; cls: string } {
  switch (sev.toLowerCase()) {
    case "critical":
      return {
        label: "Сложно",
        hours: "4–16 ч",
        cls: "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/20",
      };
    case "high":
      return {
        label: "Умеренно",
        hours: "2–8 ч",
        cls: "text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-500/10 border-orange-200 dark:border-orange-500/20",
      };
    case "medium":
      return {
        label: fix ? "Просто" : "Умеренно",
        hours: fix ? "~1 ч" : "~2 ч",
        cls: fix
          ? "text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-500/10 border-yellow-200 dark:border-yellow-500/20"
          : "text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-500/10 border-orange-200 dark:border-orange-500/20",
      };
    default:
      return {
        label: "Минимально",
        hours: "< 1 ч",
        cls: "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/20",
      };
  }
}

function fileLanguage(file: string): string {
  const ext = file.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    py: "Python",
    ts: "TypeScript",
    tsx: "TypeScript",
    js: "JavaScript",
    jsx: "JavaScript",
    java: "Java",
    go: "Go",
    rb: "Ruby",
    php: "PHP",
    cs: "C#",
    cpp: "C++",
    c: "C",
    rs: "Rust",
    kt: "Kotlin",
    swift: "Swift",
    sh: "Shell",
    bash: "Shell",
    sql: "SQL",
    yaml: "YAML",
    yml: "YAML",
    json: "JSON",
    xml: "XML",
  };
  return map[ext] ?? (ext ? ext.toUpperCase() : "Неизв.");
}

function sourceType(s: string): string {
  const m: Record<string, string> = {
    deterministic: "SAST",
    llm_a: "LLM",
    llm_b: "LLM",
    judge: "Judge",
  };
  return m[s] ?? s;
}

// ── Filter types ──────────────────────────────────────────────────────────────

interface Filters {
  severity: Set<string>;
  type: Set<string>;
  language: Set<string>;
  label: Set<string>;
  effort: Set<string>;
}

function emptyFilters(): Filters {
  return {
    severity: new Set(),
    type: new Set(),
    language: new Set(),
    label: new Set(),
    effort: new Set(),
  };
}

function countActive(f: Filters): number {
  return f.severity.size + f.type.size + f.language.size + f.label.size + f.effort.size;
}

// ── Filter sidebar ────────────────────────────────────────────────────────────

function FilterSection({
  title,
  options,
  selected,
  onToggle,
}: {
  title: string;
  options: { id: string; label: string; count: number; dotCls?: string }[];
  selected: Set<string>;
  onToggle: (id: string) => void;
}) {
  if (options.length === 0) return null;
  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
        {title}
      </p>
      <div className="space-y-1.5">
        {options.map((opt) => (
          <label
            key={opt.id}
            className="flex items-center gap-2.5 cursor-pointer group"
          >
            <input
              type="checkbox"
              checked={selected.has(opt.id)}
              onChange={() => onToggle(opt.id)}
              className="w-3.5 h-3.5 rounded border-slate-300 dark:border-slate-600 accent-indigo-500"
            />
            {opt.dotCls && (
              <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dotCls}`} />
            )}
            <span
              className={`text-xs flex-1 transition-colors ${
                selected.has(opt.id)
                  ? "text-slate-900 dark:text-white font-medium"
                  : "text-slate-600 dark:text-slate-400 group-hover:text-slate-900 dark:group-hover:text-white"
              }`}
            >
              {opt.label}
            </span>
            <span className="text-xs text-slate-400 dark:text-slate-600 bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded-full min-w-[1.5rem] text-center">
              {opt.count}
            </span>
          </label>
        ))}
      </div>
    </div>
  );
}

// ── RiskGauge (unchanged) ─────────────────────────────────────────────────────

function RiskGauge({
  score,
  crit,
  high,
}: {
  score: number;
  crit: number;
  high: number;
}) {
  const color =
    crit > 0
      ? "text-red-500"
      : high > 0
        ? "text-orange-500"
        : score > 40
          ? "text-yellow-500"
          : "text-emerald-500";
  const ringColor =
    crit > 0
      ? "stroke-red-500"
      : high > 0
        ? "stroke-orange-500"
        : score > 40
          ? "stroke-yellow-500"
          : "stroke-emerald-500";

  const r = 22;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-16 h-16">
        <svg className="w-16 h-16 -rotate-90" viewBox="0 0 56 56">
          <circle
            cx="28"
            cy="28"
            r={r}
            fill="none"
            strokeWidth="4"
            className="stroke-slate-200 dark:stroke-slate-800"
          />
          <circle
            cx="28"
            cy="28"
            r={r}
            fill="none"
            strokeWidth="4"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            className={`${ringColor} transition-all duration-700`}
          />
        </svg>
        <div
          className={`absolute inset-0 flex items-center justify-center text-base font-black ${color}`}
        >
          {score}
        </div>
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-500 mt-1 font-medium">
        Риск
      </p>
    </div>
  );
}

// ── SeverityBar (unchanged) ───────────────────────────────────────────────────

function SeverityBar({ findings }: { findings: ReviewFinding[] }) {
  const total = findings.length;
  if (total === 0) return null;

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  const bars = [
    {
      key: "critical",
      label: "Критич.",
      cls: "bg-red-500",
      textCls: "text-red-500",
      count: counts.critical ?? 0,
    },
    {
      key: "high",
      label: "Высокий",
      cls: "bg-orange-500",
      textCls: "text-orange-500",
      count: counts.high ?? 0,
    },
    {
      key: "medium",
      label: "Средний",
      cls: "bg-yellow-500",
      textCls: "text-yellow-500",
      count: counts.medium ?? 0,
    },
    {
      key: "low",
      label: "Низкий",
      cls: "bg-slate-400",
      textCls: "text-slate-400",
      count: counts.low ?? 0,
    },
  ].filter((b) => b.count > 0);

  return (
    <div className="space-y-2">
      <div className="flex h-2 rounded-full overflow-hidden gap-0.5">
        {bars.map((b) => (
          <div
            key={b.key}
            className={`${b.cls} transition-all duration-500`}
            style={{ width: `${(b.count / total) * 100}%` }}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-3">
        {bars.map((b) => (
          <span key={b.key} className="flex items-center gap-1.5 text-xs">
            <span className={`w-2 h-2 rounded-full ${b.cls}`} />
            <span className="text-slate-500 dark:text-slate-400">{b.label}</span>
            <span className={`font-bold ${b.textCls}`}>{b.count}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Enhanced FindingCard ──────────────────────────────────────────────────────

function FindingCard({ f }: { f: ReviewFinding }) {
  const [open, setOpen] = useState(false);
  const effort = estimateEffort(f.severity, f.fix);
  const lang = fileLanguage(f.file);
  const src = sourceType(f.source);

  return (
    <div
      className={`bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden border-l-4 ${severityBorder(f.severity)} transition-shadow hover:shadow-md dark:hover:shadow-black/20`}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-5 py-4 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
      >
        {/* Severity */}
        <span
          className={`shrink-0 mt-0.5 text-xs font-bold px-2.5 py-1 rounded-full ${severityBadge(f.severity)}`}
        >
          {severityLabel(f.severity)}
        </span>

        {/* Title + meta badges */}
        <div className="flex-1 min-w-0">
          <p className="font-semibold text-slate-900 dark:text-white text-sm leading-snug">
            {f.title}
          </p>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {/* CWE — категория */}
            {f.cwe && (
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                {f.cwe}
              </span>
            )}
            {/* Тип источника */}
            <span className="text-xs px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-500/20 font-medium">
              {src}
            </span>
            {/* Метка */}
            {f.short_label && (
              <span className="text-xs px-2 py-0.5 rounded bg-violet-50 dark:bg-violet-500/10 text-violet-600 dark:text-violet-400 border border-violet-200 dark:border-violet-500/20">
                {f.short_label}
              </span>
            )}
            {/* Трудоёмкость */}
            <span
              className={`text-xs px-2 py-0.5 rounded border ${effort.cls}`}
            >
              ⏱ {effort.label} · {effort.hours}
            </span>
          </div>
        </div>

        {/* File */}
        <div className="shrink-0 flex flex-col items-end gap-1 ml-2">
          <span className="text-xs font-mono text-slate-400 dark:text-slate-500 text-right max-w-[12rem] truncate">
            {f.file}
            {f.line ? `:${f.line}` : ""}
          </span>
          <span className="text-slate-300 dark:text-slate-600 text-xs">
            {open ? "▲" : "▼"}
          </span>
        </div>
      </button>

      {open && (
        <div className="px-5 pb-5 pt-1 space-y-4 border-t border-slate-100 dark:border-slate-800">
          {f.rationale && (
            <div>
              <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">
                Почему это проблема
              </p>
              <p className="text-slate-600 dark:text-slate-300 text-sm leading-relaxed">
                {f.rationale}
              </p>
            </div>
          )}
          {f.fix && (
            <div>
              <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">
                Рекомендуемое исправление
              </p>
              <pre className="bg-slate-900 dark:bg-slate-950 border border-slate-700 dark:border-slate-800 rounded-xl p-4 text-xs text-slate-200 overflow-x-auto leading-relaxed whitespace-pre-wrap">
                {f.fix}
              </pre>
            </div>
          )}
          <div className="flex items-center flex-wrap gap-4 pt-1 text-xs text-slate-400 dark:text-slate-600 border-t border-slate-100 dark:border-slate-800">
            <span>
              Источник: <span className="text-slate-500">{src}</span>
            </span>
            <span>
              Уверенность:{" "}
              <span className="text-slate-500">
                {Math.round(f.confidence * 100)}%
              </span>
            </span>
            <span>
              Язык: <span className="text-slate-500">{lang}</span>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function ReviewFindings({ result }: { result: ReviewResult }) {
  const [filters, setFilters] = useState<Filters>(emptyFilters());

  const total = result.findings.length;
  const crit = result.findings.filter((f) => f.severity === "critical").length;
  const high = result.findings.filter((f) => f.severity === "high").length;
  const score =
    crit > 0
      ? 85 + Math.min(crit * 5, 14)
      : high > 0
        ? 55 + Math.min(high * 10, 29)
        : total > 0
          ? 25
          : 0;

  // Build sidebar option lists from all findings
  const allSeverities = useMemo(() => {
    const order = ["critical", "high", "medium", "low", "info"];
    const counts = result.findings.reduce<Record<string, number>>((acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    }, {});
    const labels: Record<string, string> = {
      critical: "Критический",
      high: "Высокий",
      medium: "Средний",
      low: "Низкий",
      info: "Инфо",
    };
    const dots: Record<string, string> = {
      critical: "bg-red-500",
      high: "bg-orange-500",
      medium: "bg-yellow-500",
      low: "bg-slate-400",
      info: "bg-blue-400",
    };
    return order
      .filter((s) => counts[s] > 0)
      .map((s) => ({ id: s, label: labels[s] ?? s, count: counts[s], dotCls: dots[s] }));
  }, [result.findings]);

  const allTypes = useMemo(() => {
    const counts: Record<string, number> = {};
    result.findings.forEach((f) => {
      const t = sourceType(f.source);
      counts[t] = (counts[t] ?? 0) + 1;
    });
    return Object.entries(counts).map(([id, count]) => ({ id, label: id, count }));
  }, [result.findings]);

  const allLanguages = useMemo(() => {
    const counts: Record<string, number> = {};
    result.findings.forEach((f) => {
      const l = fileLanguage(f.file);
      counts[l] = (counts[l] ?? 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([id, count]) => ({ id, label: id, count }));
  }, [result.findings]);

  const allLabels = useMemo(() => {
    const counts: Record<string, number> = {};
    result.findings.forEach((f) => {
      if (f.short_label) counts[f.short_label] = (counts[f.short_label] ?? 0) + 1;
    });
    return Object.entries(counts).map(([id, count]) => ({ id, label: id, count }));
  }, [result.findings]);

  const allEfforts = useMemo(() => {
    const order = ["Сложно", "Умеренно", "Просто", "Минимально"];
    const counts: Record<string, number> = {};
    result.findings.forEach((f) => {
      const e = estimateEffort(f.severity, f.fix).label;
      counts[e] = (counts[e] ?? 0) + 1;
    });
    return order
      .filter((e) => counts[e] > 0)
      .map((e) => ({ id: e, label: e, count: counts[e] }));
  }, [result.findings]);

  // Apply filters
  const filteredFindings = useMemo(() => {
    return result.findings.filter((f) => {
      if (filters.severity.size > 0 && !filters.severity.has(f.severity)) return false;
      if (filters.type.size > 0 && !filters.type.has(sourceType(f.source))) return false;
      if (filters.language.size > 0 && !filters.language.has(fileLanguage(f.file))) return false;
      if (filters.label.size > 0 && (!f.short_label || !filters.label.has(f.short_label))) return false;
      if (filters.effort.size > 0 && !filters.effort.has(estimateEffort(f.severity, f.fix).label)) return false;
      return true;
    });
  }, [result.findings, filters]);

  function toggle(key: keyof Filters, id: string) {
    setFilters((prev) => {
      const next = { ...prev, [key]: new Set(prev[key]) };
      if ((next[key] as Set<string>).has(id)) {
        (next[key] as Set<string>).delete(id);
      } else {
        (next[key] as Set<string>).add(id);
      }
      return next;
    });
  }

  const activeCount = countActive(filters);

  return (
    <div className="space-y-4">
      {/* PR summary hero card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm">
        <div className="h-1 bg-gradient-to-r from-indigo-500 via-violet-500 to-purple-500" />
        <div className="p-6">
          <div className="flex items-start gap-4 mb-5">
            <RiskGauge score={score} crit={crit} high={high} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                <span className="text-xs font-mono bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 px-2 py-0.5 rounded-md border border-slate-200 dark:border-slate-700">
                  {result.repo}
                </span>
                <span className="text-xs bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-300 px-2 py-0.5 rounded-md border border-indigo-200 dark:border-indigo-500/30 font-medium">
                  PR #{result.pr_number}
                </span>
              </div>
              <a
                href={result.pr_url}
                target="_blank"
                rel="noreferrer"
                className="block text-lg font-bold text-slate-900 dark:text-white hover:text-indigo-600 dark:hover:text-indigo-300 transition-colors leading-snug mb-2"
              >
                {result.pr_title}
              </a>
              <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-500 flex-wrap">
                <span className="flex items-center gap-1">
                  <svg
                    className="w-3.5 h-3.5"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <path
                      d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8z"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  {result.pr_author}
                </span>
                <span className="flex items-center gap-1">
                  <svg
                    className="w-3.5 h-3.5"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <path
                      d="M9 12h6M9 16h6M17 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V5a2 2 0 00-2-2z"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  {result.files_scanned} файлов
                </span>
                <span className="flex items-center gap-1">
                  <svg
                    className="w-3.5 h-3.5"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <path
                      d="M12 9v4l3 3M12 3a9 9 0 100 18A9 9 0 0012 3z"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  {total}{" "}
                  {total === 1
                    ? "находка"
                    : total < 5
                      ? "находки"
                      : "находок"}
                </span>
              </div>
            </div>
          </div>

          {total > 0 && <SeverityBar findings={result.findings} />}

          {result.summary && (
            <div className="mt-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-4">
              <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">
                Сводка ревью
              </p>
              <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed">
                {result.summary}
              </p>
              {result.findings.some((f) => f.short_label) && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {result.findings
                    .map((f) => f.short_label)
                    .filter(Boolean)
                    .filter((v, i, arr) => arr.indexOf(v) === i)
                    .map((label) => (
                      <span
                        key={label}
                        className="text-xs rounded-md border border-violet-200 dark:border-violet-500/30 bg-violet-50 dark:bg-violet-500/10 px-2 py-0.5 text-violet-600 dark:text-violet-400"
                      >
                        {label}
                      </span>
                    ))}
                </div>
              )}
            </div>
          )}

          {total === 0 && (
            <div className="flex items-center gap-3 bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/20 rounded-xl px-4 py-3">
              <span className="text-emerald-500 text-xl">✅</span>
              <span className="text-sm font-semibold text-emerald-700 dark:text-emerald-300">
                Уязвимостей не обнаружено
              </span>
            </div>
          )}
        </div>

        {result.degraded && (
          <div className="border-t border-slate-100 dark:border-slate-800 px-6 py-3 flex items-center gap-2 bg-amber-50 dark:bg-amber-500/5 text-xs text-amber-600 dark:text-amber-300">
            <span>⚠</span>
            <span>
              LLM-анализ пропущен — OpenRouter недоступен. Показаны только
              детерминированные результаты.
            </span>
          </div>
        )}
      </div>

      {/* Findings + Sidebar */}
      {total > 0 && (
        <div className="flex flex-col lg:flex-row gap-5 lg:items-start">
          {/* Left: findings list */}
          <div className="flex-1 min-w-0 space-y-3 w-full">
            <div className="flex items-center gap-2 px-1">
              <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                Найденные проблемы
              </h3>
              <span className="text-xs text-slate-400 dark:text-slate-600 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-full">
                {filteredFindings.length}
              </span>
              {activeCount > 0 && (
                <span className="text-xs text-slate-400 dark:text-slate-600">
                  из {total}
                </span>
              )}
            </div>

            {filteredFindings.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 p-8 text-center">
                <p className="text-slate-500 dark:text-slate-400 text-sm">
                  Нет проблем, соответствующих фильтрам
                </p>
                <button
                  type="button"
                  onClick={() => setFilters(emptyFilters())}
                  className="mt-3 text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
                >
                  Сбросить фильтры
                </button>
              </div>
            ) : (
              filteredFindings.map((f, i) => (
                <FindingCard key={`${f.file}-${f.line}-${i}`} f={f} />
              ))
            )}
          </div>

          {/* Right: filter sidebar */}
          <div className="w-full lg:w-52 xl:w-60 lg:shrink-0 lg:sticky lg:top-4">
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-4 space-y-5">
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold text-slate-900 dark:text-white">
                  Фильтры
                </p>
                {activeCount > 0 && (
                  <button
                    type="button"
                    onClick={() => setFilters(emptyFilters())}
                    className="text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
                  >
                    Сбросить
                  </button>
                )}
              </div>
              {activeCount > 0 && (
                <div className="text-xs text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-500/10 border border-indigo-200 dark:border-indigo-500/20 rounded-lg px-2.5 py-1.5">
                  Активно фильтров: {activeCount}
                </div>
              )}
              <FilterSection
                title="Серьёзность"
                options={allSeverities}
                selected={filters.severity}
                onToggle={(id) => toggle("severity", id)}
              />
              <FilterSection
                title="Тип"
                options={allTypes}
                selected={filters.type}
                onToggle={(id) => toggle("type", id)}
              />
              {allLanguages.length > 1 && (
                <FilterSection
                  title="Язык"
                  options={allLanguages}
                  selected={filters.language}
                  onToggle={(id) => toggle("language", id)}
                />
              )}
              {allLabels.length > 0 && (
                <FilterSection
                  title="Метка"
                  options={allLabels}
                  selected={filters.label}
                  onToggle={(id) => toggle("label", id)}
                />
              )}
              {allEfforts.length > 1 && (
                <FilterSection
                  title="Трудоёмкость"
                  options={allEfforts}
                  selected={filters.effort}
                  onToggle={(id) => toggle("effort", id)}
                />
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
