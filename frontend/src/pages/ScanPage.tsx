import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Alert } from "../components/Alert";
import { Chat, type ChatHandle } from "../components/Chat";
import { RequireAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";
import { api, ApiError } from "../lib/api";
import type { ChatFinding, ChatScan } from "../lib/chatStream";
import {
  riskBadge,
  riskLabel,
  riskScoreColor,
  severityBadge,
  severityBorder,
  severityLabel,
} from "../lib/severity";
import type { ScanDetail, ScanFinding } from "../lib/types";

// ── Shared helpers (mirrors ReviewFindings) ───────────────────────────────────

function estimateEffort(
  sev: string,
  fix?: string | null,
): { label: string; hours: string; cls: string } {
  switch (sev.toLowerCase()) {
    case "critical":
      return { label: "Сложно", hours: "4–16 ч", cls: "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/20" };
    case "high":
      return { label: "Умеренно", hours: "2–8 ч", cls: "text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-500/10 border-orange-200 dark:border-orange-500/20" };
    case "medium":
      return fix
        ? { label: "Просто", hours: "~1 ч", cls: "text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-500/10 border-yellow-200 dark:border-yellow-500/20" }
        : { label: "Умеренно", hours: "~2 ч", cls: "text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-500/10 border-orange-200 dark:border-orange-500/20" };
    default:
      return { label: "Минимально", hours: "< 1 ч", cls: "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/20" };
  }
}

function fileLanguage(file: string): string {
  const ext = file.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    py: "Python", ts: "TypeScript", tsx: "TypeScript", js: "JavaScript",
    jsx: "JavaScript", java: "Java", go: "Go", rb: "Ruby", php: "PHP",
    cs: "C#", cpp: "C++", c: "C", rs: "Rust", kt: "Kotlin", swift: "Swift",
    sh: "Shell", bash: "Shell", sql: "SQL", yaml: "YAML", yml: "YAML",
    json: "JSON", xml: "XML",
  };
  return map[ext] ?? (ext ? ext.toUpperCase() : "Неизв.");
}

function sourceType(s: string): string {
  const m: Record<string, string> = { deterministic: "SAST", llm_a: "LLM", llm_b: "LLM", judge: "Judge" };
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
  return { severity: new Set(), type: new Set(), language: new Set(), label: new Set(), effort: new Set() };
}

function countActive(f: Filters) {
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
      <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{title}</p>
      <div className="space-y-1.5">
        {options.map((opt) => (
          <label key={opt.id} className="flex items-center gap-2.5 cursor-pointer group">
            <input
              type="checkbox"
              checked={selected.has(opt.id)}
              onChange={() => onToggle(opt.id)}
              className="w-3.5 h-3.5 rounded border-slate-300 dark:border-slate-600 accent-indigo-500"
            />
            {opt.dotCls && <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dotCls}`} />}
            <span className={`text-xs flex-1 transition-colors ${selected.has(opt.id) ? "text-slate-900 dark:text-white font-medium" : "text-slate-600 dark:text-slate-400 group-hover:text-slate-900 dark:group-hover:text-white"}`}>
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

function toChatFinding(f: ScanFinding): ChatFinding {
  return {
    file: f.file,
    line: f.line,
    cwe: f.cwe,
    severity: f.severity,
    title: f.title,
    rationale: f.rationale,
    fix: f.fix,
  };
}

function toChatScan(s: ScanDetail, findings: ScanFinding[]): ChatScan {
  return {
    scan_id: s.id,
    repo: s.repo_slug,
    pr_number: typeof s.pr_id === "number" ? s.pr_id : Number(s.pr_id) || 0,
    pr_title: "",
    files_scanned: s.files_scanned?.length ?? 0,
    degraded: (s.degraded?.length ?? 0) > 0,
    summary: s.summary ?? s.decision?.summary ?? null,
    findings: findings.map(toChatFinding),
  };
}

export function ScanPage() {
  return (
    <RequireAuth>
      <ScanContent />
    </RequireAuth>
  );
}

function FindingCard({
  f,
  onAction,
}: {
  f: ScanFinding;
  onAction: (kind: "ask" | "explain" | "fix", f: ScanFinding) => void;
}) {
  const { lang, t } = useSettings();
  const [open, setOpen] = useState(false);
  const effort = estimateEffort(f.severity, f.fix);
  const src = f.source ? sourceType(f.source) : null;
  const fileLang = fileLanguage(f.file);

  return (
    <div
      className={`bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden border-l-4 ${severityBorder(f.severity)} hover:shadow-md dark:hover:shadow-black/20 transition-shadow`}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-5 py-4 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
      >
        {/* Severity */}
        <span className={`shrink-0 mt-0.5 text-xs font-bold px-2.5 py-1 rounded-full ${severityBadge(f.severity)}`}>
          {severityLabel(f.severity, lang)}
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
            {src && (
              <span className="text-xs px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-500/20 font-medium">
                {src}
              </span>
            )}
            {/* Метка */}
            {f.short_label && (
              <span className="text-xs px-2 py-0.5 rounded bg-violet-50 dark:bg-violet-500/10 text-violet-600 dark:text-violet-400 border border-violet-200 dark:border-violet-500/20">
                {f.short_label}
              </span>
            )}
            {/* Трудоёмкость */}
            <span className={`text-xs px-2 py-0.5 rounded border ${effort.cls}`}>
              ⏱ {effort.label} · {effort.hours}
            </span>
          </div>
        </div>

        <div className="shrink-0 flex flex-col items-end gap-1 ml-2">
          <span className="text-xs font-mono text-slate-400 dark:text-slate-500 text-right max-w-[12rem] truncate">
            {f.file}:{f.line}
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
                {lang === "ru" ? "Почему это проблема" : "Why this is a problem"}
              </p>
              <p className="text-slate-600 dark:text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">
                {f.rationale}
              </p>
            </div>
          )}
          {f.fix && (
            <div>
              <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">
                {lang === "ru" ? "Рекомендуемое исправление" : "Suggested fix"}
              </p>
              <pre className="bg-slate-900 dark:bg-slate-950 border border-slate-700 dark:border-slate-800 rounded-xl p-4 text-xs text-slate-200 overflow-x-auto leading-relaxed whitespace-pre-wrap">
                {f.fix}
              </pre>
            </div>
          )}
          <div className="flex flex-wrap gap-2 pt-1">
            <button
              type="button"
              onClick={() => onAction("ask", f)}
              className="text-xs font-medium px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-indigo-300 hover:text-indigo-600 dark:hover:text-indigo-300 transition-all"
            >
              💬 {t("action.ask")}
            </button>
            <button
              type="button"
              onClick={() => onAction("explain", f)}
              className="text-xs font-medium px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-indigo-300 hover:text-indigo-600 dark:hover:text-indigo-300 transition-all"
            >
              📖 {t("action.explain")}
            </button>
            <button
              type="button"
              onClick={() => onAction("fix", f)}
              className="text-xs font-bold px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-all"
            >
              🔧 {t("action.fix")}
            </button>
          </div>
          <div className="flex items-center flex-wrap gap-4 pt-1 text-xs text-slate-400 dark:text-slate-600 border-t border-slate-100 dark:border-slate-800">
            {src && <span>{lang === "ru" ? "Источник" : "Source"}: <span className="text-slate-500">{src}</span></span>}
            {typeof f.confidence === "number" && (
              <span>{lang === "ru" ? "Уверенность" : "Confidence"}: <span className="text-slate-500">{Math.round(f.confidence * 100)}%</span></span>
            )}
            <span>{lang === "ru" ? "Язык" : "Language"}: <span className="text-slate-500">{fileLang}</span></span>
          </div>
        </div>
      )}
    </div>
  );
}

function ScanContent() {
  const { scanId } = useParams();
  const { lang, t } = useSettings();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState<Filters>(emptyFilters());
  const chatRef = useRef<ChatHandle>(null);
  const chatSectionRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!scanId) return;
    void api
      .getScan(scanId)
      .then((data) => {
        setScan(data.scan);
        setFindings(data.findings);
      })
      .catch((err: unknown) => {
        setError(
          err instanceof ApiError
            ? (err.detail ?? err.message)
            : t("common.error"),
        );
      })
      .finally(() => setLoading(false));
  }, [scanId, t]);

  // Build sidebar option lists
  const allSeverities = useMemo(() => {
    const order = ["critical", "high", "medium", "low", "info"];
    const counts = findings.reduce<Record<string, number>>((acc, f) => { acc[f.severity] = (acc[f.severity] ?? 0) + 1; return acc; }, {});
    const labels: Record<string, string> = { critical: "Критический", high: "Высокий", medium: "Средний", low: "Низкий", info: "Инфо" };
    const dots: Record<string, string> = { critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-slate-400", info: "bg-blue-400" };
    return order.filter((s) => counts[s] > 0).map((s) => ({ id: s, label: labels[s] ?? s, count: counts[s], dotCls: dots[s] }));
  }, [findings]);

  const allTypes = useMemo(() => {
    const counts: Record<string, number> = {};
    findings.forEach((f) => { if (f.source) { const t2 = sourceType(f.source); counts[t2] = (counts[t2] ?? 0) + 1; } });
    return Object.entries(counts).map(([id, count]) => ({ id, label: id, count }));
  }, [findings]);

  const allLanguages = useMemo(() => {
    const counts: Record<string, number> = {};
    findings.forEach((f) => { const l = fileLanguage(f.file); counts[l] = (counts[l] ?? 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([id, count]) => ({ id, label: id, count }));
  }, [findings]);

  const allLabels = useMemo(() => {
    const counts: Record<string, number> = {};
    findings.forEach((f) => { if (f.short_label) counts[f.short_label] = (counts[f.short_label] ?? 0) + 1; });
    return Object.entries(counts).map(([id, count]) => ({ id, label: id, count }));
  }, [findings]);

  const allEfforts = useMemo(() => {
    const order = ["Сложно", "Умеренно", "Просто", "Минимально"];
    const counts: Record<string, number> = {};
    findings.forEach((f) => { const e = estimateEffort(f.severity, f.fix).label; counts[e] = (counts[e] ?? 0) + 1; });
    return order.filter((e) => counts[e] > 0).map((e) => ({ id: e, label: e, count: counts[e] }));
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (filters.severity.size > 0 && !filters.severity.has(f.severity)) return false;
      if (filters.type.size > 0 && !filters.type.has(f.source ? sourceType(f.source) : "")) return false;
      if (filters.language.size > 0 && !filters.language.has(fileLanguage(f.file))) return false;
      if (filters.label.size > 0 && (!f.short_label || !filters.label.has(f.short_label))) return false;
      if (filters.effort.size > 0 && !filters.effort.has(estimateEffort(f.severity, f.fix).label)) return false;
      return true;
    });
  }, [findings, filters]);

  function toggleFilter(key: keyof Filters, id: string) {
    setFilters((prev) => {
      const next = { ...prev, [key]: new Set(prev[key]) };
      if ((next[key] as Set<string>).has(id)) (next[key] as Set<string>).delete(id);
      else (next[key] as Set<string>).add(id);
      return next;
    });
  }

  function scrollToChat() {
    chatSectionRef.current?.scrollIntoView({ behavior: "smooth" });
  }

  function onFindingAction(kind: "ask" | "explain" | "fix", f: ScanFinding) {
    const cf = toChatFinding(f);
    scrollToChat();
    if (kind === "ask") chatRef.current?.focus({ finding: cf });
    else if (kind === "explain") chatRef.current?.ask(t("action.explainFinding"), { finding: cf });
    else chatRef.current?.ask(t("action.fixFinding"), { finding: cf });
  }

  function onScanAction(kind: "ask" | "explain" | "fix") {
    scrollToChat();
    if (kind === "ask") chatRef.current?.focus({ finding: null });
    else if (kind === "explain") chatRef.current?.ask(t("action.explainScan"), { finding: null });
    else chatRef.current?.ask(t("action.fixScan"), { finding: null });
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-6xl px-4 sm:px-6 py-10">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-slate-200 dark:bg-slate-800 rounded-xl w-1/3" />
          <div className="grid grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-24 bg-slate-100 dark:bg-slate-900 rounded-2xl" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error)
    return (
      <div className="mx-auto max-w-6xl px-4 sm:px-6 py-10">
        <Alert>{error}</Alert>
      </div>
    );
  if (!scan) return null;

  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const med = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;
  const chatScan = toChatScan(scan, findings);
  const activeCount = countActive(filters);

  return (
    <div className="mx-auto max-w-6xl px-4 sm:px-6 py-10">
      <div className="flex items-center gap-2 text-sm text-slate-400 dark:text-slate-600 mb-6">
        <Link to="/dashboard" className="hover:text-slate-700 dark:hover:text-slate-300 transition-colors">
          {t("nav.projects")}
        </Link>
        <span>/</span>
        <span className="text-slate-700 dark:text-slate-300">{lang === "ru" ? "Сканирование" : "Scan"}</span>
        <span>/</span>
        <span className="font-mono text-slate-500">{scan.id.slice(0, 12)}</span>
      </div>

      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">{scan.repo_slug}</h1>
          <span className={`text-sm font-medium px-3 py-1 rounded-full border ${riskBadge(scan.risk_label)}`}>
            {riskLabel(scan.risk_label, lang)}
          </span>
        </div>
        <p className="text-slate-500 dark:text-slate-400 text-sm">PR #{scan.pr_id} · {scan.status}</p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        {[
          {
            label: lang === "ru" ? "Оценка риска" : "Risk score",
            value: <span className={`text-4xl font-black ${riskScoreColor(scan.risk_score)}`}>{scan.risk_score}</span>,
            sub: <span className="text-xs text-slate-500 dark:text-slate-600">{lang === "ru" ? "из 100" : "of 100"}</span>,
          },
          {
            label: lang === "ru" ? "Находки" : "Findings",
            value: <span className="text-4xl font-black text-slate-900 dark:text-white">{findings.length}</span>,
            sub: (
              <div className="flex gap-1 mt-1 flex-wrap">
                {crit > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-500/15 text-red-600 dark:text-red-400">{crit}</span>}
                {high > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-orange-100 dark:bg-orange-500/15 text-orange-600 dark:text-orange-400">{high}</span>}
                {med > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-100 dark:bg-yellow-500/15 text-yellow-600 dark:text-yellow-400">{med}</span>}
                {low > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400">{low}</span>}
              </div>
            ),
          },
          {
            label: lang === "ru" ? "Файлов проверено" : "Files scanned",
            value: <span className="text-4xl font-black text-slate-900 dark:text-white">{scan.files_scanned?.length ?? 0}</span>,
            sub: (scan.files_skipped?.length ?? 0) > 0
              ? <span className="text-xs text-slate-500 dark:text-slate-600">{scan.files_skipped.length} {lang === "ru" ? "пропущено" : "skipped"}</span>
              : null,
          },
          {
            label: lang === "ru" ? "Статус" : "Status",
            value: <span className="text-2xl font-black text-slate-900 dark:text-white">{scan.status}</span>,
            sub: (scan.degraded?.length ?? 0) > 0
              ? <span className="text-xs text-amber-500">⚠ {scan.degraded.join(", ")}</span>
              : null,
          },
        ].map(({ label, value, sub }) => (
          <div key={label} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5">
            <p className="text-xs text-slate-500 dark:text-slate-500 uppercase tracking-wider font-semibold mb-2">{label}</p>
            {value}
            {sub}
          </div>
        ))}
      </div>

      {chatScan.summary && (
        <div className="mb-8 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between gap-3 mb-2">
            <p className="text-xs text-slate-500 dark:text-slate-500 uppercase tracking-wider font-semibold">
              {lang === "ru" ? "Сводка ревью" : "Agent Review Summary"}
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => onScanAction("explain")}
                className="text-xs font-medium px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-indigo-300 hover:text-indigo-600 dark:hover:text-indigo-300 transition-all"
              >
                📖 {t("action.explain")}
              </button>
              <button
                type="button"
                onClick={() => onScanAction("fix")}
                className="text-xs font-bold px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-all"
              >
                🔧 {t("action.fix")} PR
              </button>
            </div>
          </div>
          <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed">
            {chatScan.summary}
          </p>
        </div>
      )}

      {/* Findings + Sidebar */}
      {findings.length > 0 ? (
        <div className="flex flex-col lg:flex-row gap-5 lg:items-start">
          {/* Left: findings list */}
          <div className="flex-1 min-w-0 space-y-3 w-full">
            <div className="flex items-center gap-2">
              <h2 className="font-semibold text-slate-900 dark:text-white text-lg">
                {lang === "ru" ? "Найденные проблемы" : "Findings"}
              </h2>
              <span className="text-xs text-slate-500 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-2.5 py-1 rounded-full">
                {filteredFindings.length}
              </span>
              {activeCount > 0 && (
                <span className="text-xs text-slate-400 dark:text-slate-600">из {findings.length}</span>
              )}
            </div>

            {filteredFindings.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 p-8 text-center">
                <p className="text-slate-500 dark:text-slate-400 text-sm">
                  {lang === "ru" ? "Нет проблем, соответствующих фильтрам" : "No findings match the current filters"}
                </p>
                <button
                  type="button"
                  onClick={() => setFilters(emptyFilters())}
                  className="mt-3 text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
                >
                  {lang === "ru" ? "Сбросить фильтры" : "Clear filters"}
                </button>
              </div>
            ) : (
              filteredFindings.map((f, i) => (
                <FindingCard key={`${f.file}-${f.line}-${i}`} f={f} onAction={onFindingAction} />
              ))
            )}
          </div>

          {/* Right: filter sidebar */}
          <div className="w-full lg:w-52 xl:w-60 lg:shrink-0 lg:sticky lg:top-4">
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-4 space-y-5">
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold text-slate-900 dark:text-white">
                  {lang === "ru" ? "Фильтры" : "Filters"}
                </p>
                {activeCount > 0 && (
                  <button
                    type="button"
                    onClick={() => setFilters(emptyFilters())}
                    className="text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
                  >
                    {lang === "ru" ? "Сбросить" : "Clear"}
                  </button>
                )}
              </div>
              {activeCount > 0 && (
                <div className="text-xs text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-500/10 border border-indigo-200 dark:border-indigo-500/20 rounded-lg px-2.5 py-1.5">
                  {lang === "ru" ? `Активно фильтров: ${activeCount}` : `Active filters: ${activeCount}`}
                </div>
              )}
              <FilterSection
                title={lang === "ru" ? "Серьёзность" : "Severity"}
                options={allSeverities}
                selected={filters.severity}
                onToggle={(id) => toggleFilter("severity", id)}
              />
              <FilterSection
                title={lang === "ru" ? "Тип" : "Type"}
                options={allTypes}
                selected={filters.type}
                onToggle={(id) => toggleFilter("type", id)}
              />
              {allLanguages.length > 1 && (
                <FilterSection
                  title={lang === "ru" ? "Язык" : "Language"}
                  options={allLanguages}
                  selected={filters.language}
                  onToggle={(id) => toggleFilter("language", id)}
                />
              )}
              {allLabels.length > 0 && (
                <FilterSection
                  title={lang === "ru" ? "Метка" : "Label"}
                  options={allLabels}
                  selected={filters.label}
                  onToggle={(id) => toggleFilter("label", id)}
                />
              )}
              {allEfforts.length > 1 && (
                <FilterSection
                  title={lang === "ru" ? "Трудоёмкость" : "Effort"}
                  options={allEfforts}
                  selected={filters.effort}
                  onToggle={(id) => toggleFilter("effort", id)}
                />
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-12 text-center">
          <div className="text-5xl mb-4">✅</div>
          <p className="font-semibold text-slate-900 dark:text-white text-xl mb-2">
            {lang === "ru" ? "Уязвимостей не обнаружено" : "No vulnerabilities found"}
          </p>
        </div>
      )}

      {/* Scan Chat */}
      <div className="mt-8" ref={chatSectionRef}>
        <div className="flex items-center gap-3 mb-6">
          <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
          <span className="text-xs text-slate-500 dark:text-slate-500 font-medium px-2">{t("action.askScan")}</span>
          <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
        </div>
        <Chat
          ref={chatRef}
          scan={chatScan}
          repo={scan.repo_slug}
          title={`Aegis · PR #${scan.pr_id}`}
          subtitle={
            lang === "ru"
              ? `Я изучил результаты сканирования PR #${scan.pr_id} (${scan.repo_slug}), Risk Score ${scan.risk_score}/100. Чем помочь?`
              : `I reviewed PR #${scan.pr_id} (${scan.repo_slug}), Risk Score ${scan.risk_score}/100. How can I help?`
          }
          className="h-[520px]"
        />
      </div>
    </div>
  );
}
