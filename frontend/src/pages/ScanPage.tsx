import { useState, useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { Alert } from "../components/Alert";
import { Chat } from "../components/Chat";
import type { QuickQuestion } from "../components/Chat";
import { RequireAuth } from "../context/AuthContext";
import { api, ApiError } from "../lib/api";
import { riskBadge, riskLabel, riskScoreColor, severityBadge, severityBorder, severityLabel } from "../lib/severity";
import type { ScanDetail, ScanFinding } from "../lib/types";

function scanQuickQuestions(prId: number, findingsCount: number): QuickQuestion[] {
  return [
    { icon: "📋", label: "Объясни результаты",  question: `Объясни результаты сканирования PR #${prId}` },
    { icon: "🚨", label: "Опасные уязвимости",  question: `Какие из ${findingsCount} находок наиболее критичны?` },
    { icon: "🔧", label: "Как исправить?",       question: "Дай конкретные рекомендации по исправлению каждой уязвимости" },
    { icon: "📈", label: "Снизить Risk Score",   question: "Как снизить Risk Score до приемлемого уровня?" },
    { icon: "🛡️", label: "Что такое CWE?",      question: "Объясни CWE-коды из результатов сканирования" },
    { icon: "📝", label: "Отчёт для команды",   question: "Составь краткий отчёт о результатах анализа для команды" },
  ];
}

function scanContext(scan: { repo_slug: string; pr_id: number; risk_score: number; risk_label: string; status: string }, findings: Array<{ severity: string; title: string; file: string; line: number; cwe: string | null }>): string {
  const counts = findings.reduce<Record<string, number>>((a, f) => {
    a[f.severity] = (a[f.severity] ?? 0) + 1;
    return a;
  }, {});
  return [
    `Репозиторий: ${scan.repo_slug}`,
    `PR: #${scan.pr_id}`,
    `Risk Score: ${scan.risk_score}/100 (${scan.risk_label})`,
    `Статус: ${scan.status}`,
    `Всего находок: ${findings.length}`,
    ...Object.entries(counts).map(([sev, n]) => `  ${sev}: ${n}`),
    findings.length > 0
      ? "\nНаходки:\n" +
        findings
          .map((f) => `- [${f.severity}] ${f.title} (${f.file}:${f.line}${f.cwe ? `, ${f.cwe}` : ""})`)
          .join("\n")
      : "Уязвимостей не найдено.",
  ].join("\n");
}

export function ScanPage() {
  return <RequireAuth><ScanContent /></RequireAuth>;
}

function statusLabel(s: string) {
  return { done: "Готово", running: "Анализ", pending: "Ожидание", failed: "Ошибка" }[s] ?? s;
}

function FindingCard({ f }: { f: ScanFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden border-l-4 ${severityBorder(f.severity)} hover:shadow-md dark:hover:shadow-black/20 transition-shadow`}>
      <button type="button" onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-5 py-4 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
        <span className={`shrink-0 mt-0.5 text-xs font-bold px-2.5 py-1 rounded-full ${severityBadge(f.severity)}`}>
          {severityLabel(f.severity)}
        </span>
        {f.cwe && (
          <span className="shrink-0 mt-0.5 text-xs font-mono px-2 py-1 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
            {f.cwe}
          </span>
        )}
        <span className="flex-1 font-semibold text-slate-900 dark:text-white text-sm leading-relaxed">{f.title}</span>
        <div className="shrink-0 flex flex-col items-end gap-1 ml-2">
          <span className="text-xs font-mono text-slate-400 dark:text-slate-500">{f.file}:{f.line}</span>
          <span className="text-slate-300 dark:text-slate-600 text-xs">{open ? "▲" : "▼"}</span>
        </div>
      </button>
      {open && (
        <div className="px-5 pb-5 pt-1 space-y-4 border-t border-slate-100 dark:border-slate-800">
          {f.rationale && (
            <div>
              <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">Почему это проблема</p>
              <p className="text-slate-600 dark:text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">{f.rationale}</p>
            </div>
          )}
          {f.fix && (
            <div>
              <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">Рекомендуемое исправление</p>
              <pre className="bg-slate-900 dark:bg-slate-950 border border-slate-700 dark:border-slate-800 rounded-xl p-4 text-xs text-slate-200 overflow-x-auto leading-relaxed whitespace-pre-wrap">{f.fix}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ScanContent() {
  const { scanId } = useParams();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return;
    void api.getScan(scanId)
      .then((data) => { setScan(data.scan); setFindings(data.findings); })
      .catch((err: unknown) => { setError(err instanceof ApiError ? (err.detail ?? err.message) : "Ошибка загрузки"); })
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) {
    return (
      <div className="mx-auto max-w-5xl px-4 sm:px-6 py-10">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-slate-200 dark:bg-slate-800 rounded-xl w-1/3" />
          <div className="grid grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => <div key={i} className="h-24 bg-slate-100 dark:bg-slate-900 rounded-2xl" />)}
          </div>
        </div>
      </div>
    );
  }

  if (error) return <div className="mx-auto max-w-5xl px-4 sm:px-6 py-10"><Alert>{error}</Alert></div>;
  if (!scan) return null;

  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const med  = findings.filter((f) => f.severity === "medium").length;
  const low  = findings.filter((f) => f.severity === "low").length;

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6 py-10">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-400 dark:text-slate-600 mb-6">
        <Link to="/dashboard" className="hover:text-slate-700 dark:hover:text-slate-300 transition-colors">Проекты</Link>
        <span>/</span>
        <span className="text-slate-700 dark:text-slate-300">Сканирование</span>
        <span>/</span>
        <span className="font-mono text-slate-500">{scan.id.slice(0, 12)}</span>
      </div>

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">{scan.repo_slug}</h1>
          <span className={`text-sm font-medium px-3 py-1 rounded-full border ${riskBadge(scan.risk_label)}`}>{riskLabel(scan.risk_label)}</span>
        </div>
        <p className="text-slate-500 dark:text-slate-400 text-sm">PR #{scan.pr_id} · {statusLabel(scan.status)}</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        {[
          {
            label: "Оценка риска",
            value: <span className={`text-4xl font-black ${riskScoreColor(scan.risk_score)}`}>{scan.risk_score}</span>,
            sub: <span className="text-xs text-slate-500 dark:text-slate-600">из 100</span>,
          },
          {
            label: "Находки",
            value: <span className="text-4xl font-black text-slate-900 dark:text-white">{findings.length}</span>,
            sub: (
              <div className="flex gap-1 mt-1 flex-wrap">
                {crit > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-500/15 text-red-600 dark:text-red-400">{crit}К</span>}
                {high > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-orange-100 dark:bg-orange-500/15 text-orange-600 dark:text-orange-400">{high}В</span>}
                {med  > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-100 dark:bg-yellow-500/15 text-yellow-600 dark:text-yellow-400">{med}С</span>}
                {low  > 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400">{low}Н</span>}
              </div>
            ),
          },
          {
            label: "Файлов проверено",
            value: <span className="text-4xl font-black text-slate-900 dark:text-white">{scan.files_scanned?.length ?? 0}</span>,
            sub: (scan.files_skipped?.length ?? 0) > 0
              ? <span className="text-xs text-slate-500 dark:text-slate-600">{scan.files_skipped.length} пропущено</span>
              : null,
          },
          {
            label: "Статус",
            value: <span className="text-2xl font-black text-slate-900 dark:text-white">{statusLabel(scan.status)}</span>,
            sub: (scan.degraded?.length ?? 0) > 0 ? <span className="text-xs text-amber-500">⚠ {scan.degraded.join(", ")}</span> : null,
          },
        ].map(({ label, value, sub }) => (
          <div key={label} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5">
            <p className="text-xs text-slate-500 dark:text-slate-500 uppercase tracking-wider font-semibold mb-2">{label}</p>
            {value}
            {sub}
          </div>
        ))}
      </div>

      {/* Findings */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-semibold text-slate-900 dark:text-white text-lg">Находки</h2>
        <span className="text-xs text-slate-500 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-2.5 py-1 rounded-full">{findings.length}</span>
      </div>

      {findings.length > 0 ? (
        <div className="space-y-3">{findings.map((f, i) => <FindingCard key={`${f.file}-${f.line}-${i}`} f={f} />)}</div>
      ) : (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-12 text-center">
          <div className="text-5xl mb-4">✅</div>
          <p className="font-semibold text-slate-900 dark:text-white text-xl mb-2">Уязвимостей не обнаружено</p>
          <p className="text-slate-500 dark:text-slate-500 text-sm max-w-sm mx-auto">
            Анализ не выявил подтверждённых проблем безопасности в изменённых строках кода.
          </p>
        </div>
      )}

      {/* Scan Chat */}
      <div className="mt-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
          <span className="text-xs text-slate-500 dark:text-slate-500 font-medium px-2">
            Спросить AI об этом сканировании
          </span>
          <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
        </div>
        <Chat
          context={scanContext(scan, findings)}
          quickQuestions={scanQuickQuestions(scan.pr_id, findings.length)}
          title={`AI · PR #${scan.pr_id}`}
          subtitle={`Я изучил результаты сканирования PR #${scan.pr_id} (${scan.repo_slug}). Risk Score: ${scan.risk_score}/100. Чем могу помочь?`}
          className="h-[480px]"
        />
      </div>
    </div>
  );
}
