import { useState } from "react";
import {
  severityBadge,
  severityBorder,
  severityLabel,
} from "../lib/severity";
import type { ReviewFinding, ReviewResult } from "../lib/types";

function sourceName(s: string): string {
  const m: Record<string, string> = {
    deterministic: "SAST",
    llm_a: "LLM-A",
    llm_b: "LLM-B",
    judge: "Judge",
  };
  return m[s] ?? s;
}

function RiskGauge({ score, crit, high }: { score: number; crit: number; high: number }) {
  const color =
    crit > 0 ? "text-red-500" : high > 0 ? "text-orange-500" : score > 40 ? "text-yellow-500" : "text-emerald-500";
  const ringColor =
    crit > 0 ? "stroke-red-500" : high > 0 ? "stroke-orange-500" : score > 40 ? "stroke-yellow-500" : "stroke-emerald-500";

  const r = 22;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-16 h-16">
        <svg className="w-16 h-16 -rotate-90" viewBox="0 0 56 56">
          <circle cx="28" cy="28" r={r} fill="none" strokeWidth="4"
            className="stroke-slate-200 dark:stroke-slate-800" />
          <circle cx="28" cy="28" r={r} fill="none" strokeWidth="4"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            className={`${ringColor} transition-all duration-700`} />
        </svg>
        <div className={`absolute inset-0 flex items-center justify-center text-base font-black ${color}`}>
          {score}
        </div>
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-500 mt-1 font-medium">Риск</p>
    </div>
  );
}

function SeverityBar({ findings }: { findings: ReviewFinding[] }) {
  const total = findings.length;
  if (total === 0) return null;

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  const bars = [
    { key: "critical", label: "Критич.", cls: "bg-red-500",    textCls: "text-red-500",    count: counts.critical ?? 0 },
    { key: "high",     label: "Высокий", cls: "bg-orange-500", textCls: "text-orange-500", count: counts.high ?? 0 },
    { key: "medium",   label: "Средний", cls: "bg-yellow-500", textCls: "text-yellow-500", count: counts.medium ?? 0 },
    { key: "low",      label: "Низкий",  cls: "bg-slate-400",  textCls: "text-slate-400",  count: counts.low ?? 0 },
  ].filter((b) => b.count > 0);

  return (
    <div className="space-y-2">
      {/* Stacked bar */}
      <div className="flex h-2 rounded-full overflow-hidden gap-0.5">
        {bars.map((b) => (
          <div
            key={b.key}
            className={`${b.cls} transition-all duration-500`}
            style={{ width: `${(b.count / total) * 100}%` }}
          />
        ))}
      </div>
      {/* Labels */}
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

function FindingCard({ f }: { f: ReviewFinding }) {
  const [open, setOpen] = useState(false);

  return (
    <div
      className={`bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden border-l-4 ${severityBorder(f.severity)} transition-shadow hover:shadow-md dark:hover:shadow-black/20`}
    >
      {/* Collapsed row */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-5 py-4 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
      >
        <span className={`shrink-0 mt-0.5 text-xs font-bold px-2.5 py-1 rounded-full ${severityBadge(f.severity)}`}>
          {severityLabel(f.severity)}
        </span>
        {f.cwe && (
          <span className="shrink-0 mt-0.5 text-xs font-mono px-2 py-1 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
            {f.cwe}
          </span>
        )}
        <span className="flex-1 font-semibold text-slate-900 dark:text-white text-sm leading-relaxed text-left">
          {f.title}
        </span>
        <div className="shrink-0 flex flex-col items-end gap-1 ml-2">
          <span className="text-xs font-mono text-slate-400 dark:text-slate-500 text-right">
            {f.file}{f.line ? `:${f.line}` : ""}
          </span>
          <span className="text-slate-300 dark:text-slate-600 text-xs">{open ? "▲" : "▼"}</span>
        </div>
      </button>

      {/* Expanded body */}
      {open && (
        <div className="px-5 pb-5 pt-1 space-y-4 border-t border-slate-100 dark:border-slate-800">
          {f.rationale && (
            <div>
              <p className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">
                Почему это проблема
              </p>
              <p className="text-slate-600 dark:text-slate-300 text-sm leading-relaxed">{f.rationale}</p>
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
          <div className="flex items-center gap-4 pt-1 text-xs text-slate-400 dark:text-slate-600 border-t border-slate-100 dark:border-slate-800">
            <span>Источник: <span className="text-slate-500">{sourceName(f.source)}</span></span>
            <span>Уверенность: <span className="text-slate-500">{Math.round(f.confidence * 100)}%</span></span>
          </div>
        </div>
      )}
    </div>
  );
}

export function ReviewFindings({ result }: { result: ReviewResult }) {
  const total = result.findings.length;
  const crit  = result.findings.filter((f) => f.severity === "critical").length;
  const high  = result.findings.filter((f) => f.severity === "high").length;
  const score = crit > 0 ? 85 + Math.min(crit * 5, 14) : high > 0 ? 55 + Math.min(high * 10, 29) : total > 0 ? 25 : 0;

  return (
    <div className="space-y-4">
      {/* PR summary hero card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm">
        {/* Top stripe */}
        <div className="h-1 bg-gradient-to-r from-indigo-500 via-violet-500 to-purple-500" />

        <div className="p-6">
          {/* PR title + meta */}
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
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8z" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  {result.pr_author}
                </span>
                <span className="flex items-center gap-1">
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path d="M9 12h6M9 16h6M17 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V5a2 2 0 00-2-2z" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  {result.files_scanned} файлов
                </span>
                <span className="flex items-center gap-1">
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path d="M12 9v4l3 3M12 3a9 9 0 100 18A9 9 0 0012 3z" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  {total} {total === 1 ? "находка" : total < 5 ? "находки" : "находок"}
                </span>
              </div>
            </div>
          </div>

          {/* Severity breakdown */}
          {total > 0 && <SeverityBar findings={result.findings} />}

          {total === 0 && (
            <div className="flex items-center gap-3 bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/20 rounded-xl px-4 py-3">
              <span className="text-emerald-500 text-xl">✅</span>
              <span className="text-sm font-semibold text-emerald-700 dark:text-emerald-300">Уязвимостей не обнаружено</span>
            </div>
          )}
        </div>

        {/* Degraded warning */}
        {result.degraded && (
          <div className="border-t border-slate-100 dark:border-slate-800 px-6 py-3 flex items-center gap-2 bg-amber-50 dark:bg-amber-500/5 text-xs text-amber-600 dark:text-amber-300">
            <span>⚠</span>
            <span>LLM-анализ пропущен — OpenRouter недоступен. Показаны только детерминированные результаты.</span>
          </div>
        )}
      </div>

      {/* Findings list */}
      {result.findings.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 px-1">
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Найденные проблемы</h3>
            <span className="text-xs text-slate-400 dark:text-slate-600 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-full">{total}</span>
          </div>
          {result.findings.map((f, i) => (
            <FindingCard key={`${f.file}-${f.line}-${i}`} f={f} />
          ))}
        </div>
      )}
    </div>
  );
}
