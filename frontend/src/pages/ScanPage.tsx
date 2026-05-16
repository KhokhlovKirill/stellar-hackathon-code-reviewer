import { useEffect, useRef, useState } from "react";
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
  return (
    <div
      className={`bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden border-l-4 ${severityBorder(f.severity)} hover:shadow-md dark:hover:shadow-black/20 transition-shadow`}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-5 py-4 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
      >
        <span
          className={`shrink-0 mt-0.5 text-xs font-bold px-2.5 py-1 rounded-full ${severityBadge(f.severity)}`}
        >
          {severityLabel(f.severity, lang)}
        </span>
        {f.cwe && (
          <span className="shrink-0 mt-0.5 text-xs font-mono px-2 py-1 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
            {f.cwe}
          </span>
        )}
        <span className="flex-1 font-semibold text-slate-900 dark:text-white text-sm leading-relaxed">
          {f.title}
        </span>
        <div className="shrink-0 flex flex-col items-end gap-1 ml-2">
          <span className="text-xs font-mono text-slate-400 dark:text-slate-500">
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
          {/* Finding action menu — mirrors the VS Code extension */}
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
          {(f.source || typeof f.confidence === "number") && (
            <div className="flex items-center gap-4 pt-1 text-xs text-slate-400 dark:text-slate-600 border-t border-slate-100 dark:border-slate-800">
              {f.source && (
                <span>
                  {lang === "ru" ? "Источник" : "Source"}:{" "}
                  <span className="text-slate-500">{f.source}</span>
                </span>
              )}
              {typeof f.confidence === "number" && (
                <span>
                  {lang === "ru" ? "Уверенность" : "Confidence"}:{" "}
                  <span className="text-slate-500">
                    {Math.round(f.confidence * 100)}%
                  </span>
                </span>
              )}
            </div>
          )}
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

  function scrollToChat() {
    chatSectionRef.current?.scrollIntoView({ behavior: "smooth" });
  }

  function onFindingAction(
    kind: "ask" | "explain" | "fix",
    f: ScanFinding,
  ) {
    const cf = toChatFinding(f);
    scrollToChat();
    if (kind === "ask") chatRef.current?.focus({ finding: cf });
    else if (kind === "explain")
      chatRef.current?.ask(t("action.explainFinding"), { finding: cf });
    else chatRef.current?.ask(t("action.fixFinding"), { finding: cf });
  }

  function onScanAction(kind: "ask" | "explain" | "fix") {
    scrollToChat();
    if (kind === "ask") chatRef.current?.focus({ finding: null });
    else if (kind === "explain")
      chatRef.current?.ask(t("action.explainScan"), { finding: null });
    else chatRef.current?.ask(t("action.fixScan"), { finding: null });
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-5xl px-4 sm:px-6 py-10">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-slate-200 dark:bg-slate-800 rounded-xl w-1/3" />
          <div className="grid grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className="h-24 bg-slate-100 dark:bg-slate-900 rounded-2xl"
              />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error)
    return (
      <div className="mx-auto max-w-5xl px-4 sm:px-6 py-10">
        <Alert>{error}</Alert>
      </div>
    );
  if (!scan) return null;

  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const med = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;
  const chatScan = toChatScan(scan, findings);

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6 py-10">
      <div className="flex items-center gap-2 text-sm text-slate-400 dark:text-slate-600 mb-6">
        <Link
          to="/dashboard"
          className="hover:text-slate-700 dark:hover:text-slate-300 transition-colors"
        >
          {t("nav.projects")}
        </Link>
        <span>/</span>
        <span className="text-slate-700 dark:text-slate-300">
          {lang === "ru" ? "Сканирование" : "Scan"}
        </span>
        <span>/</span>
        <span className="font-mono text-slate-500">{scan.id.slice(0, 12)}</span>
      </div>

      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
            {scan.repo_slug}
          </h1>
          <span
            className={`text-sm font-medium px-3 py-1 rounded-full border ${riskBadge(scan.risk_label)}`}
          >
            {riskLabel(scan.risk_label, lang)}
          </span>
        </div>
        <p className="text-slate-500 dark:text-slate-400 text-sm">
          PR #{scan.pr_id} · {scan.status}
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        {[
          {
            label: lang === "ru" ? "Оценка риска" : "Risk score",
            value: (
              <span
                className={`text-4xl font-black ${riskScoreColor(scan.risk_score)}`}
              >
                {scan.risk_score}
              </span>
            ),
            sub: (
              <span className="text-xs text-slate-500 dark:text-slate-600">
                {lang === "ru" ? "из 100" : "of 100"}
              </span>
            ),
          },
          {
            label: lang === "ru" ? "Находки" : "Findings",
            value: (
              <span className="text-4xl font-black text-slate-900 dark:text-white">
                {findings.length}
              </span>
            ),
            sub: (
              <div className="flex gap-1 mt-1 flex-wrap">
                {crit > 0 && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-500/15 text-red-600 dark:text-red-400">
                    {crit}
                  </span>
                )}
                {high > 0 && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-orange-100 dark:bg-orange-500/15 text-orange-600 dark:text-orange-400">
                    {high}
                  </span>
                )}
                {med > 0 && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-100 dark:bg-yellow-500/15 text-yellow-600 dark:text-yellow-400">
                    {med}
                  </span>
                )}
                {low > 0 && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400">
                    {low}
                  </span>
                )}
              </div>
            ),
          },
          {
            label: lang === "ru" ? "Файлов проверено" : "Files scanned",
            value: (
              <span className="text-4xl font-black text-slate-900 dark:text-white">
                {scan.files_scanned?.length ?? 0}
              </span>
            ),
            sub:
              (scan.files_skipped?.length ?? 0) > 0 ? (
                <span className="text-xs text-slate-500 dark:text-slate-600">
                  {scan.files_skipped.length}{" "}
                  {lang === "ru" ? "пропущено" : "skipped"}
                </span>
              ) : null,
          },
          {
            label: lang === "ru" ? "Статус" : "Status",
            value: (
              <span className="text-2xl font-black text-slate-900 dark:text-white">
                {scan.status}
              </span>
            ),
            sub:
              (scan.degraded?.length ?? 0) > 0 ? (
                <span className="text-xs text-amber-500">
                  ⚠ {scan.degraded.join(", ")}
                </span>
              ) : null,
          },
        ].map(({ label, value, sub }) => (
          <div
            key={label}
            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5"
          >
            <p className="text-xs text-slate-500 dark:text-slate-500 uppercase tracking-wider font-semibold mb-2">
              {label}
            </p>
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

      <div className="flex items-center justify-between mb-4">
        <h2 className="font-semibold text-slate-900 dark:text-white text-lg">
          {lang === "ru" ? "Находки" : "Findings"}
        </h2>
        <span className="text-xs text-slate-500 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-2.5 py-1 rounded-full">
          {findings.length}
        </span>
      </div>

      {findings.length > 0 ? (
        <div className="space-y-3">
          {findings.map((f, i) => (
            <FindingCard
              key={`${f.file}-${f.line}-${i}`}
              f={f}
              onAction={onFindingAction}
            />
          ))}
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-12 text-center">
          <div className="text-5xl mb-4">✅</div>
          <p className="font-semibold text-slate-900 dark:text-white text-xl mb-2">
            {lang === "ru"
              ? "Уязвимостей не обнаружено"
              : "No vulnerabilities found"}
          </p>
        </div>
      )}

      {/* Scan Chat — same structured context & path as the VS Code extension */}
      <div className="mt-8" ref={chatSectionRef}>
        <div className="flex items-center gap-3 mb-6">
          <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
          <span className="text-xs text-slate-500 dark:text-slate-500 font-medium px-2">
            {t("action.askScan")}
          </span>
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
