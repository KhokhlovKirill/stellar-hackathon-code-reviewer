import * as vscode from "vscode";
import type { Finding, ScanResult, SeverityLevel } from "../types";
import { SEVERITY_ORDER } from "../types";

function escHtml(s: string): string {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function jsLiteral(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function riskBadgeClass(score: number): string {
  if (score <= 30) return "risk-low";
  if (score <= 60) return "risk-medium";
  if (score <= 80) return "risk-high";
  return "risk-critical";
}

function buildReadableSummary(scan: ScanResult): string {
  const total = scan.findings.length;
  const critical = scan.findings.filter((f) => f.severity === "critical").length;
  const high = scan.findings.filter((f) => f.severity === "high").length;
  const medium = scan.findings.filter((f) => f.severity === "medium").length;
  const low = scan.findings.filter((f) => f.severity === "low").length;
  const priority = scan.findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 4);

  if (scan.summary && scan.summary.trim()) {
    return scan.summary.trim();
  }

  if (total === 0) {
    return [
      `Aegis проверил ${scan.files_scanned} изменённых файлов в этом pull request.`,
      "Подтверждённых exploitable security проблем на изменённых строках не найдено.",
      "Перед merge всё равно стоит проверить бизнес-логику и покрытие тестами, потому что автоматический анализ не заменяет финальное ревью владельца кода.",
    ].join("\n");
  }

  const counts = [
    critical ? `${critical} critical` : "",
    high ? `${high} high` : "",
    medium ? `${medium} medium` : "",
    low ? `${low} low` : "",
  ].filter(Boolean).join(", ");

  const lines = [
    `Aegis проверил ${scan.files_scanned} изменённых файлов и нашёл ${total} security finding(s): ${counts}.`,
  ];
  if (critical || high) {
    lines.push(
      "До merge нужно сначала закрыть critical/high finding(s), потому что они могут дать прямой путь к эксплуатации или утечке секретов."
    );
  } else {
    lines.push(
      "Критичных блокеров не найдено, но medium/low finding(s) стоит разобрать до слияния или явно принять риск."
    );
  }
  if (priority.length > 0) {
    lines.push("Главные пункты для ревью:");
    for (const f of priority) {
      lines.push(`- ${f.severity.toUpperCase()} ${f.file}:${f.line}: ${f.title}`);
    }
  }
  lines.push(
    "Кнопки ниже открывают агента с контекстом всего PR: можно попросить объяснить ревью, сгруппировать причины или подготовить план исправлений."
  );
  return lines.join("\n");
}

function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#ca8a04",
    low: "#2563eb",
    info: "#6b7280",
  };
  return map[severity] ?? "#6b7280";
}

function findingHtml(f: Finding, idx: number): string {
  const cweHtml = f.cwe
    ? `<a class="cwe-badge" href="https://cwe.mitre.org/data/definitions/${f.cwe.replace(/^CWE-/i, "")}.html" target="_blank">${escHtml(f.cwe)}</a>`
    : "";
  const shortLabel = (f.short_label || f.title || "")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 5)
    .join(" ");
  const shortLabelHtml = shortLabel
    ? `<span class="short-label" title="Model-generated compact label">${escHtml(shortLabel)}</span>`
    : "";

  const exploitHtml = f.exploit
    ? `<details class="expandable"><summary>Exploit scenario</summary><div class="expandable-body">${escHtml(f.exploit)}</div></details>`
    : "";

  const fixHtml = f.fix
    ? `<details class="expandable"><summary>Suggested fix</summary><div class="expandable-body code-block">${escHtml(f.fix)}</div></details>`
    : "";

  return `
    <div class="finding-card" data-fingerprint="${escHtml(f.fingerprint)}" data-idx="${idx}">
      <div class="finding-header">
        <div class="finding-meta">
          <span class="severity-dot" style="background:${severityColor(f.severity)}"></span>
          <span class="finding-title">${escHtml(f.title)}</span>
          ${shortLabelHtml}
          ${cweHtml}
          <span class="source-badge">${escHtml(f.source)}</span>
        </div>
        <div class="finding-actions">
          <button class="btn-sm btn-fix" data-fingerprint="${escHtml(f.fingerprint)}" title="Auto-fix this finding">Fix</button>
          <button class="btn-sm btn-chat" data-fingerprint="${escHtml(f.fingerprint)}" title="Ask agent about this finding">Ask Agent</button>
          <button class="btn-sm btn-ignore" data-fingerprint="${escHtml(f.fingerprint)}" title="Mark as false positive">Ignore</button>
        </div>
      </div>
      <div class="finding-location">
        <a href="#" class="file-link" data-file="${escHtml(f.file)}" data-line="${f.line}">
          ${escHtml(f.file)}:${f.line}
        </a>
        <span class="confidence-badge">conf: ${Math.round(f.confidence * 100)}%</span>
      </div>
      <div class="finding-rationale">${escHtml(f.rationale)}</div>
      ${exploitHtml}
      ${fixHtml}
    </div>`;
}

function severitySectionHtml(
  severity: SeverityLevel,
  findings: Finding[]
): string {
  if (findings.length === 0) return "";

  const open = severity === "critical" || severity === "high" ? "open" : "";
  const color = severityColor(severity);

  return `
    <details class="severity-section" ${open}>
      <summary class="severity-header">
        <span class="severity-dot" style="background:${color}"></span>
        <span class="severity-label">${severity.toUpperCase()}</span>
        <span class="severity-count">${findings.length}</span>
      </summary>
      <div class="findings-list">
        ${findings.map((f, i) => findingHtml(f, i)).join("")}
      </div>
    </details>`;
}

export function getPRDetailWebviewContent(
  webview: vscode.Webview,
  _extensionUri: vscode.Uri,
  scanResult: ScanResult
): string {
  const nonce = Math.random().toString(36).slice(2);
  const csp = `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; img-src data:; connect-src 'none';`;

  // Group findings by severity
  const bySeverity = new Map<SeverityLevel, Finding[]>();
  const severityOrder: SeverityLevel[] = ["critical", "high", "medium", "low", "info"];
  for (const sev of severityOrder) bySeverity.set(sev, []);
  for (const f of scanResult.findings) {
    const sev = f.severity as SeverityLevel;
    bySeverity.get(sev)!.push(f);
  }

  const sectionsHtml = severityOrder
    .map((sev) => severitySectionHtml(sev, bySeverity.get(sev)!))
    .join("");

  const riskClass = riskBadgeClass(
    scanResult.findings.length > 0
      ? Math.round(
          (scanResult.findings.filter(
            (f) => SEVERITY_ORDER[f.severity] <= 1
          ).length /
            Math.max(scanResult.findings.length, 1)) *
            100
        )
      : 0
  );

  const degradedBadge = scanResult.degraded
    ? `<span class="degraded-badge" title="LLM analysis was degraded - results may be incomplete">⚠ Degraded</span>`
    : "";

  const initialJson = jsLiteral(scanResult);
  const summaryHtml = escHtml(buildReadableSummary(scanResult));
  const compactLabels = scanResult.findings
    .map((f) => (f.short_label || f.title || "").split(/\s+/).filter(Boolean).slice(0, 5).join(" "))
    .filter(Boolean);
  const compactLabelsHtml = compactLabels.length
    ? `<div class="summary-labels">${compactLabels.map((label) => `<span>${escHtml(label)}</span>`).join("")}</div>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="${csp}" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Aegis PR Detail</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --color-bg: var(--vscode-editor-background);
      --color-fg: var(--vscode-editor-foreground);
      --color-border: var(--vscode-panel-border, #3c3c3c);
      --color-surface: var(--vscode-editorWidget-background, #252526);
      --color-button-bg: var(--vscode-button-background);
      --color-button-fg: var(--vscode-button-foreground);
      --color-button-hover: var(--vscode-button-hoverBackground);
      --radius: 6px;
    }

    body {
      font-family: var(--vscode-font-family, system-ui, sans-serif);
      font-size: var(--vscode-font-size, 13px);
      background: var(--color-bg);
      color: var(--color-fg);
      min-height: 100vh;
    }

    /* PR Header */
    .pr-header {
      padding: 16px 20px 12px;
      border-bottom: 1px solid var(--color-border);
      background: var(--color-surface);
    }
    .pr-header-top {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .pr-title {
      font-size: 15px;
      font-weight: 600;
      flex: 1;
      min-width: 200px;
    }
    .pr-actions { display: flex; gap: 8px; flex-shrink: 0; }

    .pr-meta {
      margin-top: 8px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      font-size: 12px;
      opacity: 0.75;
    }
    .pr-meta span { display: flex; align-items: center; gap: 4px; }

    /* Risk badge */
    .risk-badge {
      display: inline-flex;
      align-items: center;
      padding: 3px 10px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.04em;
      flex-shrink: 0;
    }
    .risk-low      { background: #166534; color: #bbf7d0; }
    .risk-medium   { background: #854d0e; color: #fef08a; }
    .risk-high     { background: #9a3412; color: #fed7aa; }
    .risk-critical { background: #7f1d1d; color: #fecaca; }

    .degraded-badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 12px;
      background: #78350f;
      color: #fde68a;
      font-size: 11px;
      margin-left: 8px;
    }

    /* Stats bar */
    .stats-bar {
      padding: 10px 20px;
      border-bottom: 1px solid var(--color-border);
      display: flex;
      gap: 24px;
      flex-wrap: wrap;
      font-size: 12px;
    }
    .stat { display: flex; align-items: center; gap: 6px; }
    .stat-value { font-weight: 700; font-size: 15px; }
    .stat-label { opacity: 0.65; }

    /* Findings sections */
    .findings-container { padding: 12px 20px; }

    .severity-section {
      margin-bottom: 8px;
      border: 1px solid var(--color-border);
      border-radius: var(--radius);
      overflow: hidden;
    }
    .severity-section summary {
      list-style: none;
      cursor: pointer;
    }
    .severity-section summary::-webkit-details-marker { display: none; }

    .severity-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      background: var(--color-surface);
      user-select: none;
    }
    .severity-header:hover { opacity: 0.85; }
    .severity-label { font-weight: 600; font-size: 12px; letter-spacing: 0.05em; flex: 1; }
    .severity-count {
      background: var(--color-border);
      border-radius: 10px;
      padding: 1px 7px;
      font-size: 11px;
    }

    .severity-dot {
      width: 10px; height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    .findings-list { padding: 4px 0; }

    /* Individual finding card */
    .finding-card {
      padding: 10px 14px;
      border-bottom: 1px solid var(--color-border);
    }
    .finding-card:last-child { border-bottom: none; }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 10px;
      flex-wrap: wrap;
    }
    .finding-meta {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      flex: 1;
    }
    .finding-title { font-weight: 600; }
    .finding-actions {
      display: flex;
      gap: 6px;
      flex-shrink: 0;
    }

    .finding-location {
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .file-link {
      font-size: 12px;
      color: var(--vscode-textLink-foreground, #4ec9b0);
      text-decoration: none;
      font-family: var(--vscode-editor-font-family, monospace);
    }
    .file-link:hover { text-decoration: underline; }

    .confidence-badge {
      font-size: 11px;
      opacity: 0.55;
    }

    .finding-rationale {
      font-size: 12px;
      opacity: 0.8;
      margin-top: 6px;
      line-height: 1.5;
    }

    .expandable {
      margin-top: 6px;
    }
    .expandable summary {
      font-size: 12px;
      cursor: pointer;
      color: var(--vscode-textLink-foreground, #4ec9b0);
      list-style: none;
    }
    .expandable summary::-webkit-details-marker { display: none; }
    .expandable-body {
      margin-top: 6px;
      font-size: 12px;
      line-height: 1.5;
      opacity: 0.85;
      padding-left: 10px;
      border-left: 2px solid var(--color-border);
    }
    .code-block {
      font-family: var(--vscode-editor-font-family, monospace);
      background: var(--vscode-textCodeBlock-background, #1e1e1e);
      padding: 8px 10px;
      border-radius: 4px;
      white-space: pre-wrap;
    }

    .cwe-badge {
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 4px;
      background: var(--vscode-badge-background, #4a4a4a);
      color: var(--vscode-badge-foreground, #fff);
      text-decoration: none;
    }
    .cwe-badge:hover { opacity: 0.8; }
    .short-label,
    .source-badge {
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 4px;
      background: var(--vscode-editor-background);
      border: 1px solid var(--color-border);
      color: var(--color-fg);
      opacity: 0.82;
      max-width: 180px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .source-badge {
      opacity: 0.62;
      font-family: var(--vscode-editor-font-family, monospace);
    }

    /* Buttons */
    .btn {
      background: var(--color-button-bg);
      color: var(--color-button-fg);
      border: none;
      border-radius: var(--radius);
      padding: 6px 14px;
      cursor: pointer;
      font-size: 12px;
    }
    .btn:hover { background: var(--color-button-hover); }
    .btn-secondary {
      background: transparent;
      border: 1px solid var(--color-border);
      color: var(--color-fg);
    }
    .btn-secondary:hover { background: var(--color-surface); }

    .btn-sm {
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 4px;
      border: 1px solid var(--color-border);
      background: transparent;
      color: var(--color-fg);
      cursor: pointer;
    }
    .btn-sm:hover { background: var(--color-surface); }
    .btn-fix { border-color: var(--color-button-bg); color: var(--color-button-fg); background: var(--color-button-bg); }
    .btn-fix:hover { background: var(--color-button-hover); }

    .empty-state {
      text-align: center;
      padding: 48px 20px;
      opacity: 0.5;
      font-size: 14px;
    }
    .summary-panel {
      margin: 12px 20px 20px;
      border: 1px solid var(--color-border);
      border-radius: var(--radius);
      background: var(--color-surface);
      padding: 14px;
    }
    .summary-panel h2 {
      font-size: 13px;
      margin-bottom: 8px;
      font-weight: 700;
    }
    .summary-text {
      font-size: 12px;
      line-height: 1.55;
      opacity: 0.9;
      white-space: pre-wrap;
    }
    .summary-labels {
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .summary-labels span {
      font-size: 11px;
      padding: 3px 7px;
      border-radius: 4px;
      border: 1px solid var(--color-border);
      background: var(--vscode-editor-background);
      color: var(--color-fg);
      opacity: 0.84;
      max-width: 170px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .summary-actions {
      margin-top: 12px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .error-banner {
      display: none;
      margin: 12px 20px;
      padding: 10px 12px;
      border: 1px solid #7f1d1d;
      border-radius: var(--radius);
      color: #fecaca;
      background: #450a0a;
      font-size: 12px;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div class="pr-header">
    <div class="pr-header-top">
      <div class="pr-title" id="prTitle">${escHtml(scanResult.pr_title || `PR #${scanResult.pr_number}`)}</div>
      <div class="pr-actions">
        <button class="btn btn-secondary" id="rescanBtn">Re-scan</button>
        <button class="btn" id="fixAllBtn">Fix All</button>
      </div>
    </div>
    <div class="pr-meta">
      ${scanResult.pr_author ? `<span>👤 ${escHtml(scanResult.pr_author)}</span>` : ""}
      ${scanResult.pr_url ? `<span><a href="${escHtml(scanResult.pr_url)}" style="color:inherit">PR #${scanResult.pr_number}</a></span>` : ""}
      <span id="riskBadgeContainer">
        <span class="risk-badge ${riskClass}" id="riskBadge">
          ${scanResult.findings.length === 0 ? "Clean" : `${scanResult.findings.filter(f => SEVERITY_ORDER[f.severity as SeverityLevel] <= 1).length} critical/high`}
        </span>
        ${degradedBadge}
      </span>
    </div>
  </div>

  <div class="stats-bar">
    <div class="stat">
      <span class="stat-value" id="statFiles">${scanResult.files_scanned}</span>
      <span class="stat-label">files scanned</span>
    </div>
    <div class="stat">
      <span class="stat-value" id="statFindings">${scanResult.findings.length}</span>
      <span class="stat-label">findings</span>
    </div>
    <div class="stat">
      <span class="stat-value" id="statCritical">${scanResult.findings.filter(f => f.severity === "critical").length}</span>
      <span class="stat-label">critical</span>
    </div>
    <div class="stat">
      <span class="stat-value" id="statHigh">${scanResult.findings.filter(f => f.severity === "high").length}</span>
      <span class="stat-label">high</span>
    </div>
    ${scanResult.repo ? `<div class="stat"><span class="stat-label">Repo: <strong>${escHtml(scanResult.repo)}</strong></span></div>` : ""}
  </div>

  <div class="error-banner" id="errorBanner"></div>

  <div class="findings-container" id="findingsContainer">
    ${scanResult.findings.length === 0
      ? '<div class="empty-state">No findings — this PR looks clean!</div>'
      : sectionsHtml
    }
  </div>

  <div class="summary-panel">
    <h2>Agent Review Summary</h2>
    <div class="summary-text">${summaryHtml}</div>
    ${compactLabelsHtml}
    <div class="summary-actions">
      <button class="btn" id="askPrBtn">Ask Agent About PR</button>
      <button class="btn btn-secondary" id="explainPrBtn">Explain Whole Review</button>
      <button class="btn btn-secondary" id="fixPrBtn">Generate Whole-PR Fix Plan</button>
    </div>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    let currentScan = ${initialJson};
    let findingsByFingerprint = new Map(
      (currentScan.findings || []).map(f => [String(f.fingerprint), f])
    );

    function escHtml(s) {
      return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
    }

    function showError(message) {
      const banner = document.getElementById('errorBanner');
      if (!banner) return;
      banner.textContent = String(message);
      banner.style.display = 'block';
    }

    function post(type, payload) {
      try {
        vscode.postMessage({ type, ...(payload || {}) });
      } catch (err) {
        showError('Cannot send command to VS Code extension host: ' + String(err));
      }
    }

    // File link handler
    document.addEventListener('click', (e) => {
      try {
        const target = e.target && e.target.closest ? e.target : null;
        if (!target) return;

        const fileLink = target.closest('.file-link');
        if (fileLink) {
          e.preventDefault();
          post('openFile', {
            file: fileLink.dataset.file,
            line: parseInt(fileLink.dataset.line, 10)
          });
          return;
        }

        const fixBtn = target.closest('.btn-fix');
        if (fixBtn) {
          const finding = findingsByFingerprint.get(String(fixBtn.dataset.fingerprint));
          if (!finding) {
            showError('Finding was not found in current scan data.');
            return;
          }
          post('fixFinding', { fingerprint: finding.fingerprint, finding });
          return;
        }

        const chatBtn = target.closest('.btn-chat');
        if (chatBtn) {
          const finding = findingsByFingerprint.get(String(chatBtn.dataset.fingerprint));
          if (!finding) {
            showError('Finding was not found in current scan data.');
            return;
          }
          post('chatFinding', { fingerprint: finding.fingerprint, finding });
          return;
        }

        const ignoreBtn = target.closest('.btn-ignore');
        if (ignoreBtn) {
          const fp = ignoreBtn.dataset.fingerprint;
          const finding = findingsByFingerprint.get(String(fp));
          post('ignoreFinding', { fingerprint: fp, finding });
          const card = ignoreBtn.closest('.finding-card');
          if (card) {
            card.style.opacity = '0.4';
            card.style.pointerEvents = 'none';
          }
          return;
        }
      } catch (err) {
        showError('PR panel action failed: ' + String(err));
      }
    });

    document.getElementById('fixAllBtn').addEventListener('click', () => {
      post('fixAll');
    });

    document.getElementById('rescanBtn').addEventListener('click', () => {
      post('rescan', { scan: currentScan });
    });

    document.getElementById('askPrBtn').addEventListener('click', () => {
      post('chatScan', {
        prompt: 'Answer questions about the whole pull request review. Start by summarizing the most important security risks and the evidence for each.'
      });
    });

    document.getElementById('explainPrBtn').addEventListener('click', () => {
      post('chatScan', {
        prompt: 'Explain the whole security review for this pull request in plain language. Group findings by root cause, call out duplicates, and explain what must be fixed before merge.'
      });
    });

    document.getElementById('fixPrBtn').addEventListener('click', () => {
      post('chatScan', {
        prompt: 'Create a complete remediation plan for this pull request. If possible, provide unified diff patches for all critical and high severity findings, then list anything that needs manual verification.'
      });
    });

    // Handle messages from extension host
    window.addEventListener('message', (event) => {
      const msg = event.data;
      if (msg.type === 'loadScan') {
        currentScan = msg.scan;
        findingsByFingerprint = new Map(
          (currentScan.findings || []).map(f => [String(f.fingerprint), f])
        );
      }
    });
  </script>
</body>
</html>`;
}
