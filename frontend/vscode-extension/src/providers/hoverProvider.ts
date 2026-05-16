import * as vscode from "vscode";
import type { DiagnosticsProvider } from "./diagnosticsProvider";

export class AegisHoverProvider implements vscode.HoverProvider {
  constructor(private readonly diagnosticsProvider: DiagnosticsProvider) {}

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken
  ): vscode.Hover | null {
    const finding = this.diagnosticsProvider.getFindingAtLine(
      document.uri.fsPath,
      position.line
    );

    if (!finding) return null;

    const md = new vscode.MarkdownString("", true);
    md.isTrusted = true;
    md.supportHtml = false;

    // Header with severity badge
    const severityEmoji: Record<string, string> = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🔵",
      info: "⚪",
    };

    const badge = severityEmoji[finding.severity] ?? "⚫";
    md.appendMarkdown(
      `## ${badge} **${finding.severity.toUpperCase()}** — ${finding.title}\n\n`
    );

    if (finding.cwe) {
      md.appendMarkdown(
        `**CWE:** [${finding.cwe}](https://cwe.mitre.org/data/definitions/${finding.cwe.replace(/^CWE-/i, "")}.html)\n\n`
      );
    }

    md.appendMarkdown(`---\n\n`);
    md.appendMarkdown(`**Why this matters:**\n\n${finding.rationale}\n\n`);

    if (finding.exploit) {
      md.appendMarkdown(`**Exploit scenario:**\n\n${finding.exploit}\n\n`);
    }

    if (finding.fix) {
      md.appendMarkdown(`**Suggested fix:**\n\n`);
      md.appendCodeblock(finding.fix, "");
    }

    md.appendMarkdown(`---\n\n`);

    // Command links
    const fixArgs = encodeURIComponent(JSON.stringify([finding]));
    const chatArgs = encodeURIComponent(JSON.stringify([finding]));
    const ignoreArgs = encodeURIComponent(JSON.stringify([finding.fingerprint]));

    md.appendMarkdown(
      `[$(shield) Fix this](command:aegis.fixFinding?${fixArgs}) | ` +
      `[$(comment-discussion) Ask agent](command:aegis.openChat?${chatArgs}) | ` +
      `[$(eye-closed) Mark false positive](command:aegis.markFalsePositive?${ignoreArgs})`
    );

    return new vscode.Hover(md);
  }
}
