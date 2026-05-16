import * as vscode from "vscode";
import type { DiagnosticsProvider } from "./diagnosticsProvider";
import type { Finding } from "../types";

export class AegisCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  constructor(private readonly diagnosticsProvider: DiagnosticsProvider) {}

  refresh(): void {
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(
    document: vscode.TextDocument,
    _token: vscode.CancellationToken
  ): vscode.CodeLens[] {
    const findings = this.diagnosticsProvider.getFindingsForFile(
      document.uri.fsPath
    );

    if (findings.length === 0) return [];

    const lenses: vscode.CodeLens[] = [];

    for (const finding of findings) {
      const line = Math.max(0, finding.line - 1);
      const range = new vscode.Range(line, 0, line, 0);

      lenses.push(
        new vscode.CodeLens(range, {
          title: "$(shield) Fix",
          command: "aegis.fixFinding",
          arguments: [finding],
          tooltip: "Ask Aegis to generate an automated fix for this finding",
        })
      );

      lenses.push(
        new vscode.CodeLens(range, {
          title: "$(comment-discussion) Ask Agent",
          command: "aegis.openChat",
          arguments: [finding],
          tooltip: "Open Aegis chat with this finding as context",
        })
      );

      lenses.push(
        new vscode.CodeLens(range, {
          title: "$(eye-closed) Ignore",
          command: "aegis.markFalsePositive",
          arguments: [finding.fingerprint],
          tooltip: "Mark this finding as a false positive",
        })
      );
    }

    return lenses;
  }

  resolveCodeLens(
    codeLens: vscode.CodeLens,
    _token: vscode.CancellationToken
  ): vscode.CodeLens {
    return codeLens;
  }
}
