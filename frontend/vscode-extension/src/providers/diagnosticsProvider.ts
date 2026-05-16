import * as vscode from "vscode";
import type { Finding, ScanResult, SeverityLevel } from "../types";
import { SEVERITY_ORDER } from "../types";

function severityToDiagnostic(
  severity: SeverityLevel
): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function cweMitrUrl(cwe: string): vscode.Uri {
  const num = cwe.replace(/^CWE-/i, "");
  return vscode.Uri.parse(
    `https://cwe.mitre.org/data/definitions/${num}.html`
  );
}

export class DiagnosticsProvider {
  private collection: vscode.DiagnosticCollection;

  // Map fingerprint → Finding for hover/codelens lookups
  private findingsByFile = new Map<string, Finding[]>();

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("aegis");
  }

  loadFindingsForScan(
    scanResult: ScanResult,
    severityGate: SeverityLevel = "medium"
  ): void {
    this.collection.clear();
    this.findingsByFile.clear();

    const gateRank = SEVERITY_ORDER[severityGate];

    // Group by file
    const byFile = new Map<string, Finding[]>();
    for (const finding of scanResult.findings) {
      if (SEVERITY_ORDER[finding.severity] > gateRank) continue;

      // Normalize file path — try to find in workspace
      const filePath = this._resolveFilePath(finding.file);
      if (!byFile.has(filePath)) {
        byFile.set(filePath, []);
      }
      byFile.get(filePath)!.push(finding);
    }

    // Set diagnostics per file
    for (const [filePath, findings] of byFile.entries()) {
      this.findingsByFile.set(filePath, findings);

      const diagnostics: vscode.Diagnostic[] = findings.map((f) => {
        const line = Math.max(0, f.line - 1);
        const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);

        const severity = severityToDiagnostic(f.severity);
        const message = `[Aegis] ${f.title}\n${f.rationale.slice(0, 200)}`;

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = "Aegis Security";

        const codeValue = f.cwe ?? f.rule_id ?? "aegis";
        if (f.cwe) {
          diagnostic.code = {
            value: codeValue,
            target: cweMitrUrl(f.cwe),
          };
        } else {
          diagnostic.code = codeValue;
        }

        // Store fingerprint in related information for retrieval
        diagnostic.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(
            new vscode.Location(
              vscode.Uri.file(filePath),
              range
            ),
            `fingerprint:${f.fingerprint}`
          ),
        ];

        return diagnostic;
      });

      const uri = vscode.Uri.file(filePath);
      this.collection.set(uri, diagnostics);
    }
  }

  clearAll(): void {
    this.collection.clear();
    this.findingsByFile.clear();
  }

  removeFinding(fingerprint: string): void {
    for (const [filePath, findings] of this.findingsByFile.entries()) {
      const idx = findings.findIndex((f) => f.fingerprint === fingerprint);
      if (idx !== -1) {
        findings.splice(idx, 1);
        const uri = vscode.Uri.file(filePath);
        const remaining = findings.map((f) => {
          const line = Math.max(0, f.line - 1);
          const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
          return new vscode.Diagnostic(
            range,
            `[Aegis] ${f.title}`,
            severityToDiagnostic(f.severity)
          );
        });
        this.collection.set(uri, remaining);
        if (findings.length === 0) {
          this.findingsByFile.delete(filePath);
        }
        break;
      }
    }
  }

  getFindingsForFile(filePath: string): Finding[] {
    return this.findingsByFile.get(filePath) ?? [];
  }

  getFindingAtLine(filePath: string, line: number): Finding | undefined {
    const findings = this.findingsByFile.get(filePath) ?? [];
    return findings.find((f) => f.line === line + 1);
  }

  getAllFindings(): Finding[] {
    const all: Finding[] = [];
    for (const findings of this.findingsByFile.values()) {
      all.push(...findings);
    }
    return all;
  }

  dispose(): void {
    this.collection.dispose();
  }

  private _resolveFilePath(file: string): string {
    // If it's already absolute, use as-is
    if (file.startsWith("/")) return file;

    // Try to prepend workspace root
    const folders = vscode.workspace.workspaceFolders;
    if (folders && folders.length > 0) {
      const root = folders[0].uri.fsPath;
      return `${root}/${file}`;
    }
    return file;
  }
}
