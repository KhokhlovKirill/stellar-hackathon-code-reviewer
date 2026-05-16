import * as vscode from "vscode";
import type { Finding, ScanResult, SeverityLevel } from "../types";
import { SEVERITY_ORDER, SEVERITY_ICON } from "../types";

// ---------------------------------------------------------------------------
// Tree node types
// ---------------------------------------------------------------------------

export class SeverityGroupNode extends vscode.TreeItem {
  readonly nodeType = "severityGroup" as const;
  children: FindingTreeItem[] = [];

  constructor(
    public readonly severity: SeverityLevel,
    count: number
  ) {
    super(
      `${severity.toUpperCase()} (${count})`,
      severity === "critical" || severity === "high"
        ? vscode.TreeItemCollapsibleState.Expanded
        : vscode.TreeItemCollapsibleState.Collapsed
    );
    this.iconPath = new vscode.ThemeIcon(SEVERITY_ICON[severity] ?? "circle-outline");
    this.contextValue = "aegisSeverityGroup";
  }
}

export class FindingTreeItem extends vscode.TreeItem {
  readonly nodeType = "finding" as const;

  constructor(public readonly finding: Finding) {
    super(finding.title, vscode.TreeItemCollapsibleState.None);

    const cwePart = finding.cwe ? ` [${finding.cwe}]` : "";
    this.description = `${finding.file}:${finding.line}${cwePart}`;
    this.iconPath = new vscode.ThemeIcon(
      SEVERITY_ICON[finding.severity] ?? "circle-outline"
    );
    this.contextValue = "aegisFinding";
    this.tooltip = new vscode.MarkdownString(
      [
        `**${finding.severity.toUpperCase()}** ${finding.title}`,
        finding.cwe ? `CWE: ${finding.cwe}` : "",
        `File: \`${finding.file}:${finding.line}\``,
        "",
        finding.rationale,
      ]
        .filter((l) => l !== undefined)
        .join("\n\n")
    );

    this.command = {
      command: "vscode.open",
      title: "Go to finding",
      arguments: [
        vscode.Uri.file(finding.file),
        {
          selection: new vscode.Range(
            Math.max(0, finding.line - 1),
            0,
            Math.max(0, finding.line - 1),
            0
          ),
        },
      ],
    };
  }
}

export type FindingsTreeNode = SeverityGroupNode | FindingTreeItem;

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export class FindingsTreeProvider
  implements vscode.TreeDataProvider<FindingsTreeNode>
{
  private _onDidChangeTreeData =
    new vscode.EventEmitter<FindingsTreeNode | undefined | null | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private groups: SeverityGroupNode[] = [];

  loadScanResult(
    scanResult: ScanResult | null,
    severityGate: SeverityLevel = "medium"
  ): void {
    this.groups = [];

    if (!scanResult) {
      this._onDidChangeTreeData.fire();
      return;
    }

    const gateRank = SEVERITY_ORDER[severityGate];
    const filtered = scanResult.findings.filter(
      (f) => SEVERITY_ORDER[f.severity] <= gateRank
    );

    // Group by severity
    const bySeverity = new Map<SeverityLevel, Finding[]>();
    const severityOrder: SeverityLevel[] = [
      "critical",
      "high",
      "medium",
      "low",
      "info",
    ];

    for (const f of filtered) {
      const sev = f.severity as SeverityLevel;
      if (!bySeverity.has(sev)) {
        bySeverity.set(sev, []);
      }
      bySeverity.get(sev)!.push(f);
    }

    for (const sev of severityOrder) {
      const findings = bySeverity.get(sev);
      if (!findings || findings.length === 0) continue;

      const group = new SeverityGroupNode(sev, findings.length);
      group.children = findings.map((f) => new FindingTreeItem(f));
      this.groups.push(group);
    }

    this._onDidChangeTreeData.fire();
  }

  clearAll(): void {
    this.groups = [];
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingsTreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(
    element?: FindingsTreeNode
  ): vscode.ProviderResult<FindingsTreeNode[]> {
    if (!element) {
      if (this.groups.length === 0) {
        return [];
      }
      return this.groups;
    }

    if (element.nodeType === "severityGroup") {
      return element.children;
    }

    return [];
  }
}
