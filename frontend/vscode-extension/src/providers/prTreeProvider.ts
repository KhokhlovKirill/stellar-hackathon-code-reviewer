import * as vscode from "vscode";
import type { AegisClient } from "../aegisClient";
import type { PRInfo, RepoInfo, ScanSummary } from "../types";
import { SEVERITY_ICON } from "../types";

// ---------------------------------------------------------------------------
// Tree node types
// ---------------------------------------------------------------------------

export type AegisTreeNode =
  | RepoNode
  | PRNode
  | ScanNode
  | LoadingNode
  | MessageNode;

export class RepoNode extends vscode.TreeItem {
  readonly nodeType = "repo" as const;
  children: PRNode[] = [];

  constructor(
    public readonly repo: RepoInfo,
    prCount: number
  ) {
    super(
      repo.slug,
      prCount > 0
        ? vscode.TreeItemCollapsibleState.Expanded
        : vscode.TreeItemCollapsibleState.Collapsed
    );
    const kind = repo.provider === "gitlab" ? "MR" : "PR";
    this.description = `${repo.project_name} • ${prCount} ${kind}${prCount !== 1 ? "s" : ""}`;
    this.iconPath = new vscode.ThemeIcon("repo");
    this.contextValue = "aegisRepo";
    this.tooltip = `${repo.provider}: ${repo.slug}\nStatus: ${repo.status}`;
  }
}

export class PRNode extends vscode.TreeItem {
  readonly nodeType = "pr" as const;
  children: ScanNode[] = [];

  constructor(
    public readonly pr: PRInfo,
    public readonly repoSlug: string,
    public readonly repoId: number
  ) {
    super(
      `#${pr.pr_number} ${pr.title}`,
      pr.last_scan
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None
    );

    const lastScan = pr.last_scan;
    if (lastScan) {
      const label = lastScan.risk_label as keyof typeof SEVERITY_ICON;
      this.iconPath = new vscode.ThemeIcon(SEVERITY_ICON[label] ?? "circle-outline");
      this.description = `${lastScan.risk_label.toUpperCase()} (score: ${lastScan.risk_score})`;
    } else {
      this.iconPath = new vscode.ThemeIcon("git-pull-request");
      this.description = pr.draft ? "draft" : "no scan";
    }

    this.contextValue = "aegisPR";
    this.tooltip = [
      `${pr.url.includes("/merge_requests/") ? "MR" : "PR"} #${pr.pr_number}: ${pr.title}`,
      `Author: ${pr.author}`,
      `${pr.head_branch} → ${pr.base_branch}`,
      pr.state ? `State: ${pr.state}` : "",
      pr.draft ? "(draft)" : "",
      lastScan ? `Last scan: ${lastScan.risk_label} risk` : "Not scanned",
    ]
      .filter(Boolean)
      .join("\n");

    this.command = {
      command: "aegis.openPRDetail",
      title: "Open PR Detail",
      arguments: [this],
    };
  }
}

export class ScanNode extends vscode.TreeItem {
  readonly nodeType = "scan" as const;

  constructor(public readonly scan: ScanSummary) {
    super(
      `Scan ${new Date(scan.started_at).toLocaleDateString()}`,
      vscode.TreeItemCollapsibleState.None
    );

    const label = scan.risk_label as keyof typeof SEVERITY_ICON;
    this.iconPath = new vscode.ThemeIcon(SEVERITY_ICON[label] ?? "circle-outline");
    this.description = `${scan.risk_label} risk • score ${scan.risk_score}`;
    this.contextValue = "aegisScan";
    this.tooltip = [
      `Scan ID: ${scan.id}`,
      `Status: ${scan.status}`,
      `Risk: ${scan.risk_label} (${scan.risk_score})`,
      `Files scanned: ${scan.files_scanned}`,
      scan.degraded ? "⚠ Degraded mode" : "",
    ]
      .filter(Boolean)
      .join("\n");

    this.command = {
      command: "aegis.openPRDetail",
      title: "Open Scan Detail",
      arguments: [this],
    };
  }
}

export class LoadingNode extends vscode.TreeItem {
  readonly nodeType = "loading" as const;

  constructor(message: string = "Loading...") {
    super(message, vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon("loading~spin");
    this.contextValue = "aegisLoading";
  }
}

export class MessageNode extends vscode.TreeItem {
  readonly nodeType = "message" as const;

  constructor(message: string, icon: string = "info") {
    super(message, vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon(icon);
    this.contextValue = "aegisMessage";
  }
}

// ---------------------------------------------------------------------------
// Tree provider
// ---------------------------------------------------------------------------

export class PRTreeProvider
  implements vscode.TreeDataProvider<AegisTreeNode>
{
  private _onDidChangeTreeData =
    new vscode.EventEmitter<AegisTreeNode | undefined | null | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private repoNodes: RepoNode[] = [];
  private loading = false;
  private errorMessage: string | null = null;

  constructor(private client: AegisClient) {}

  setClient(client: AegisClient): void {
    this.client = client;
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  clear(errorMessage: string | null = null): void {
    this.repoNodes = [];
    this.errorMessage = errorMessage;
    this.loading = false;
    this._onDidChangeTreeData.fire();
  }

  async loadData(): Promise<void> {
    this.loading = true;
    this.errorMessage = null;
    this._onDidChangeTreeData.fire();

    try {
      const repos = await this.client.getRepos();
      const nodes: RepoNode[] = [];

      for (const repo of repos) {
        let prs: PRInfo[] = [];
        try {
          prs = await this.client.getRepoPRs(repo.id);
        } catch {
          // ignore per-repo errors
        }

        const repoNode = new RepoNode(repo, prs.length);
        repoNode.children = prs.map((pr) => {
          const prNode = new PRNode(pr, repo.slug, repo.id);
          if (pr.last_scan) {
            prNode.children = [new ScanNode(pr.last_scan)];
          }
          return prNode;
        });
        nodes.push(repoNode);
      }

      this.repoNodes = nodes;
      this.errorMessage = null;
      await vscode.commands.executeCommand(
        "setContext", "aegis.repoCount", nodes.length
      );
    } catch (err) {
      this.repoNodes = [];
      this.errorMessage = err instanceof Error ? err.message : String(err);
      await vscode.commands.executeCommand(
        "setContext", "aegis.repoCount", 0
      );
    } finally {
      this.loading = false;
      this._onDidChangeTreeData.fire();
    }
  }

  getTreeItem(element: AegisTreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(
    element?: AegisTreeNode
  ): vscode.ProviderResult<AegisTreeNode[]> {
    if (!element) {
      // Root
      if (this.loading) {
        return [new LoadingNode("Loading repositories...")];
      }
      if (this.errorMessage) {
        return [new MessageNode(`Failed to load repositories: ${this.errorMessage}`, "error")];
      }
      if (this.repoNodes.length === 0) {
        return [];
      }
      return this.repoNodes;
    }

    switch (element.nodeType) {
      case "repo":
        return element.children.length > 0
          ? element.children
          : [new MessageNode("No pull/merge requests found", "git-pull-request")];
      case "pr":
        return element.children;
      default:
        return [];
    }
  }
}
