import * as vscode from "vscode";
import type { AegisClient, ChatFinding, ChatScan } from "../aegisClient";
import { saveToken } from "../auth";
import { getBackendUrl, getGithubToken, getLanguage } from "../config";
import type { DiagnosticsProvider } from "../providers/diagnosticsProvider";
import type { PRTreeProvider } from "../providers/prTreeProvider";
import type { FindingsTreeProvider } from "../providers/findingsTreeProvider";
import type { PanelManager } from "../views/panelManager";
import type { GitProvider } from "../git/gitProvider";
import { PatchTargetNotFoundError } from "../git/gitProvider";
import * as fs from "fs";
import type { AegisCodeLensProvider } from "../providers/codeLensProvider";
import type { Finding, ScanResult } from "../types";
import { getSeverityGate } from "../config";
import type { PRNode, ScanNode } from "../providers/prTreeProvider";
// PRNode imported for aegis.scanPR and aegis.openPRDetail argument typing

interface CommandDeps {
  context: vscode.ExtensionContext;
  client: AegisClient;
  diagnostics: DiagnosticsProvider;
  prTree: PRTreeProvider;
  findingsTree: FindingsTreeProvider;
  panelManager: PanelManager;
  git: GitProvider;
  codeLens: AegisCodeLensProvider;
  statusBar: vscode.StatusBarItem;
  currentScan: { value: ScanResult | null };
  reinitClient: () => AegisClient;
}

function setStatus(statusBar: vscode.StatusBarItem, text: string): void {
  statusBar.text = `$(shield) ${text}`;
}

function filterFindingsBySeverity(findings: Finding[]): Finding[] {
  const gate = getSeverityGate();
  const gateOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  const gateRank = gateOrder[gate] ?? 4;
  return findings.filter((f) => (gateOrder[f.severity] ?? 4) <= gateRank);
}

function toChatFinding(finding: Finding): ChatFinding {
  return {
    file: finding.file,
    line: finding.line,
    cwe: finding.cwe ?? null,
    severity: finding.severity,
    title: finding.title,
    rationale: finding.rationale,
    exploit: finding.exploit ?? null,
    fix: finding.fix ?? null,
  };
}

function toChatScan(scan: ScanResult | null | undefined): ChatScan | null {
  if (!scan) return null;
  return {
    scan_id: scan.scan_id,
    repo: scan.repo,
    pr_number: scan.pr_number,
    pr_title: scan.pr_title,
    pr_url: scan.pr_url,
    pr_author: scan.pr_author,
    files_scanned: scan.files_scanned,
    degraded: scan.degraded,
    summary: scan.summary ?? null,
    findings: scan.findings.map(toChatFinding),
  };
}

export function registerAllCommands(deps: CommandDeps): vscode.Disposable[] {
  const {
    context,
    client,
    diagnostics,
    prTree,
    findingsTree,
    panelManager,
    git,
    codeLens,
    statusBar,
    currentScan,
    reinitClient,
  } = deps;

  const disposables: vscode.Disposable[] = [];

  // ---------------------------------------------------------------------------
  // aegis.login — opens browser to web login page, token arrives via URI handler
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand("aegis.login", async () => {
      // Auto-detect backend: try configured URL, fall back to localhost:8080
      let backendUrl = getBackendUrl();

      const reachable = await client.ping().catch(() => false);
      if (!reachable) {
        // Ask once — only if the configured backend is unreachable
        const entered = await vscode.window.showInputBox({
          prompt: "Aegis backend URL",
          value: backendUrl,
          placeHolder: "https://aegis.khokhlovkirill.ru",
          ignoreFocusOut: true,
        });
        if (!entered) return;
        backendUrl = entered.trim().replace(/\/$/, "");
        await vscode.workspace
          .getConfiguration("aegis")
          .update("backendUrl", backendUrl, vscode.ConfigurationTarget.Global);
      }

      const loginUrl = `${backendUrl}/api/ext/auth/vscode-login`;
      await vscode.env.openExternal(vscode.Uri.parse(loginUrl));

      // The URI handler (extension.ts) will receive the token automatically
      // after the user signs in and the browser redirects to vscode://...
    })
  );

  // ---------------------------------------------------------------------------
  // aegis.configure
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand("aegis.configure", async () => {
      const choice = await vscode.window.showQuickPick(
        [
          { label: "$(settings-gear) Open Settings UI", id: "settings" },
          { label: "$(key) Login / Update token", id: "login" },
          { label: "$(link) Change backend URL", id: "url" },
          { label: "$(filter) Change severity gate", id: "severity" },
          { label: "$(comment-discussion) Change language", id: "language" },
          { label: "$(sign-out) Logout", id: "logout" },
        ],
        { placeHolder: "Aegis: Configure" }
      );

      if (!choice) return;

      switch (choice.id) {
        case "settings":
          await vscode.commands.executeCommand(
            "workbench.action.openSettings",
            "aegis"
          );
          break;
        case "login":
          await vscode.commands.executeCommand("aegis.login");
          break;
        case "url": {
          const url = await vscode.window.showInputBox({
            prompt: "Backend URL",
            value: getBackendUrl(),
          });
          if (url) {
            await vscode.workspace
              .getConfiguration("aegis")
              .update(
                "backendUrl",
                url,
                vscode.ConfigurationTarget.Global
              );
          }
          break;
        }
        case "severity": {
          const sev = await vscode.window.showQuickPick(
            ["info", "low", "medium", "high", "critical"],
            { placeHolder: "Minimum severity to show" }
          );
          if (sev) {
            await vscode.workspace
              .getConfiguration("aegis")
              .update(
                "severityGate",
                sev,
                vscode.ConfigurationTarget.Global
              );
          }
          break;
        }
        case "language": {
          const lang = await vscode.window.showQuickPick(
            [
              { label: "Русский", id: "ru" },
              { label: "English", id: "en" },
            ],
            { placeHolder: "Language for AI summaries and agent responses" }
          );
          if (lang) {
            await vscode.workspace
              .getConfiguration("aegis")
              .update("language", lang.id, vscode.ConfigurationTarget.Global);
            client.setLanguage(lang.id as "ru" | "en");
          }
          break;
        }
        case "logout": {
          const { clearToken } = await import("../auth");
          await clearToken(context);
          client.setToken(undefined);
          await vscode.commands.executeCommand(
            "setContext", "aegis.isAuthenticated", false
          );
          setStatus(statusBar, "Sign in");
          vscode.window.showInformationMessage("Aegis: Logged out");
          break;
        }
      }
    })
  );

  // ---------------------------------------------------------------------------
  // aegis.openWebUI
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand("aegis.openWebUI", async () => {
      const url = getBackendUrl();
      await vscode.env.openExternal(vscode.Uri.parse(url));
    })
  );

  // ---------------------------------------------------------------------------
  // aegis.scanURL
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand("aegis.scanURL", async () => {
      const url = await vscode.window.showInputBox({
        prompt: "GitHub PR URL",
        placeHolder: "https://github.com/owner/repo/pull/123",
      });
      if (!url) return;

      let ghToken = getGithubToken();
      if (!ghToken) {
        const entered = await vscode.window.showInputBox({
          prompt: "GitHub Personal Access Token (optional, for private repos)",
          password: true,
          placeHolder: "Leave empty for public repos",
        });
        ghToken = entered ?? "";
      }

      setStatus(statusBar, "Scanning PR...");
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Aegis: Scanning PR...",
          cancellable: false,
        },
        async (progress) => {
          progress.report({ message: "Fetching diff and running analysis..." });
          try {
            const result = await client.scanUrl(url, ghToken || undefined);
            currentScan.value = result;

            diagnostics.loadFindingsForScan(result, getSeverityGate());
            codeLens.refresh();
            findingsTree.loadScanResult(result, getSeverityGate());

            const panel = panelManager.getOrCreatePRDetailPanel(
              result,
              (msg) => handlePRDetailMessage(msg, deps, result)
            );
            panel.title = `Aegis: ${result.pr_title || "PR Detail"}`;

            const criticalCount = result.findings.filter(
              (f) => f.severity === "critical" || f.severity === "high"
            ).length;
            const msg = `Scan complete: ${result.findings.length} findings (${criticalCount} critical/high)`;
            setStatus(statusBar, msg);
            vscode.window.showInformationMessage(`Aegis: ${msg}`);
          } catch (err) {
            setStatus(statusBar, "Scan failed");
            vscode.window.showErrorMessage(`Aegis scan failed: ${err}`);
          }
        }
      );
    })
  );

  // ---------------------------------------------------------------------------
  // aegis.scanCurrentBranch
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand("aegis.scanCurrentBranch", async () => {
      setStatus(statusBar, "Scanning branch...");
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Aegis: Scanning current branch...",
          cancellable: false,
        },
        async (progress) => {
          try {
            const branch = (await git.getCurrentBranch()) ?? "HEAD";
            const remote = await git.getRepoRemoteInfo();
            if (remote && branch !== "HEAD") {
              try {
                const repos = await client.getRepos();
                const connected = repos.find((r) =>
                  r.provider === remote.provider && r.slug.toLowerCase() === remote.slug.toLowerCase()
                );
                if (connected) {
                  const prs = await client.getRepoPRs(connected.id);
                  const currentPr = prs.find((pr) => pr.head_branch === branch);
                  if (currentPr) {
                    progress.report({ message: `Found connected PR/MR #${currentPr.pr_number}; scanning provider diff...` });
                    const result = await client.scanPR(connected.id, currentPr.pr_number);
                    currentScan.value = result;

                    diagnostics.loadFindingsForScan(result, getSeverityGate());
                    codeLens.refresh();
                    findingsTree.loadScanResult(result, getSeverityGate());
                    prTree.loadData().catch(() => {});

                    const panel = panelManager.getOrCreatePRDetailPanel(
                      result,
                      (msg) => handlePRDetailMessage(msg, deps, result)
                    );
                    panel.title = `Aegis: PR #${currentPr.pr_number}`;
                    setStatus(statusBar, `PR scan: ${result.findings.length} findings`);
                    return;
                  }
                }
              } catch {
                // Not signed in or repo not connected; fall back to local diff.
              }
            }

            progress.report({ message: "Getting diff vs main..." });
            const diff = await git.getDiffVsMain();
            if (!diff.trim()) {
              vscode.window.showInformationMessage(
                "Aegis: No changes detected vs main branch"
              );
              setStatus(statusBar, "No changes");
              return;
            }

            const repoSlug = (await git.getRepoSlug()) ?? "local";

            progress.report({ message: "Running security analysis..." });
            const result = await client.scanBranch(diff, repoSlug, branch);
            currentScan.value = result;

            diagnostics.loadFindingsForScan(result, getSeverityGate());
            codeLens.refresh();
            findingsTree.loadScanResult(result, getSeverityGate());

            const panel = panelManager.getOrCreatePRDetailPanel(
              result,
              (msg) => handlePRDetailMessage(msg, deps, result)
            );
            panel.title = `Aegis: ${branch}`;

            const msg = `Branch scan: ${result.findings.length} findings`;
            setStatus(statusBar, msg);
            if (result.findings.length === 0) {
              vscode.window.showInformationMessage("Aegis: Branch looks clean!");
            } else {
              const crit = result.findings.filter(
                (f) => f.severity === "critical" || f.severity === "high"
              ).length;
              vscode.window.showWarningMessage(
                `Aegis: ${result.findings.length} findings (${crit} critical/high)`
              );
            }
          } catch (err) {
            setStatus(statusBar, "Scan failed");
            vscode.window.showErrorMessage(`Aegis branch scan failed: ${err}`);
          }
        }
      );
    })
  );

  // ---------------------------------------------------------------------------
  // aegis.scanCurrentFile
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand("aegis.scanCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showErrorMessage("Aegis: No active file");
        return;
      }

      const filePath = editor.document.uri.fsPath;
      setStatus(statusBar, "Scanning file...");

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Aegis: Scanning current file...",
          cancellable: false,
        },
        async () => {
          try {
            const diff = await git.getDiffCurrentFile(filePath);
            if (!diff.trim()) {
              vscode.window.showInformationMessage(
                "Aegis: No changes in this file"
              );
              setStatus(statusBar, "Ready");
              return;
            }

            const repoSlug = (await git.getRepoSlug()) ?? "local";
            const branch = (await git.getCurrentBranch()) ?? "HEAD";

            const result = await client.scanBranch(diff, repoSlug, branch);

            // Only update diagnostics for this file
            const fileFindingsResult: ScanResult = {
              ...result,
              findings: result.findings.filter((f) =>
                filePath.endsWith(f.file) || f.file.endsWith(filePath)
              ),
            };
            diagnostics.loadFindingsForScan(fileFindingsResult, getSeverityGate());
            codeLens.refresh();

            setStatus(statusBar, `File scan: ${result.findings.length} findings`);
            vscode.window.showInformationMessage(
              `Aegis: ${result.findings.length} findings in this file`
            );
          } catch (err) {
            setStatus(statusBar, "Scan failed");
            vscode.window.showErrorMessage(`Aegis file scan failed: ${err}`);
          }
        }
      );
    })
  );

  // ---------------------------------------------------------------------------
  // aegis.refreshPRs
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand("aegis.refreshPRs", async () => {
      setStatus(statusBar, "Refreshing...");
      try {
        await prTree.loadData();
        setStatus(statusBar, "Ready");
      } catch (err) {
        setStatus(statusBar, "Refresh failed");
        vscode.window.showErrorMessage(`Aegis refresh failed: ${err}`);
      }
    })
  );

  // ---------------------------------------------------------------------------
  // aegis.scanPR — scan a PR node from the sidebar tree
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand(
      "aegis.scanPR",
      async (node: PRNode | undefined) => {
        if (!node) return;

        const label = `#${node.pr.pr_number} ${node.pr.title}`;
        setStatus(statusBar, `Scanning PR ${label}...`);

        await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: `Aegis: Scanning PR ${label}`,
            cancellable: false,
          },
          async (progress) => {
            progress.report({ message: "Fetching diff and running security analysis..." });
            try {
              const result = await client.scanPR(node.repoId, node.pr.pr_number);
              currentScan.value = result;

              diagnostics.loadFindingsForScan(result, getSeverityGate());
              codeLens.refresh();
              findingsTree.loadScanResult(result, getSeverityGate());

              // Refresh PR list so the new scan summary shows up
              prTree.loadData().catch(() => {});

              const panel = panelManager.getOrCreatePRDetailPanel(
                result,
                (msg) => handlePRDetailMessage(msg, deps, result)
              );
              panel.title = `Aegis: PR #${node.pr.pr_number}`;

              const crit = result.findings.filter(
                (f) => f.severity === "critical" || f.severity === "high"
              ).length;
              const summary = `${result.findings.length} findings (${crit} critical/high)`;
              setStatus(statusBar, summary);

              if (result.findings.length === 0) {
                vscode.window.showInformationMessage(
                  `Aegis: PR #${node.pr.pr_number} looks clean — no security findings.`
                );
              } else {
                vscode.window.showWarningMessage(
                  `Aegis: PR #${node.pr.pr_number} — ${summary}`
                );
              }
            } catch (err) {
              setStatus(statusBar, "Scan failed");
              vscode.window.showErrorMessage(`Aegis: PR scan failed: ${err}`);
            }
          }
        );
      }
    )
  );

  // ---------------------------------------------------------------------------
  // aegis.openPRDetail
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand(
      "aegis.openPRDetail",
      async (node: PRNode | ScanNode | undefined) => {
        if (!node) return;

        let scanId: string | undefined;
        if (node.nodeType === "pr") {
          scanId = node.pr.last_scan?.id;
        } else if (node.nodeType === "scan") {
          scanId = node.scan.id;
        }

        if (!scanId) {
          vscode.window.showInformationMessage(
            "Aegis: No scan available for this PR. Scan it first."
          );
          return;
        }

        try {
          const detail = await client.getScan(scanId);
          const scanResult: ScanResult = {
            scan_id: detail.scan.id,
            repo:
              node.nodeType === "pr" ? node.repoSlug : "",
            pr_number: parseInt(detail.scan.pr_id, 10) || 0,
            pr_title: `PR #${detail.scan.pr_id}`,
            pr_url: "",
            pr_author: "",
            files_scanned: detail.scan.files_scanned ?? 0,
            degraded: detail.scan.degraded ?? false,
            findings: detail.findings,
            summary: detail.scan.summary ?? null,
          };

          currentScan.value = scanResult;
          diagnostics.loadFindingsForScan(scanResult, getSeverityGate());
          codeLens.refresh();
          findingsTree.loadScanResult(scanResult, getSeverityGate());

          panelManager.getOrCreatePRDetailPanel(scanResult, (msg) =>
            handlePRDetailMessage(msg, deps, scanResult)
          );
        } catch (err) {
          vscode.window.showErrorMessage(`Aegis: Failed to load scan: ${err}`);
        }
      }
    )
  );

  // ---------------------------------------------------------------------------
  // aegis.openChat
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand(
      "aegis.openChat",
      async (
        findingArg?: Finding,
        scanArg?: ScanResult,
        initialMessage?: string
      ) => {
        const scanContext = scanArg ?? currentScan.value ?? undefined;
        const panel = panelManager.getOrCreateChatPanel(
          { finding: findingArg, scanResult: scanContext },
          (msg) => handleChatMessage(msg, deps, findingArg, scanContext)
        );

        if (findingArg) {
          panel.webview.postMessage({ type: "setFinding", finding: findingArg });
        }
        if (scanContext) {
          panel.webview.postMessage({ type: "setScan", scan: scanContext });
        }
        if (initialMessage) {
          panel.webview.postMessage({ type: "sendInitial", text: initialMessage });
        }
        panel.reveal(vscode.ViewColumn.Beside, false);
      }
    )
  );

  // ---------------------------------------------------------------------------
  // aegis.fixFinding
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand(
      "aegis.fixFinding",
      async (findingArg?: Finding) => {
        if (!findingArg) {
          // Try to get from cursor position
          const editor = vscode.window.activeTextEditor;
          if (!editor) return;
          const line = editor.selection.active.line;
          const finding = diagnostics.getFindingAtLine(
            editor.document.uri.fsPath,
            line
          );
          if (!finding) {
            vscode.window.showInformationMessage(
              "Aegis: No finding at cursor position"
            );
            return;
          }
          findingArg = finding;
        }

        const repoSlug = (await git.getRepoSlug()) ?? "local";

        setStatus(statusBar, "Generating fix...");
        const panel = panelManager.getOrCreateChatPanel(
          { finding: findingArg },
          (msg) => handleChatMessage(msg, deps, findingArg)
        );
        panel.reveal(vscode.ViewColumn.Beside, false);

        const chatFinding = toChatFinding(findingArg);

        panel.webview.postMessage({ type: "streamStart" });

        let fullContent = "";
        try {
          for await (const token of client.streamChat(
            chatFinding,
            toChatScan(currentScan.value),
            repoSlug,
            "Please generate a comprehensive fix for this security finding. Provide the fix as a unified diff.",
            []
          )) {
            fullContent += token;
            panel.webview.postMessage({ type: "streamChunk", token });
          }
        } catch (err) {
          panel.webview.postMessage({ type: "error", message: String(err) });
          setStatus(statusBar, "Fix failed");
          return;
        }

        const patchMatch = fullContent.match(/```(?:diff|patch)\s*\n([\s\S]*?)```/);
        const proposedPatch = patchMatch ? patchMatch[1].trim() : null;
        panel.webview.postMessage({ type: "streamEnd", proposed_patch: proposedPatch });

        if (proposedPatch) {
          const apply = await vscode.window.showInformationMessage(
            "Aegis: Fix generated. Apply patch?",
            "Apply",
            "Review in Chat",
            "Cancel"
          );
          if (apply === "Apply") {
            await applyAndVerify(proposedPatch, findingArg, deps);
          }
        } else {
          vscode.window.showInformationMessage("Aegis: Fix suggestion added to chat panel");
        }

        setStatus(statusBar, "Ready");
      }
    )
  );

  // ---------------------------------------------------------------------------
  // aegis.fixAll
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand("aegis.fixAll", async () => {
      const scan = currentScan.value;
      const allFindings = scan
        ? filterFindingsBySeverity(scan.findings)
        : diagnostics.getAllFindings();

      if (allFindings.length === 0) {
        vscode.window.showInformationMessage("Aegis: No findings to fix");
        return;
      }

      const repoSlug = (await git.getRepoSlug()) ?? "local";
      let fixed = 0;
      let failed = 0;

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Aegis: Auto-fixing findings...",
          cancellable: false,
        },
        async (progress) => {
          for (let i = 0; i < allFindings.length; i++) {
            const finding = allFindings[i];
            progress.report({
              message: `Fixing ${i + 1}/${allFindings.length}: ${finding.title}`,
              increment: (1 / allFindings.length) * 100,
            });

            try {
              const chatFinding = toChatFinding(finding);
              let patch = "";
              let patchContent = "";
              for await (const token of client.streamChat(
                chatFinding, toChatScan(currentScan.value), repoSlug,
                "Please generate a fix for this security finding as a unified diff.", []
              )) { patchContent += token; }
              const m = patchContent.match(/```(?:diff|patch)\s*\n([\s\S]*?)```/);
              patch = m ? m[1].trim() : "";
              if (patch) {
                await git.applyPatch(patch, {
                  hintFiles: finding.file ? [finding.file] : [],
                });
                diagnostics.removeFinding(finding.fingerprint);
                fixed++;
              } else {
                failed++;
              }
            } catch {
              failed++;
            }
          }
        }
      );

      codeLens.refresh();

      // Re-scan to verify
      if (fixed > 0) {
        const rescan = await vscode.window.showInformationMessage(
          `Aegis: Fixed ${fixed} findings, ${failed} could not be auto-fixed. Re-scan to verify?`,
          "Re-scan",
          "Dismiss"
        );
        if (rescan === "Re-scan") {
          await vscode.commands.executeCommand("aegis.scanCurrentBranch");
        }
      } else {
        vscode.window.showWarningMessage(
          `Aegis: Could not auto-fix ${failed} findings. Review in chat panel.`
        );
      }
    })
  );

  // ---------------------------------------------------------------------------
  // aegis.markFalsePositive
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand(
      "aegis.markFalsePositive",
      async (fingerprint?: string) => {
        if (!fingerprint) {
          const editor = vscode.window.activeTextEditor;
          if (!editor) return;
          const line = editor.selection.active.line;
          const finding = diagnostics.getFindingAtLine(
            editor.document.uri.fsPath,
            line
          );
          if (!finding) return;
          fingerprint = finding.fingerprint;
        }

        try {
          const scanId = currentScan.value?.scan_id ?? "";
          if (scanId) {
            await client.markFalsePositive(scanId, fingerprint);
          }
          diagnostics.removeFinding(fingerprint);
          codeLens.refresh();
          vscode.window.showInformationMessage(
            "Aegis: Marked as false positive"
          );
        } catch (err) {
          vscode.window.showErrorMessage(
            `Aegis: Failed to mark false positive: ${err}`
          );
        }
      }
    )
  );

  // ---------------------------------------------------------------------------
  // aegis.hardenBranch
  // ---------------------------------------------------------------------------
  disposables.push(
    vscode.commands.registerCommand("aegis.hardenBranch", async () => {
      setStatus(statusBar, "Hardening branch...");
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Aegis: Hardening branch...",
          cancellable: false,
        },
        async (progress) => {
          try {
            // Step 1: Scan
            progress.report({ message: "Scanning current branch..." });
            const diff = await git.getDiffVsMain();
            if (!diff.trim()) {
              vscode.window.showInformationMessage(
                "Aegis: No changes to harden"
              );
              setStatus(statusBar, "Ready");
              return;
            }

            const repoSlug = (await git.getRepoSlug()) ?? "local";
            const branch = (await git.getCurrentBranch()) ?? "HEAD";
            const result = await client.scanBranch(diff, repoSlug, branch);
            currentScan.value = result;

            const criticalHigh = result.findings.filter(
              (f) => f.severity === "critical" || f.severity === "high"
            );

            if (criticalHigh.length === 0) {
              diagnostics.loadFindingsForScan(result, getSeverityGate());
              codeLens.refresh();
              findingsTree.loadScanResult(result, getSeverityGate());
              setStatus(statusBar, "Branch is clean");
              vscode.window.showInformationMessage(
                "Aegis: Branch has no critical/high findings. Nothing to harden."
              );
              return;
            }

            // Step 2: Fix all critical/high
            progress.report({
              message: `Fixing ${criticalHigh.length} critical/high findings...`,
            });

            let fixed = 0;
            for (const finding of criticalHigh) {
              try {
                const chatFinding = toChatFinding(finding);
                let hardenContent = "";
                for await (const token of client.streamChat(
                  chatFinding, toChatScan(currentScan.value), repoSlug,
                  "Please generate a fix for this security finding as a unified diff.", []
                )) { hardenContent += token; }
                const hm = hardenContent.match(/```(?:diff|patch)\s*\n([\s\S]*?)```/);
                if (hm) {
                  await git.applyPatch(hm[1].trim(), {
                    hintFiles: finding.file ? [finding.file] : [],
                  });
                  fixed++;
                }
              } catch {
                // continue
              }
            }

            // Step 3: Re-scan
            progress.report({ message: "Re-scanning to verify fixes..." });
            const newDiff = await git.getDiffVsMain();
            if (newDiff.trim()) {
              const recheck = await client.scanBranch(
                newDiff,
                repoSlug,
                branch
              );
              currentScan.value = recheck;
              diagnostics.loadFindingsForScan(recheck, getSeverityGate());
              codeLens.refresh();
              findingsTree.loadScanResult(recheck, getSeverityGate());

              const remaining = recheck.findings.filter(
                (f) => f.severity === "critical" || f.severity === "high"
              ).length;

              setStatus(
                statusBar,
                `Harden done: ${fixed} fixed, ${remaining} remaining`
              );
              vscode.window.showInformationMessage(
                `Aegis: Fixed ${fixed}/${criticalHigh.length} critical/high findings. ` +
                  `${remaining} require manual review.\n\n` +
                  `Suggested commit message: "security: apply Aegis autofix recommendations"`
              );
            }
          } catch (err) {
            setStatus(statusBar, "Harden failed");
            vscode.window.showErrorMessage(`Aegis harden failed: ${err}`);
          }
        }
      );
    })
  );

  return disposables;
}

// ---------------------------------------------------------------------------
// Message handlers
// ---------------------------------------------------------------------------

async function handleChatMessage(
  msg: Record<string, unknown>,
  deps: CommandDeps,
  finding?: Finding,
  scan?: ScanResult
): Promise<void> {
  const { client, git, panelManager, currentScan } = deps;

  if (msg.type === "sendMessage") {
    const text = String(msg.text ?? "");
    const findingData = (msg.finding as Finding | null) ?? finding ?? null;
    const scanData = (msg.scan as ScanResult | null) ?? scan ?? currentScan.value ?? null;
    const history = (msg.history as Array<{ role: string; content: string }>) ?? [];
    const repoSlug = (await git.getRepoSlug()) ?? "local";

    const panel = panelManager.activeChatPanel;
    if (!panel) return;

    // Build ChatFinding (null = free-form chat mode)
    const chatFinding: ChatFinding | null = findingData ? toChatFinding(findingData) : null;
    const chatScan = toChatScan(scanData);

    panel.webview.postMessage({ type: "streamStart" });

    let fullContent = "";
    try {
      for await (const token of client.streamChat(
        chatFinding,
        chatScan,
        repoSlug,
        text,
        history.map((h) => ({ role: h.role as "user" | "assistant", content: h.content }))
      )) {
        fullContent += token;
        panel.webview.postMessage({ type: "streamChunk", token });
      }
    } catch (err) {
      panel.webview.postMessage({ type: "error", message: String(err) });
      return;
    }

    // Extract patch from accumulated content
    const patchMatch = fullContent.match(/```(?:diff|patch)\s*\n([\s\S]*?)```/);
    const proposedPatch = patchMatch ? patchMatch[1].trim() : null;
    panel.webview.postMessage({ type: "streamEnd", proposed_patch: proposedPatch });

  } else if (msg.type === "applyPatch") {
    const patch = String(msg.patch ?? "");
    const hintFiles: string[] = [];
    const ctxFinding = (msg.finding as Finding | null) ?? finding ?? null;
    if (ctxFinding?.file) hintFiles.push(ctxFinding.file);
    const ctxScan = (msg.scan as ScanResult | null) ?? scan ?? currentScan.value ?? null;
    for (const f of ctxScan?.findings ?? []) {
      if (f.file && !hintFiles.includes(f.file)) hintFiles.push(f.file);
    }
    try {
      await git.applyPatch(patch, { hintFiles });
      vscode.window.showInformationMessage("Aegis: Patch applied successfully");
      if (currentScan.value) {
        await vscode.commands.executeCommand("aegis.scanCurrentBranch");
      }
    } catch (err) {
      if (err instanceof PatchTargetNotFoundError) {
        const ok = await offerPatchRecovery(git, err, hintFiles);
        if (ok && currentScan.value) {
          await vscode.commands.executeCommand("aegis.scanCurrentBranch");
        }
      } else {
        vscode.window.showErrorMessage(`Aegis: Failed to apply patch: ${err}`);
      }
    }
  }
}

async function handlePRDetailMessage(
  msg: Record<string, unknown>,
  deps: CommandDeps,
  _scanResult: ScanResult
): Promise<void> {
  const { git } = deps;

  switch (msg.type) {
    case "openFile": {
      const file = String(msg.file ?? "");
      const line = (msg.line as number) ?? 1;
      const folders = vscode.workspace.workspaceFolders;
      let uri: vscode.Uri;
      if (file.startsWith("/")) {
        uri = vscode.Uri.file(file);
      } else if (folders && folders.length > 0) {
        uri = vscode.Uri.joinPath(folders[0].uri, file);
      } else {
        return;
      }
      await vscode.window.showTextDocument(uri, {
        selection: new vscode.Range(
          Math.max(0, line - 1),
          0,
          Math.max(0, line - 1),
          0
        ),
      });
      break;
    }
    case "fixFinding": {
      const finding = msg.finding as Finding | undefined;
      if (finding) {
        await vscode.commands.executeCommand("aegis.fixFinding", finding);
      }
      break;
    }
    case "chatFinding": {
      const finding = msg.finding as Finding | undefined;
      if (finding) {
        await vscode.commands.executeCommand("aegis.openChat", finding, _scanResult);
      }
      break;
    }
    case "chatScan": {
      const prompt = String(
        msg.prompt ??
          "Explain the security review for this pull request, prioritize the risks, and suggest the safest remediation plan."
      );
      await vscode.commands.executeCommand("aegis.openChat", undefined, _scanResult, prompt);
      break;
    }
    case "ignoreFinding": {
      const fp = String(msg.fingerprint ?? "");
      if (fp) {
        await vscode.commands.executeCommand("aegis.markFalsePositive", fp);
      }
      break;
    }
    case "fixAll":
      await vscode.commands.executeCommand("aegis.fixAll");
      break;
    case "rescan":
      await vscode.commands.executeCommand("aegis.scanCurrentBranch");
      break;
  }
}

async function applyAndVerify(
  patch: string,
  finding: Finding,
  deps: CommandDeps
): Promise<void> {
  const { git, diagnostics, codeLens, currentScan } = deps;
  const hintFiles = finding.file ? [finding.file] : [];
  try {
    await git.applyPatch(patch, { hintFiles });
    diagnostics.removeFinding(finding.fingerprint);
    codeLens.refresh();
    vscode.window.showInformationMessage(
      "Aegis: Patch applied. Re-scanning to verify..."
    );
    if (currentScan.value) {
      await vscode.commands.executeCommand("aegis.scanCurrentBranch");
    }
  } catch (err) {
    if (err instanceof PatchTargetNotFoundError) {
      const ok = await offerPatchRecovery(git, err, hintFiles);
      if (ok) {
        diagnostics.removeFinding(finding.fingerprint);
        codeLens.refresh();
        if (currentScan.value) {
          await vscode.commands.executeCommand("aegis.scanCurrentBranch");
        }
      }
    } else {
      vscode.window.showErrorMessage(`Aegis: Failed to apply patch: ${err}`);
    }
  }
}

/**
 * Interactive recovery when the patch target isn't in any open workspace
 * folder. Offers: open the correct folder and retry, save the patch to disk,
 * or copy it to the clipboard. Returns true iff the patch was successfully
 * applied to a folder picked by the user.
 */
async function offerPatchRecovery(
  git: GitProvider,
  err: PatchTargetNotFoundError,
  hintFiles: string[]
): Promise<boolean> {
  const target = err.targetPath;
  const choice = await vscode.window.showQuickPick(
    [
      {
        label: "$(folder-opened) Open scanned repository…",
        description: `Pick the folder that contains ${target} and apply there`,
        id: "open",
      },
      {
        label: "$(save) Save patch to file…",
        description: "Write the diff to disk so you can apply it manually",
        id: "save",
      },
      {
        label: "$(clippy) Copy patch to clipboard",
        description: "Paste it into `git apply` in another terminal",
        id: "copy",
      },
    ],
    {
      placeHolder: `Aegis: "${target}" is not in any open workspace folder. What would you like to do?`,
      ignoreFocusOut: true,
    }
  );
  if (!choice) return false;

  if (choice.id === "copy") {
    await vscode.env.clipboard.writeText(err.sanitizedPatch);
    vscode.window.showInformationMessage("Aegis: Patch copied to clipboard.");
    return false;
  }

  if (choice.id === "save") {
    const defaultName = `aegis-fix-${(target.split("/").pop() ?? "patch").replace(/\.[^.]+$/, "")}.patch`;
    const uri = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(defaultName),
      filters: { Patches: ["patch", "diff"], "All files": ["*"] },
      saveLabel: "Save patch",
    });
    if (!uri) return false;
    await fs.promises.writeFile(uri.fsPath, err.sanitizedPatch, "utf8");
    const action = await vscode.window.showInformationMessage(
      `Aegis: Patch saved to ${uri.fsPath}.`,
      "Reveal in Explorer",
      "Open"
    );
    if (action === "Reveal in Explorer") {
      await vscode.commands.executeCommand("revealFileInOS", uri);
    } else if (action === "Open") {
      await vscode.window.showTextDocument(uri);
    }
    return false;
  }

  // "open" — folder picker + retry against the picked root.
  const picked = await vscode.window.showOpenDialog({
    canSelectFolders: true,
    canSelectFiles: false,
    canSelectMany: false,
    openLabel: "Apply patch here",
    title: `Pick the repository containing ${target}`,
  });
  if (!picked || picked.length === 0) return false;
  const rootOverride = picked[0].fsPath;

  try {
    await git.applyPatch(err.sanitizedPatch, { hintFiles, rootOverride });
    const reopen = await vscode.window.showInformationMessage(
      `Aegis: Patch applied in ${rootOverride}.`,
      "Open that folder",
      "Stay here"
    );
    if (reopen === "Open that folder") {
      await vscode.commands.executeCommand(
        "vscode.openFolder",
        vscode.Uri.file(rootOverride),
        { forceNewWindow: false }
      );
    }
    return true;
  } catch (err2) {
    if (err2 instanceof PatchTargetNotFoundError) {
      vscode.window.showErrorMessage(
        `Aegis: ${target} is not in ${rootOverride} either. ` +
          "Make sure you picked the repository that was scanned."
      );
    } else {
      vscode.window.showErrorMessage(
        `Aegis: Failed to apply patch in ${rootOverride}: ${err2 instanceof Error ? err2.message : String(err2)}`
      );
    }
    return false;
  }
}
