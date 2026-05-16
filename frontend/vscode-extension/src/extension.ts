import * as vscode from "vscode";
import { AegisClient } from "./aegisClient";
import { getToken, saveToken, isAuthenticated, clearToken } from "./auth";
import {
  getBackendUrl,
  getLanguage,
  getSeverityGate,
  getAutoScanOnBranchChange,
  getAutoScanOnSave,
  onConfigChange,
} from "./config";
import { DiagnosticsProvider } from "./providers/diagnosticsProvider";
import { PRTreeProvider } from "./providers/prTreeProvider";
import { FindingsTreeProvider } from "./providers/findingsTreeProvider";
import { AegisCodeLensProvider } from "./providers/codeLensProvider";
import { AegisHoverProvider } from "./providers/hoverProvider";
import { PanelManager } from "./views/panelManager";
import { GitProvider } from "./git/gitProvider";
import { registerAllCommands } from "./commands/index";
import type { ScanResult } from "./types";

// ---------------------------------------------------------------------------
// Extension state
// ---------------------------------------------------------------------------

let client: AegisClient;
let currentScan: { value: ScanResult | null } = { value: null };
let statusBar: vscode.StatusBarItem;
let autoRefreshTimer: ReturnType<typeof setInterval> | null = null;
let lastBranch: string | null = null;

export async function activate(
  context: vscode.ExtensionContext
): Promise<void> {
  // --- 0. URI handler (vscode://aegis.aegis-security/auth?token=...) ---
  // Receives the token after browser-based login and wires everything up.
  context.subscriptions.push(
    vscode.window.registerUriHandler({
      async handleUri(uri: vscode.Uri): Promise<void> {
        if (uri.path !== "/auth") return;
        const params = new URLSearchParams(uri.query);
        const token = params.get("token");
        const username = params.get("username") ?? "user";
        if (!token) return;

        await saveToken(context, token);
        client.setBaseUrl(getBackendUrl());
        client.setToken(token);
        client.setLanguage(getLanguage());

        await vscode.commands.executeCommand(
          "setContext",
          "aegis.isAuthenticated",
          true
        );
        statusBar.text = "$(shield) Aegis: Signed in";

        // Load repos immediately after login
        await prTree.setClient(client);
        prTree.loadData().catch(() => {});

        vscode.window.showInformationMessage(
          `$(shield) Aegis: Signed in as ${username}`
        );
      },
    })
  );

  // --- 1. Initial setup ---
  const token = await getToken(context);
  const initiallyAuthed = !!token;

  // Set context keys immediately so viewsWelcome renders before any async work
  await vscode.commands.executeCommand(
    "setContext", "aegis.isAuthenticated", initiallyAuthed
  );
  await vscode.commands.executeCommand("setContext", "aegis.repoCount", 0);

  client = new AegisClient(getBackendUrl(), token);
  client.setLanguage(getLanguage());

  const git = new GitProvider();
  const diagnostics = new DiagnosticsProvider();
  const codeLens = new AegisCodeLensProvider(diagnostics);
  const hoverProvider = new AegisHoverProvider(diagnostics);
  const prTree = new PRTreeProvider(client);
  const findingsTree = new FindingsTreeProvider();
  const panelManager = new PanelManager(context);

  client.setUnauthorizedHandler(async () => {
    await clearToken(context);
    client.setToken(undefined);
    prTree.clear();
    await vscode.commands.executeCommand(
      "setContext",
      "aegis.isAuthenticated",
      false
    );
    await vscode.commands.executeCommand("setContext", "aegis.repoCount", 0);
    statusBar.text = "$(shield) Aegis: Sign in";
    statusBar.command = "aegis.login";
    vscode.window.showWarningMessage(
      "Aegis: session expired. Sign in again to continue."
    );
  });

  // Status bar
  statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBar.text = "$(shield) Aegis: Ready";
  statusBar.tooltip = "Aegis Security Review — click to configure";
  statusBar.command = "aegis.configure";
  statusBar.show();
  context.subscriptions.push(statusBar);

  // --- 2. Register providers ---
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider(
      { scheme: "file" },
      codeLens
    )
  );

  context.subscriptions.push(
    vscode.languages.registerHoverProvider(
      { scheme: "file" },
      hoverProvider
    )
  );

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("aegis.prTree", prTree)
  );

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("aegis.findingsTree", findingsTree)
  );

  context.subscriptions.push(diagnostics);

  // --- 3. Register commands ---
  function reinitClient(): AegisClient {
    client.setBaseUrl(getBackendUrl());
    return client;
  }

  const commandDisposables = registerAllCommands({
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
  });

  for (const d of commandDisposables) {
    context.subscriptions.push(d);
  }

  // --- 4. Auto-refresh timer (every 5 minutes) ---
  autoRefreshTimer = setInterval(
    async () => {
      if (await isAuthenticated(context)) {
        await vscode.commands.executeCommand("aegis.refreshPRs");
      }
    },
    5 * 60 * 1000
  );

  context.subscriptions.push({
    dispose: () => {
      if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
      }
    },
  });

  // --- 5. Watch active editor changes → update findings tree ---
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (!editor) return;
      const findings = diagnostics.getFindingsForFile(
        editor.document.uri.fsPath
      );
      if (findings.length > 0 && currentScan.value) {
        findingsTree.loadScanResult(
          {
            ...currentScan.value,
            findings,
          },
          getSeverityGate()
        );
      }
    })
  );

  // --- 6. Set aegis.hasFindingAtCursor context ---
  context.subscriptions.push(
    vscode.window.onDidChangeTextEditorSelection(async (e) => {
      const editor = e.textEditor;
      if (!editor) {
        await vscode.commands.executeCommand(
          "setContext",
          "aegis.hasFindingAtCursor",
          false
        );
        return;
      }
      const line = editor.selection.active.line;
      const finding = diagnostics.getFindingAtLine(
        editor.document.uri.fsPath,
        line
      );
      await vscode.commands.executeCommand(
        "setContext",
        "aegis.hasFindingAtCursor",
        !!finding
      );
    })
  );

  // --- 7. Watch for configuration changes → reinitialize client ---
  context.subscriptions.push(
    onConfigChange(async () => {
      const newToken = await getToken(context);
      client.setBaseUrl(getBackendUrl());
      client.setToken(newToken);
      client.setLanguage(getLanguage());
      prTree.setClient(client);
      // Reload diagnostics with new severity gate if a scan is loaded
      if (currentScan.value) {
        diagnostics.loadFindingsForScan(currentScan.value, getSeverityGate());
        findingsTree.loadScanResult(currentScan.value, getSeverityGate());
        codeLens.refresh();
      }
    })
  );

  // --- 8. Auto-scan on branch change ---
  if (getAutoScanOnBranchChange()) {
    const branchWatcher = setInterval(async () => {
      const branch = await git.getCurrentBranch();
      if (branch && branch !== lastBranch) {
        lastBranch = branch;
        if (lastBranch !== null) {
          // Branch changed — trigger scan
          await vscode.commands.executeCommand("aegis.scanCurrentBranch");
        }
      }
    }, 10_000);

    context.subscriptions.push({
      dispose: () => clearInterval(branchWatcher),
    });
  }

  // --- 9. Auto-scan on save ---
  if (getAutoScanOnSave()) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(async (_doc) => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
          await vscode.commands.executeCommand("aegis.scanCurrentFile");
        }
      })
    );
  }

  // --- 10. Check backend connectivity ---
  const backendReachable = await client.ping();
  if (!backendReachable) {
    statusBar.text = "$(shield) Aegis: Offline";
    statusBar.tooltip = "Backend not reachable. Click to configure.";
    vscode.window.showWarningMessage(
      `Aegis: Cannot reach backend at ${getBackendUrl()}. ` +
        "Configure the backend URL in settings.",
      "Configure"
    ).then((choice) => {
      if (choice === "Configure") {
        vscode.commands.executeCommand("aegis.configure");
      }
    });
  } else {
    statusBar.text = "$(shield) Aegis: Ready";
    const authed = await isAuthenticated(context);
    await vscode.commands.executeCommand(
      "setContext",
      "aegis.isAuthenticated",
      authed
    );
    if (authed) {
      prTree.loadData().catch(() => {});
    } else {
      statusBar.text = "$(shield) Aegis: Sign in";
      statusBar.command = "aegis.login";
    }
  }

  // Track last branch
  lastBranch = await git.getCurrentBranch();
}

export function deactivate(): void {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
}
