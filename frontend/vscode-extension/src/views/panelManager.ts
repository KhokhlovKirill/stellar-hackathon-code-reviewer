import * as vscode from "vscode";
import type { Finding, ScanResult } from "../types";
import { getChatWebviewContent } from "./chatView";
import { getPRDetailWebviewContent } from "./prDetailView";

interface ChatContext {
  finding?: Finding;
  scanResult?: ScanResult;
  initialMessage?: string;
  lang?: "ru" | "en";
}

export class PanelManager {
  private chatPanel: vscode.WebviewPanel | null = null;
  private prDetailPanel: vscode.WebviewPanel | null = null;

  get activeChatPanel(): vscode.WebviewPanel | null {
    return this.chatPanel;
  }

  constructor(private readonly context: vscode.ExtensionContext) {}

  getOrCreateChatPanel(
    chatContext?: ChatContext,
    onMessage?: (msg: Record<string, unknown>) => void
  ): vscode.WebviewPanel {
    if (this.chatPanel) {
      this.chatPanel.reveal(vscode.ViewColumn.Beside);

      // Update context if provided
      if (chatContext?.finding) {
        this.chatPanel.webview.postMessage({
          type: "setFinding",
          finding: chatContext.finding,
        });
      }
      if (chatContext?.scanResult) {
        this.chatPanel.webview.postMessage({
          type: "setScan",
          scan: chatContext.scanResult,
        });
      }
      if (chatContext?.initialMessage) {
        this.chatPanel.webview.postMessage({
          type: "sendInitial",
          text: chatContext.initialMessage,
        });
      }
      return this.chatPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      "aegisChat",
      "Aegis Security Chat",
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [
          vscode.Uri.joinPath(this.context.extensionUri, "resources"),
        ],
      }
    );

    panel.webview.html = getChatWebviewContent(
      panel.webview,
      this.context.extensionUri,
      chatContext?.finding,
      chatContext?.scanResult,
      chatContext?.initialMessage,
      chatContext?.lang ?? "ru"
    );

    panel.webview.onDidReceiveMessage(
      (msg: Record<string, unknown>) => {
        if (onMessage) {
          onMessage(msg);
        }
      },
      undefined,
      this.context.subscriptions
    );

    panel.onDidDispose(
      () => {
        this.chatPanel = null;
      },
      null,
      this.context.subscriptions
    );

    this.chatPanel = panel;
    return panel;
  }

  getOrCreatePRDetailPanel(
    scanResult: ScanResult,
    onMessage?: (msg: Record<string, unknown>) => void
  ): vscode.WebviewPanel {
    if (this.prDetailPanel) {
      this.prDetailPanel.reveal(vscode.ViewColumn.One);
      this.prDetailPanel.webview.html = getPRDetailWebviewContent(
        this.prDetailPanel.webview,
        this.context.extensionUri,
        scanResult
      );
      return this.prDetailPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      "aegisPRDetail",
      `Aegis: ${scanResult.pr_title || "PR Detail"}`,
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [
          vscode.Uri.joinPath(this.context.extensionUri, "resources"),
        ],
      }
    );

    panel.webview.html = getPRDetailWebviewContent(
      panel.webview,
      this.context.extensionUri,
      scanResult
    );

    panel.webview.onDidReceiveMessage(
      (msg: Record<string, unknown>) => {
        if (onMessage) {
          onMessage(msg);
        }
      },
      undefined,
      this.context.subscriptions
    );

    panel.onDidDispose(
      () => {
        this.prDetailPanel = null;
      },
      null,
      this.context.subscriptions
    );

    this.prDetailPanel = panel;
    return panel;
  }

  updateChatPanel(panel: vscode.WebviewPanel, msg: Record<string, unknown>): void {
    panel.webview.postMessage(msg);
  }

  disposeAll(): void {
    this.chatPanel?.dispose();
    this.prDetailPanel?.dispose();
    this.chatPanel = null;
    this.prDetailPanel = null;
  }
}
