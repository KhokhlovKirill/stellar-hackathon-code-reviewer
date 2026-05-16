import * as vscode from "vscode";
import type { SeverityLevel } from "./types";

function cfg(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("aegis");
}

export function getBackendUrl(): string {
  return (cfg().get<string>("backendUrl") ?? "https://aegis.khokhlovkirill.ru").replace(/\/$/, "");
}

export function getSeverityGate(): SeverityLevel {
  return (cfg().get<string>("severityGate") ?? "medium") as SeverityLevel;
}

export function getGithubToken(): string {
  return cfg().get<string>("githubToken") ?? "";
}

export function getLanguage(): "ru" | "en" {
  const value = cfg().get<string>("language") ?? "ru";
  return value === "en" ? "en" : "ru";
}

export function getAutoScanOnBranchChange(): boolean {
  return cfg().get<boolean>("autoScanOnBranchChange") ?? false;
}

export function getAutoScanOnSave(): boolean {
  return cfg().get<boolean>("autoScanOnSave") ?? false;
}

export function getShowInlineDecorations(): boolean {
  return cfg().get<boolean>("showInlineDecorations") ?? true;
}

export function onConfigChange(
  handler: () => void
): vscode.Disposable {
  return vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration("aegis")) {
      handler();
    }
  });
}
