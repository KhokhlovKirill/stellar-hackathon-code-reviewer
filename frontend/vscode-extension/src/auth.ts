import * as vscode from "vscode";

const TOKEN_KEY = "aegis.auth.token";

export async function saveToken(
  ctx: vscode.ExtensionContext,
  token: string
): Promise<void> {
  await ctx.secrets.store(TOKEN_KEY, token);
}

export async function getToken(
  ctx: vscode.ExtensionContext
): Promise<string | undefined> {
  return ctx.secrets.get(TOKEN_KEY);
}

export async function clearToken(
  ctx: vscode.ExtensionContext
): Promise<void> {
  await ctx.secrets.delete(TOKEN_KEY);
}

export async function isAuthenticated(
  ctx: vscode.ExtensionContext
): Promise<boolean> {
  const token = await getToken(ctx);
  return !!token && token.length > 0;
}
