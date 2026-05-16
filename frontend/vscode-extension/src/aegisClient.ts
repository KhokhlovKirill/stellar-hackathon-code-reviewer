import type {
  ChatMessage,
  Finding,
  PRInfo,
  RepoInfo,
  ScanResult,
  ScanSummary,
} from "./types";

interface LoginResponse {
  access_token: string;
  token_type: string;
}

export interface ChatFinding {
  file: string;
  line: number;
  cwe: string | null;
  severity: string;
  title: string;
  rationale: string;
  exploit: string | null;
  fix: string | null;
}

export interface ChatScan {
  scan_id: string;
  repo: string;
  pr_number: number;
  pr_title: string;
  pr_url: string;
  pr_author: string;
  files_scanned: number;
  degraded: boolean;
  summary: string | null;
  findings: ChatFinding[];
}

interface ChatApiResponse {
  reply: string;
  proposed_patch: string | null;
}

interface ScanDetailResponse {
  scan: ScanSummary;
  findings: Finding[];
}

export class AegisClient {
  private baseUrl: string;
  private token: string | undefined;
  private language: "ru" | "en" = "ru";
  private onUnauthorized: (() => void | Promise<void>) | undefined;

  constructor(
    baseUrl: string,
    token?: string,
    onUnauthorized?: () => void | Promise<void>
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.token = token;
    this.onUnauthorized = onUnauthorized;
  }

  setToken(token: string | undefined): void {
    this.token = token;
  }

  setBaseUrl(baseUrl: string): void {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  setLanguage(language: "ru" | "en"): void {
    this.language = language;
  }

  setUnauthorizedHandler(handler: (() => void | Promise<void>) | undefined): void {
    this.onUnauthorized = handler;
  }

  private defaultHeaders(auth: boolean = false): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (auth && this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    return headers;
  }

  private async fetch<T>(
    method: string,
    path: string,
    body?: unknown,
    auth: boolean = false
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const options: RequestInit = {
      method,
      headers: this.defaultHeaders(auth),
    };
    if (body !== undefined) {
      options.body = JSON.stringify(body);
    }

    let response: Response;
    try {
      response = await fetch(url, options);
    } catch (err) {
      throw new Error(`Network error calling ${url}: ${err}`);
    }

    if (!response.ok) {
      let detail = response.statusText;
      try {
        const errBody = (await response.json()) as { detail?: string };
        detail = errBody.detail ?? detail;
      } catch {
        // ignore
      }
      if (response.status === 401 && auth && this.onUnauthorized) {
        await this.onUnauthorized();
        throw new Error("Authentication expired. Sign in to Aegis again.");
      }
      throw new Error(`Aegis API error ${response.status}: ${detail}`);
    }

    return response.json() as Promise<T>;
  }

  async login(username: string, password: string): Promise<{ access_token: string }> {
    return this.fetch<LoginResponse>("POST", "/api/auth/login", {
      username,
      password,
    });
  }

  async getRepos(): Promise<RepoInfo[]> {
    return this.fetch<RepoInfo[]>("GET", "/api/ext/repos", undefined, true);
  }

  async getRepoPRs(repoId: number): Promise<PRInfo[]> {
    return this.fetch<PRInfo[]>(
      "GET",
      `/api/ext/repos/${repoId}/prs`,
      undefined,
      true
    );
  }

  async getRepoScans(repoId: number): Promise<ScanSummary[]> {
    return this.fetch<ScanSummary[]>(
      "GET",
      `/api/ext/repos/${repoId}/scans`,
      undefined,
      true
    );
  }

  async getScan(
    scanId: string
  ): Promise<ScanDetailResponse> {
    return this.fetch<ScanDetailResponse>(
      "GET",
      `/api/ext/scans/${scanId}`
    );
  }

  async scanUrl(url: string, token?: string): Promise<ScanResult> {
    return this.fetch<ScanResult>("POST", "/api/ext/scan/url", {
      url,
      token: token ?? null,
      lang: this.language,
    });
  }

  async scanPR(repoId: number, prNumber: number): Promise<ScanResult> {
    return this.fetch<ScanResult>(
      "POST",
      "/api/ext/scan/pr",
      { repo_id: repoId, pr_number: prNumber, lang: this.language },
      true
    );
  }

  async scanBranch(
    diff: string,
    repoSlug: string,
    ref: string
  ): Promise<ScanResult> {
    return this.fetch<ScanResult>("POST", "/api/ext/scan/branch", {
      diff,
      repo_slug: repoSlug,
      ref,
      lang: this.language,
    });
  }

  async chat(
    finding: ChatFinding | null,
    scan: ChatScan | null,
    repo: string,
    message: string,
    history: ChatMessage[]
  ): Promise<ChatApiResponse> {
    return this.fetch<ChatApiResponse>("POST", "/api/ext/chat", {
      finding: finding ?? null,
      scan: scan ?? null,
      repo,
      message,
      lang: this.language,
      history: history.map((m) => ({ role: m.role, content: m.content })),
    });
  }

  async *streamChat(
    finding: ChatFinding | null,
    scan: ChatScan | null,
    repo: string,
    message: string,
    history: ChatMessage[]
  ): AsyncGenerator<string, void, unknown> {
    const url = `${this.baseUrl}/api/ext/chat/stream`;
    let response: Response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: this.defaultHeaders(),
        body: JSON.stringify({
          finding: finding ?? null,
          scan: scan ?? null,
          repo,
          message,
          lang: this.language,
          history: history.map((m) => ({ role: m.role, content: m.content })),
        }),
      });
    } catch (err) {
      throw new Error(`Network error: ${err}`);
    }

    if (!response.ok) {
      let detail = response.statusText;
      try {
        const b = (await response.json()) as { detail?: string };
        detail = b.detail ?? detail;
      } catch { /* ignore */ }
      throw new Error(`Aegis API ${response.status}: ${detail}`);
    }

    if (!response.body) {
      throw new Error("No response body for streaming");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const data = line.slice(6).trim();
          if (data === "[DONE]") return;
          try {
            const obj = JSON.parse(data) as { token?: string; error?: string };
            if (obj.error) throw new Error(obj.error);
            if (obj.token) yield obj.token;
          } catch (e) {
            if (e instanceof Error && e.name !== "SyntaxError") throw e;
          }
        }
      }
    } finally {
      reader.cancel().catch(() => {});
    }
  }

  async markFalsePositive(
    scanId: string,
    fingerprint: string
  ): Promise<void> {
    await this.fetch("POST", "/api/ext/feedback", {
      scan_id: scanId,
      fingerprint,
      kind: "false_positive",
    });
  }

  async ping(): Promise<boolean> {
    try {
      const url = `${this.baseUrl}/healthz`;
      const response = await fetch(url, {
        method: "GET",
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }
}
