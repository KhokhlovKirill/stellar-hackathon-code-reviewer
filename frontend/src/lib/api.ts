import { clearToken, getToken } from "./token";
import type {
  LoginResponse,
  Project,
  ProjectDetail,
  QuickConnectResult,
  Repo,
  ReviewResult,
  ScanDetail,
  ScanFinding,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly detail?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function parseError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { detail?: string | { msg?: string }[] };
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail) && body.detail[0]?.msg) {
      return body.detail[0].msg;
    }
  } catch {
    /* ignore */
  }
  if (res.status === 502 || res.status === 503) {
    return "Backend unavailable — wait a few seconds and try again, or run: make docker-up";
  }
  return res.statusText || "Request failed";
}

async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    // Always read the backend's real reason first — never discard a 401's
    // detail (e.g. "invalid credentials") behind a generic "Unauthorized",
    // otherwise the UI can't localize it ("Неверный пароль" / etc.).
    const detail = await parseError(res);
    // Only drop a stored token when an *authenticated* request was rejected.
    // A failed login/register has no token to clear and must keep its detail.
    if (res.status === 401 && token) {
      clearToken();
    }
    throw new ApiError(detail, res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  register(email: string, password: string, displayName: string) {
    return apiFetch<LoginResponse>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        email,
        password,
        display_name: displayName,
      }),
    });
  },

  login(username: string, password: string) {
    return apiFetch<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  },

  listProjects() {
    return apiFetch<Project[]>("/api/projects");
  },

  createProject(name: string, description: string) {
    return apiFetch<Project>("/api/projects", {
      method: "POST",
      body: JSON.stringify({ name, description }),
    });
  },

  getProject(projectId: number) {
    return apiFetch<ProjectDetail>(`/api/projects/${projectId}`);
  },

  addRepo(projectId: number, payload: {
    provider: string;
    external_id: string;
    slug: string;
    access_token: string;
    webhook_secret: string;
    severity_gate: string;
    merge_block: string;
  }) {
    return apiFetch<Repo>(`/api/projects/${projectId}/repos`, {
      method: "POST",
      body: JSON.stringify({
        ...payload,
        ignore_globs: [],
        ensemble_profile: "det+don+judge",
        lang: "ru",
      }),
    });
  },

  review(repoUrl: string, token?: string, lang: "ru" | "en" = "ru") {
    return apiFetch<ReviewResult>("/api/review", {
      method: "POST",
      body: JSON.stringify({ repo_url: repoUrl, token: token ?? "", lang }),
    });
  },

  getScan(scanId: string) {
    return apiFetch<{ scan: ScanDetail; findings: ScanFinding[] }>(
      `/api/scans/${scanId}`,
    );
  },

  quickConnect(
    projectId: number,
    payload: {
      repo_url: string;
      access_token: string;
      public_url: string;
      severity_gate: string;
      merge_block: string;
    },
  ) {
    return apiFetch<QuickConnectResult>(
      `/api/projects/${projectId}/repos/quick-connect`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    );
  },

  scanConnectedPR(
    projectId: number,
    repoId: number,
    prNumber: number,
    lang: "ru" | "en" = "ru",
  ) {
    return apiFetch<ReviewResult>(
      `/api/projects/${projectId}/repos/${repoId}/pulls/${prNumber}/scan`,
      {
        method: "POST",
        body: JSON.stringify({ lang }),
      },
    );
  },

  scanConnectedRepo(projectId: number, repoId: number, lang: "ru" | "en" = "ru") {
    return apiFetch<ReviewResult>(
      `/api/projects/${projectId}/repos/${repoId}/scan`,
      {
        method: "POST",
        body: JSON.stringify({ lang }),
      },
    );
  },
};
