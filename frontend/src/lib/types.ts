export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export interface Project {
  id: number;
  name: string;
  description: string;
  repo_count: number;
  created_at: string;
}

export interface Repo {
  id: number;
  provider: string;
  external_id: string;
  slug: string;
  status: string;
  policy: {
    severity_gate: string;
    merge_block: string;
    ignore_globs: string[];
    ensemble_profile: string;
    lang: string;
  };
}

export interface ScanSummary {
  id: string;
  repo_slug: string;
  pr_id: number;
  status: string;
  risk_score: number;
  risk_label: string;
  started_at: string;
}

export interface ConnectedPR {
  repo_id: number;
  repo_slug: string;
  provider: string;
  pr_number: number;
  title: string;
  author: string;
  url: string;
  head_branch: string;
  base_branch: string;
  state: string;
  created_at: string;
  updated_at: string;
  draft: boolean;
  last_scan?: {
    id: string;
    risk_score: number;
    risk_label: string;
    status: string;
    started_at: string;
  } | null;
}

export interface ProjectDetail {
  project: { id: number; name: string; description: string };
  repos: Repo[];
  scans: ScanSummary[];
  pull_requests: ConnectedPR[];
}

export interface QuickConnectResult {
  repo_id: number;
  slug: string;
  external_id: string;
  webhook_secret: string;
  webhook_url: string;
  github_hook_id: number | null;
  provider?: string;
}

export interface ReviewFinding {
  severity: Severity;
  cwe?: string;
  title: string;
  file: string;
  line?: number;
  rationale?: string;
  fix?: string;
  source: string;
  confidence: number;
  short_label?: string | null;
}

export interface ReviewResult {
  scan_id?: string;
  repo: string;
  pr_number: number;
  pr_title: string;
  pr_url: string;
  pr_author: string;
  files_scanned: number;
  degraded: boolean;
  summary?: string | null;
  findings: ReviewFinding[];
}

export interface ScanDetail {
  id: string;
  repo_slug: string;
  pr_id: number | string;
  status: string;
  risk_score: number;
  risk_label: string;
  summary?: string | null;
  decision?: {
    summary?: string;
    finding_labels?: Record<string, string>;
  };
  files_scanned: string[];
  files_skipped: string[];
  degraded: string[];
}

export interface ScanFinding {
  fingerprint?: string;
  file: string;
  line: number;
  cwe: string | null;
  severity: Severity;
  title: string;
  rationale: string;
  fix: string | null;
  source?: string;
  confidence?: number;
  short_label?: string | null;
}
