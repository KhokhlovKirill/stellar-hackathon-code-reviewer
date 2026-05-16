export interface Finding {
  fingerprint: string;
  file: string;
  line: number;
  cwe: string | null;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  rationale: string;
  exploit: string | null;
  fix: string | null;
  confidence: number;
  source: string;
  rule_id?: string;
  short_label?: string | null;
}

export interface ScanResult {
  scan_id: string;
  repo: string;
  pr_number: number;
  pr_title: string;
  pr_url: string;
  pr_author: string;
  files_scanned: number;
  degraded: boolean;
  findings: Finding[];
  summary?: string | null;
}

export interface PRInfo {
  pr_number: number;
  title: string;
  author: string;
  url: string;
  head_branch: string;
  base_branch: string;
  created_at: string;
  updated_at: string;
  draft: boolean;
  last_scan?: ScanSummary;
}

export interface ScanSummary {
  id: string;
  pr_id: string;
  status: string;
  risk_score: number;
  risk_label: "info" | "low" | "medium" | "high" | "critical";
  started_at: string;
  finished_at: string | null;
  files_scanned?: number;
  degraded?: boolean;
  summary?: string | null;
}

export interface RepoInfo {
  id: number;
  provider: string;
  slug: string;
  external_id: string;
  status: string;
  project_id: number | null;
  project_name: string;
  policy: {
    severity_gate: string;
    merge_block: string;
    lang: string;
  };
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  proposed_patch?: string;
}

export type SeverityLevel = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_ICON: Record<SeverityLevel, string> = {
  critical: "error",
  high: "warning",
  medium: "info",
  low: "pass",
  info: "pass",
};
