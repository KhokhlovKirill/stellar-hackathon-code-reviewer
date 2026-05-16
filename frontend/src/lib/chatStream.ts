import { getToken } from "./token";
import type { Lang } from "../context/SettingsContext";

// ── Wire types — must match backend aegis.api.extension ChatFinding / ChatScan ──
export interface ChatFinding {
  file: string;
  line: number;
  cwe?: string | null;
  severity: string;
  title: string;
  rationale: string;
  exploit?: string | null;
  fix?: string | null;
}

export interface ChatScan {
  scan_id?: string;
  repo?: string;
  pr_number?: number;
  pr_title?: string;
  pr_url?: string;
  pr_author?: string;
  files_scanned?: number;
  degraded?: boolean;
  summary?: string | null;
  findings?: ChatFinding[];
}

export interface ChatHistoryItem {
  role: "user" | "assistant";
  content: string;
}

export interface StreamChatOptions {
  message: string;
  lang: Lang;
  finding?: ChatFinding | null;
  scan?: ChatScan | null;
  repo?: string;
  history?: ChatHistoryItem[];
  signal?: AbortSignal;
}

/**
 * Stream a chat completion token-by-token from the SAME endpoint and with the
 * SAME structured payload the VS Code extension uses (`/api/ext/chat/stream`),
 * so web and extension behave identically. Yields decoded token deltas.
 */
export async function* streamChat(
  opts: StreamChatOptions,
): AsyncGenerator<string, void, unknown> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch("/api/ext/chat/stream", {
    method: "POST",
    headers,
    body: JSON.stringify({
      message: opts.message,
      lang: opts.lang,
      finding: opts.finding ?? null,
      scan: opts.scan ?? null,
      repo: opts.repo ?? "",
      history: opts.history ?? [],
    }),
    signal: opts.signal,
  });

  if (!res.ok || !res.body) {
    throw new Error(`HTTP ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // SSE frames are separated by a blank line.
    let sep: number;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);

      for (const raw of frame.split("\n")) {
        const line = raw.trimStart();
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim();
        if (data === "[DONE]") return;
        if (!data) continue;
        try {
          const parsed = JSON.parse(data) as {
            token?: string;
            error?: string;
          };
          if (parsed.error) throw new Error(parsed.error);
          if (typeof parsed.token === "string") yield parsed.token;
        } catch (err) {
          // A genuine backend error frame must propagate; malformed SSE
          // noise is ignored (mirrors the extension's resilient parser).
          if (err instanceof Error && err.message && data.includes('"error"')) {
            throw err;
          }
        }
      }
    }
  }
}

// ── Markdown segmentation: split assistant text into prose + fenced blocks ──────
export interface Segment {
  kind: "text" | "diff" | "code";
  content: string;
  lang?: string;
}

const FENCE_RE = /```(\w*)\s*\n([\s\S]*?)```/g;

/** Split a message into prose / diff / code segments for rich rendering. */
export function splitSegments(text: string): Segment[] {
  const segments: Segment[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  FENCE_RE.lastIndex = 0;
  while ((m = FENCE_RE.exec(text)) !== null) {
    if (m.index > last) {
      segments.push({ kind: "text", content: text.slice(last, m.index) });
    }
    const lang = (m[1] || "").toLowerCase();
    const body = m[2].replace(/\n$/, "");
    segments.push({
      kind: lang === "diff" || lang === "patch" ? "diff" : "code",
      content: body,
      lang,
    });
    last = FENCE_RE.lastIndex;
  }
  if (last < text.length) {
    segments.push({ kind: "text", content: text.slice(last) });
  }
  return segments;
}

/** Extract the first proposed diff/patch block, if any. */
export function extractPatch(text: string): string | null {
  for (const s of splitSegments(text)) {
    if (s.kind === "diff") return s.content;
  }
  return null;
}
