import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";
import { useSettings } from "../context/SettingsContext";
import {
  splitSegments,
  streamChat,
  type ChatFinding,
  type ChatScan,
  type Segment,
} from "../lib/chatStream";
import { AegisLogo } from "./AegisLogo";

// ── Public types ───────────────────────────────────────────────────────────────
export interface QuickQuestion {
  icon: string;
  label: string;
  question: string;
}

export interface ChatContext {
  finding?: ChatFinding | null;
  scan?: ChatScan | null;
}

export interface ChatHandle {
  /** Imperatively send a message, optionally switching the active context.
   *  Mirrors the VS Code extension's Explain / Fix commands. */
  ask: (text: string, ctx?: ChatContext) => void;
  /** Switch the active finding/scan context without sending — mirrors the
   *  extension's `aegis.openChat(finding)` (Ask Aegis) entry point. */
  focus: (ctx?: ChatContext) => void;
}

interface ChatProps {
  finding?: ChatFinding | null;
  scan?: ChatScan | null;
  repo?: string;
  quickQuestions?: QuickQuestion[];
  title?: string;
  subtitle?: string;
  /** Auto-send this prompt once on mount (e.g. opened from a "Fix" button). */
  autoAsk?: string | null;
  className?: string;
}

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  streaming?: boolean;
}

let _id = 0;
const uid = () => `m${++_id}`;

// ── Lightweight, safe inline markdown (bold / italic / code) ────────────────────
function renderInline(text: string, keyBase: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    const k = `${keyBase}-${i++}`;
    if (tok.startsWith("**")) {
      nodes.push(
        <strong key={k} className="font-semibold">
          {tok.slice(2, -2)}
        </strong>,
      );
    } else if (tok.startsWith("`")) {
      nodes.push(
        <code
          key={k}
          className="px-1 py-0.5 rounded bg-slate-200/70 dark:bg-slate-700/70 text-[0.85em] font-mono"
        >
          {tok.slice(1, -1)}
        </code>,
      );
    } else {
      nodes.push(
        <em key={k} className="italic">
          {tok.slice(1, -1)}
        </em>,
      );
    }
    last = re.lastIndex;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function ProseBlock({ text }: { text: string }) {
  const lines = text.split("\n");
  return (
    <div className="space-y-1.5">
      {lines.map((line, idx) => {
        const key = `l${idx}`;
        if (!line.trim()) return <div key={key} className="h-1.5" />;
        const h = line.match(/^(#{1,4})\s+(.*)$/);
        if (h) {
          return (
            <p
              key={key}
              className="font-bold text-slate-900 dark:text-white mt-2"
            >
              {renderInline(h[2], key)}
            </p>
          );
        }
        const bullet = line.match(/^\s*[-*]\s+(.*)$/);
        if (bullet) {
          return (
            <div key={key} className="flex gap-2 pl-1">
              <span className="text-indigo-400 shrink-0">•</span>
              <span>{renderInline(bullet[1], key)}</span>
            </div>
          );
        }
        const num = line.match(/^\s*(\d+)\.\s+(.*)$/);
        if (num) {
          return (
            <div key={key} className="flex gap-2 pl-1">
              <span className="text-indigo-400 shrink-0 font-medium">
                {num[1]}.
              </span>
              <span>{renderInline(num[2], key)}</span>
            </div>
          );
        }
        return <p key={key}>{renderInline(line, key)}</p>;
      })}
    </div>
  );
}

function DiffViewer({ patch }: { patch: string }) {
  const { t } = useSettings();
  const [copied, setCopied] = useState(false);
  const [hidden, setHidden] = useState(false);
  if (hidden) return null;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(patch);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard unavailable */
    }
  };
  const download = () => {
    const blob = new Blob([patch.endsWith("\n") ? patch : `${patch}\n`], {
      type: "text/x-patch",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "aegis-fix.patch";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="my-2 rounded-xl border border-slate-300 dark:border-slate-700 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-slate-100 dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
        <span className="text-xs font-semibold text-slate-600 dark:text-slate-300">
          {t("chat.proposedPatch")}
        </span>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => void copy()}
            className="text-xs px-2 py-1 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-colors"
          >
            {copied ? t("chat.copied") : t("chat.copy")}
          </button>
          <button
            type="button"
            onClick={download}
            className="text-xs px-2 py-1 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
          >
            {t("chat.download")}
          </button>
          <button
            type="button"
            onClick={() => setHidden(true)}
            className="text-xs px-2 py-1 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors"
          >
            {t("chat.dismiss")}
          </button>
        </div>
      </div>
      <pre className="overflow-x-auto text-xs leading-relaxed font-mono bg-slate-950 text-slate-200 p-3">
        {patch.split("\n").map((ln, i) => {
          let cls = "text-slate-300";
          if (ln.startsWith("+") && !ln.startsWith("+++")) cls = "text-emerald-400";
          else if (ln.startsWith("-") && !ln.startsWith("---"))
            cls = "text-red-400";
          else if (
            ln.startsWith("@@") ||
            ln.startsWith("diff ") ||
            ln.startsWith("--- ") ||
            ln.startsWith("+++ ")
          )
            cls = "text-indigo-400";
          return (
            <div key={`d${i}`} className={cls}>
              {ln || " "}
            </div>
          );
        })}
      </pre>
    </div>
  );
}

function MessageBody({ segments }: { segments: Segment[] }) {
  return (
    <>
      {segments.map((s, i) => {
        if (s.kind === "diff") return <DiffViewer key={`s${i}`} patch={s.content} />;
        if (s.kind === "code") {
          return (
            <pre
              key={`s${i}`}
              className="my-2 overflow-x-auto text-xs leading-relaxed font-mono bg-slate-950 text-slate-200 p-3 rounded-xl border border-slate-700"
            >
              {s.content}
            </pre>
          );
        }
        return <ProseBlock key={`s${i}`} text={s.content} />;
      })}
    </>
  );
}

// ── Component ──────────────────────────────────────────────────────────────────
export const Chat = forwardRef<ChatHandle, ChatProps>(function Chat(
  {
    finding = null,
    scan = null,
    repo = "",
    quickQuestions,
    title = "Aegis AI",
    subtitle,
    autoAsk = null,
    className = "",
  },
  ref,
) {
  const { lang, t } = useSettings();

  const makeWelcome = useCallback(
    (): Message => ({
      id: "welcome",
      role: "assistant",
      content: subtitle ?? t("chat.welcome"),
    }),
    [subtitle, t],
  );

  const [messages, setMessages] = useState<Message[]>([makeWelcome()]);
  const [input, setInput] = useState("");
  const [pending, setPending] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  // Active structured context (props by default, overridable via ask()).
  const ctxRef = useRef<ChatContext>({ finding, scan });
  ctxRef.current = { finding, scan };

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, pending]);

  const send = useCallback(
    async (text: string, override?: ChatContext) => {
      const trimmed = text.trim();
      if (!trimmed || pending) return;
      if (override) ctxRef.current = { finding, scan, ...override };
      setInput("");

      const history = messages
        .filter((m) => m.id !== "welcome")
        .map((m) => ({ role: m.role, content: m.content }));

      const userMsg: Message = { id: uid(), role: "user", content: trimmed };
      const assistantId = uid();
      setMessages((prev) => [
        ...prev,
        userMsg,
        { id: assistantId, role: "assistant", content: "", streaming: true },
      ]);
      setPending(true);

      const ctrl = new AbortController();
      abortRef.current = ctrl;
      try {
        let acc = "";
        for await (const tok of streamChat({
          message: trimmed,
          lang,
          finding: ctxRef.current.finding ?? null,
          scan: ctxRef.current.scan ?? null,
          repo,
          history,
          signal: ctrl.signal,
        })) {
          acc += tok;
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantId ? { ...m, content: acc } : m,
            ),
          );
        }
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantId
              ? { ...m, content: acc || t("chat.retry"), streaming: false }
              : m,
          ),
        );
      } catch (err) {
        const aborted = err instanceof Error && err.name === "AbortError";
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantId
              ? {
                  ...m,
                  content: m.content || (aborted ? "—" : t("chat.retry")),
                  streaming: false,
                }
              : m,
          ),
        );
      } finally {
        setPending(false);
        abortRef.current = null;
      }
    },
    [pending, messages, lang, finding, scan, repo, t],
  );

  useImperativeHandle(
    ref,
    () => ({
      ask: (text: string, ctx?: ChatContext) => void send(text, ctx),
      focus: (ctx?: ChatContext) => {
        if (ctx) ctxRef.current = { finding, scan, ...ctx };
        bottomRef.current?.scrollIntoView({ behavior: "smooth" });
      },
    }),
    [send, finding, scan],
  );

  // Auto-send the opening prompt once (e.g. opened from a Fix/Explain button).
  const autoFired = useRef(false);
  useEffect(() => {
    if (autoAsk && !autoFired.current) {
      autoFired.current = true;
      void send(autoAsk);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoAsk]);

  const stop = () => abortRef.current?.abort();
  const reset = () => {
    abortRef.current?.abort();
    setMessages([makeWelcome()]);
  };

  const showQuick =
    messages.length <= 1 && quickQuestions && quickQuestions.length > 0;

  return (
    <div
      className={`flex flex-col bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden ${className}`}
    >
      {/* Header */}
      <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-100 dark:border-slate-800 bg-gradient-to-r from-indigo-50 to-violet-50 dark:from-indigo-500/5 dark:to-violet-500/5 shrink-0">
        <div className="flex items-center justify-center w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-600 to-violet-600 shadow-md shadow-indigo-500/25">
          <AegisLogo size={18} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="font-semibold text-slate-900 dark:text-white text-sm">
            {title}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-500 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" />
            {t("chat.assistant")}
          </p>
        </div>
        {messages.length > 1 && (
          <button
            type="button"
            onClick={reset}
            className="shrink-0 text-xs text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 transition-colors px-2 py-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            {t("chat.clear")}
          </button>
        )}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-5 space-y-4 min-h-0">
        {messages.map((m) => (
          <div
            key={m.id}
            className={`flex gap-2.5 ${m.role === "user" ? "flex-row-reverse" : ""}`}
          >
            {m.role === "assistant" && (
              <div className="shrink-0 flex items-center justify-center w-7 h-7 rounded-lg bg-gradient-to-br from-indigo-600 to-violet-600 shadow-sm mt-0.5">
                <AegisLogo size={13} />
              </div>
            )}
            <div
              className={`max-w-[82%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${
                m.role === "user"
                  ? "bg-gradient-to-br from-indigo-600 to-violet-600 text-white rounded-tr-sm whitespace-pre-wrap"
                  : "bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-tl-sm border border-slate-200 dark:border-slate-700"
              }`}
            >
              {m.role === "assistant" ? (
                <>
                  <MessageBody segments={splitSegments(m.content)} />
                  {m.streaming && (
                    <span className="inline-block w-1.5 h-3.5 ml-0.5 align-middle bg-indigo-400 animate-pulse" />
                  )}
                </>
              ) : (
                m.content
              )}
            </div>
          </div>
        ))}

        {pending && messages[messages.length - 1]?.content === "" && (
          <div className="flex gap-2.5">
            <div className="shrink-0 flex items-center justify-center w-7 h-7 rounded-lg bg-gradient-to-br from-indigo-600 to-violet-600 shadow-sm mt-0.5">
              <AegisLogo size={13} />
            </div>
            <div className="bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl rounded-tl-sm px-4 py-3 flex items-center gap-1.5">
              {[0, 1, 2].map((i) => (
                <div
                  key={i}
                  className="w-2 h-2 rounded-full bg-indigo-400 dark:bg-slate-500 animate-bounce"
                  style={{ animationDelay: `${i * 0.15}s` }}
                />
              ))}
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Quick questions */}
      {showQuick && (
        <div className="px-5 pb-4 flex flex-wrap gap-2 shrink-0">
          {quickQuestions!.map((q) => (
            <button
              key={q.question}
              type="button"
              onClick={() => void send(q.question)}
              className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 text-slate-600 dark:text-slate-300 hover:border-indigo-300 dark:hover:border-indigo-500/60 hover:bg-indigo-50 dark:hover:bg-indigo-500/10 hover:text-indigo-700 dark:hover:text-indigo-300 transition-all font-medium"
            >
              <span>{q.icon}</span>
              <span>{q.label}</span>
            </button>
          ))}
        </div>
      )}

      {/* Input */}
      <div className="border-t border-slate-100 dark:border-slate-800 p-4 shrink-0">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void send(input);
          }}
          className="flex gap-2"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={t("chat.placeholder")}
            disabled={pending}
            className="flex-1 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/70 focus:border-indigo-500/50 transition-all disabled:opacity-50"
          />
          {pending ? (
            <button
              type="button"
              onClick={stop}
              className="px-4 py-2.5 rounded-xl bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200 text-sm font-bold transition-all"
            >
              {t("chat.stop")}
            </button>
          ) : (
            <button
              type="submit"
              disabled={!input.trim()}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-sm font-bold transition-all shadow-md shadow-indigo-500/20 hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-40 disabled:cursor-not-allowed disabled:transform-none"
            >
              →
            </button>
          )}
        </form>
      </div>
    </div>
  );
});
