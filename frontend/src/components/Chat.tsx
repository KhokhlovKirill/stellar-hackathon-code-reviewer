import { useEffect, useRef, useState } from "react";
import { getToken } from "../lib/token";
import { AegisLogo } from "./AegisLogo";

// ── Types ──────────────────────────────────────────────────────────────────────
export interface QuickQuestion {
  icon: string;
  label: string;
  question: string;
}

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
}

interface ChatProps {
  /** Stringified context the AI knows about (PR info, findings, etc.) */
  context?: string;
  quickQuestions?: QuickQuestion[];
  title?: string;
  subtitle?: string;
  /** Tailwind classes added to the outer container */
  className?: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────
let _id = 0;
const uid = () => `m${++_id}`;

const WELCOME = (subtitle?: string): Message => ({
  id: "welcome",
  role: "assistant",
  content:
    subtitle ??
    "Привет! Я Aegis AI — ваш помощник по безопасности кода. " +
    "Задайте вопрос об уязвимостях, настройке интеграций или интерпретации результатов сканирования.",
});

async function callChat(
  messages: { role: string; content: string }[],
  context?: string,
): Promise<string> {
  const token = getToken();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch("/api/chat", {
    method: "POST",
    headers,
    body: JSON.stringify({ messages, context }),
  });

  if (res.status === 404 || res.status === 501 || res.status === 405) {
    return (
      "🔧 LLM-бэкенд пока подключается. " +
      "Интерфейс уже готов — скоро Aegis AI начнёт отвечать на ваши вопросы!"
    );
  }
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  const data = (await res.json()) as { reply?: string; message?: string };
  return data.reply ?? data.message ?? "Ответ получен, но формат неизвестен.";
}

// ── Component ──────────────────────────────────────────────────────────────────
export function Chat({
  context,
  quickQuestions,
  title = "Aegis AI",
  subtitle,
  className = "",
}: ChatProps) {
  const welcome = WELCOME(subtitle);
  const [messages, setMessages] = useState<Message[]>([welcome]);
  const [input, setInput] = useState("");
  const [pending, setPending] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, pending]);

  async function send(text: string) {
    const trimmed = text.trim();
    if (!trimmed || pending) return;
    setInput("");

    const userMsg: Message = { id: uid(), role: "user", content: trimmed };
    setMessages((prev) => [...prev, userMsg]);
    setPending(true);

    try {
      const history = messages
        .filter((m) => m.id !== "welcome")
        .map((m) => ({ role: m.role, content: m.content }));
      history.push({ role: "user", content: trimmed });

      const reply = await callChat(history, context);
      setMessages((prev) => [...prev, { id: uid(), role: "assistant", content: reply }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { id: uid(), role: "assistant", content: "⚠️ Не удалось получить ответ. Попробуйте ещё раз." },
      ]);
    } finally {
      setPending(false);
    }
  }

  const showQuick = messages.length <= 1 && quickQuestions && quickQuestions.length > 0;

  return (
    <div
      className={`flex flex-col bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden ${className}`}
    >
      {/* ── Header ── */}
      <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-100 dark:border-slate-800 bg-gradient-to-r from-indigo-50 to-violet-50 dark:from-indigo-500/5 dark:to-violet-500/5 shrink-0">
        <div className="flex items-center justify-center w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-600 to-violet-600 shadow-md shadow-indigo-500/25">
          <AegisLogo size={18} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="font-semibold text-slate-900 dark:text-white text-sm">{title}</p>
          <p className="text-xs text-slate-500 dark:text-slate-500 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" />
            AI-ассистент по безопасности
          </p>
        </div>
        {messages.length > 1 && (
          <button
            type="button"
            onClick={() => setMessages([welcome])}
            className="shrink-0 text-xs text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 transition-colors px-2 py-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            Очистить
          </button>
        )}
      </div>

      {/* ── Messages ── */}
      <div className="flex-1 overflow-y-auto p-5 space-y-4 min-h-0">
        {messages.map((m) => (
          <div key={m.id} className={`flex gap-2.5 ${m.role === "user" ? "flex-row-reverse" : ""}`}>
            {m.role === "assistant" && (
              <div className="shrink-0 flex items-center justify-center w-7 h-7 rounded-lg bg-gradient-to-br from-indigo-600 to-violet-600 shadow-sm mt-0.5">
                <AegisLogo size={13} />
              </div>
            )}
            <div
              className={`max-w-[82%] rounded-2xl px-4 py-3 text-sm leading-relaxed whitespace-pre-wrap ${
                m.role === "user"
                  ? "bg-gradient-to-br from-indigo-600 to-violet-600 text-white rounded-tr-sm"
                  : "bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-tl-sm border border-slate-200 dark:border-slate-700"
              }`}
            >
              {m.content}
            </div>
          </div>
        ))}

        {/* Typing indicator */}
        {pending && (
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

      {/* ── Quick questions ── */}
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

      {/* ── Input ── */}
      <div className="border-t border-slate-100 dark:border-slate-800 p-4 shrink-0">
        <form
          onSubmit={(e) => { e.preventDefault(); void send(input); }}
          className="flex gap-2"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Задайте вопрос по безопасности..."
            disabled={pending}
            className="flex-1 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/70 focus:border-indigo-500/50 transition-all disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={pending || !input.trim()}
            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-sm font-bold transition-all shadow-md shadow-indigo-500/20 hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-40 disabled:cursor-not-allowed disabled:transform-none"
          >
            →
          </button>
        </form>
      </div>
    </div>
  );
}
