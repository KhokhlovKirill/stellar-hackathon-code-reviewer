import { useState } from "react";
import { Link } from "react-router-dom";
import { Alert } from "../components/Alert";
import { PrimaryButton, TextInput, FormField } from "../components/FormField";
import { AegisLogo } from "../components/AegisLogo";
import { useAuth } from "../context/AuthContext";
import { ApiError } from "../lib/api";

function ShieldDecoration() {
  return (
    <svg viewBox="0 0 280 320" fill="none" className="w-52 h-auto mx-auto">
      <circle cx="140" cy="165" r="110" fill="rgba(99,102,241,0.04)" />
      <circle cx="140" cy="165" r="85"  fill="rgba(99,102,241,0.06)" />
      <circle cx="140" cy="165" r="60"  fill="rgba(99,102,241,0.05)" />
      <path d="M140 28L228 66V148C228 208 190 256 140 275C90 256 52 208 52 148V66L140 28Z" fill="url(#sl-fill)" />
      <path d="M140 28L228 66V148C228 208 190 256 140 275C90 256 52 208 52 148V66L140 28Z"
        stroke="rgba(129,140,248,0.4)" strokeWidth="1.5" fill="none" />
      <path d="M140 52L210 85V142C210 194 178 234 140 250C102 234 70 194 70 142V85L140 52Z"
        stroke="rgba(129,140,248,0.12)" strokeWidth="1" fill="none" />
      <path d="M150 87L122 158H143L132 228L164 150H143L157 87Z" fill="url(#sl-bolt)" />
      <circle cx="52"  cy="78"  r="3" fill="rgba(99,102,241,0.35)" />
      <circle cx="228" cy="240" r="3" fill="rgba(99,102,241,0.35)" />
      <line x1="52" y1="78" x2="70" y2="88" stroke="rgba(99,102,241,0.18)" strokeWidth="1" />
      <line x1="228" y1="240" x2="210" y2="230" stroke="rgba(99,102,241,0.18)" strokeWidth="1" />
      <defs>
        <linearGradient id="sl-fill" x1="52" y1="28" x2="228" y2="275" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="rgba(99,102,241,0.22)" />
          <stop offset="100%" stopColor="rgba(124,58,237,0.08)" />
        </linearGradient>
        <linearGradient id="sl-bolt" x1="122" y1="87" x2="164" y2="228" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#a5b4fc" />
          <stop offset="100%" stopColor="#c4b5fd" />
        </linearGradient>
      </defs>
    </svg>
  );
}

const FEATURES = [
  { icon: "🔍", label: "AI-анализ pull request'ов на уязвимости" },
  { icon: "🛡️", label: "SAST + LLM ансамбль для максимальной точности" },
  { icon: "⚡", label: "Автоматические webhook'и для GitHub / GitLab" },
  { icon: "📊", label: "Детальные отчёты с рекомендациями по исправлению" },
];

export function LoginPage() {
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setPending(true);
    const fd = new FormData(e.currentTarget);
    try {
      await login(String(fd.get("email") ?? ""), String(fd.get("password") ?? ""));
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Ошибка входа");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col md:flex-row">
      {/* Left brand panel – always dark */}
      <div className="relative hidden md:flex md:w-[45%] lg:w-1/2 flex-col justify-center items-center p-12 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-indigo-950/90 via-slate-950 to-violet-950/60" />
        <div className="absolute inset-0 opacity-[0.025]"
          style={{ backgroundImage: "radial-gradient(circle at 1px 1px, white 1px, transparent 0)", backgroundSize: "40px 40px" }} />
        <div className="relative z-10 max-w-sm w-full text-center">
          <div className="flex items-center justify-center gap-3 mb-3">
            <AegisLogo size={52} />
            <span className="text-5xl font-black tracking-tighter bg-gradient-to-r from-indigo-300 to-violet-300 bg-clip-text text-transparent">AEGIS</span>
          </div>
          <p className="text-slate-400 text-base mb-10 font-medium">AI-система анализа безопасности кода</p>
          <ShieldDecoration />
          <div className="mt-10 space-y-3 text-left">
            {FEATURES.map((f) => (
              <div key={f.icon} className="flex items-center gap-3 bg-slate-800/30 border border-slate-700/30 rounded-xl px-4 py-3">
                <span className="text-xl">{f.icon}</span>
                <span className="text-sm text-slate-300">{f.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right form panel */}
      <div className="flex flex-1 items-center justify-center px-6 py-12 md:px-12 bg-slate-50 dark:bg-[#020617]">
        <div className="w-full max-w-md">
          <div className="flex md:hidden items-center gap-2.5 mb-10">
            <AegisLogo size={36} />
            <span className="text-2xl font-black tracking-tighter bg-gradient-to-r from-indigo-500 to-violet-500 dark:from-indigo-300 dark:to-violet-300 bg-clip-text text-transparent">AEGIS</span>
          </div>

          <div className="mb-8">
            <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">Добро пожаловать</h1>
            <p className="text-slate-500 dark:text-slate-400">Войдите в свой аккаунт для продолжения</p>
          </div>

          {error && <div className="mb-6"><Alert>{error}</Alert></div>}

          <form onSubmit={onSubmit} className="space-y-5">
            <FormField label="Электронная почта">
              <TextInput name="email" type="email" required autoFocus placeholder="you@example.com" />
            </FormField>
            <FormField label="Пароль">
              <TextInput name="password" type="password" required placeholder="••••••••" />
            </FormField>
            <div className="pt-1">
              <PrimaryButton disabled={pending}>{pending ? "Вход..." : "Войти →"}</PrimaryButton>
            </div>
          </form>

          <div className="mt-6 pt-6 border-t border-slate-200 dark:border-slate-800 text-center">
            <p className="text-slate-500 text-sm">
              Нет аккаунта?{" "}
              <Link to="/register" className="text-indigo-600 dark:text-indigo-400 hover:text-indigo-500 dark:hover:text-indigo-300 font-medium transition-colors">
                Зарегистрироваться
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
