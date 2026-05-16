import { useState } from "react";
import { Link } from "react-router-dom";
import { Alert } from "../components/Alert";
import { PrimaryButton, TextInput, FormField } from "../components/FormField";
import { AegisLogo } from "../components/AegisLogo";
import { useAuth } from "../context/AuthContext";
import { ApiError } from "../lib/api";

function SecurityIllustration() {
  return (
    <svg viewBox="0 0 280 240" fill="none" className="w-64 h-auto mx-auto">
      <rect x="20" y="20" width="240" height="200" rx="12" fill="rgba(15,23,42,0.6)" stroke="rgba(99,102,241,0.2)" strokeWidth="1" />
      <rect x="20" y="20" width="240" height="36" rx="12" fill="rgba(99,102,241,0.12)" />
      <circle cx="44" cy="38" r="5" fill="rgba(239,68,68,0.7)" />
      <circle cx="60" cy="38" r="5" fill="rgba(245,158,11,0.7)" />
      <circle cx="76" cy="38" r="5" fill="rgba(34,197,94,0.7)" />
      <text x="110" y="43" fontSize="9" fill="rgba(129,140,248,0.8)" fontFamily="monospace">aegis scan --pr 42</text>
      {[0,1,2,3,4,5,6].map((i) => (
        <rect key={i} x="36" y={72 + i*18} width={[130,90,110,70,140,60,100][i]} height="7" rx="3"
          fill={i === 2 ? "rgba(239,68,68,0.35)" : i === 5 ? "rgba(245,158,11,0.25)" : "rgba(100,116,139,0.2)"} />
      ))}
      <rect x="160" y="97" width="84" height="22" rx="6" fill="rgba(239,68,68,0.15)" stroke="rgba(239,68,68,0.3)" strokeWidth="0.75" />
      <text x="173" y="112" fontSize="8" fill="rgba(252,165,165,0.9)" fontFamily="monospace">⚠ SQL Injection</text>
      <rect x="160" y="133" width="84" height="22" rx="6" fill="rgba(245,158,11,0.12)" stroke="rgba(245,158,11,0.25)" strokeWidth="0.75" />
      <text x="170" y="148" fontSize="8" fill="rgba(253,230,138,0.9)" fontFamily="monospace">↑ Hardcoded key</text>
      <rect x="160" y="175" width="84" height="30" rx="8" fill="rgba(99,102,241,0.12)" stroke="rgba(99,102,241,0.25)" strokeWidth="0.75" />
      <text x="180" y="188" fontSize="7" fill="rgba(165,180,252,0.7)" fontFamily="monospace">Risk Score</text>
      <text x="186" y="200" fontSize="13" fontWeight="bold" fill="#f87171" fontFamily="monospace">78/100</text>
    </svg>
  );
}

const BENEFITS = [
  { icon: "🚀", label: "Настройка за 5 минут с webhook'ом" },
  { icon: "🔒", label: "Нулевые false-positive благодаря Judge LLM" },
  { icon: "📦", label: "Поддержка монорепозиториев и mono-PR" },
  { icon: "🌐", label: "GitHub, GitLab и Bitbucket из коробки" },
];

function isPlausibleEmail(value: string) {
  const email = value.trim().toLowerCase();
  if (email.length < 3 || email.length > 254 || email.split("@").length !== 2) return false;
  const [local, domain] = email.split("@");
  if (!local || !domain || local.length > 64) return false;
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return false;
  if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) return false;
  if (domain.includes("..") || domain.startsWith("[") || domain.endsWith("]")) return false;
  const labels = domain.split(".");
  if (labels.length < 2) return false;
  if (!labels.every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))) return false;
  return /^[A-Za-z]{2,}$/.test(labels[labels.length - 1]);
}

export function RegisterPage() {
  const { register } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setPending(true);
    const fd = new FormData(e.currentTarget);
    const pass    = String(fd.get("password") ?? "");
    const confirm = String(fd.get("confirm") ?? "");
    const email = String(fd.get("email") ?? "").trim().toLowerCase();
    if (!isPlausibleEmail(email)) { setError("Введите действительный email: имя@домен.tld, без недопустимых точек и символов"); setPending(false); return; }
    if (pass !== confirm) { setError("Пароли не совпадают"); setPending(false); return; }
    if (pass.length < 8)  { setError("Пароль должен быть не менее 8 символов"); setPending(false); return; }
    try {
      await register(email, pass, email);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setError("Пользователь с таким email уже существует");
      } else {
        setError(err instanceof ApiError ? (err.detail ?? err.message) : "Ошибка регистрации");
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col md:flex-row">
      {/* Left brand panel */}
      <div className="relative hidden md:flex md:w-[45%] lg:w-1/2 flex-col justify-center items-center p-12 overflow-hidden bg-violet-50 dark:bg-transparent">
        <div className="absolute inset-0 bg-gradient-to-br from-violet-100/80 via-slate-100/60 to-indigo-100/50 dark:from-violet-950/80 dark:via-slate-950 dark:to-indigo-950/70" />
        <div className="absolute inset-0 opacity-[0.04] dark:opacity-[0.025]"
          style={{ backgroundImage: "radial-gradient(circle at 1px 1px, rgb(124,58,237) 1px, transparent 0)", backgroundSize: "40px 40px" }} />
        <div className="relative z-10 max-w-sm w-full text-center">
          <div className="flex items-center justify-center gap-3 mb-3">
            <AegisLogo size={52} />
            <span className="text-5xl font-black tracking-tighter bg-gradient-to-r from-indigo-600 to-violet-600 dark:from-indigo-300 dark:to-violet-300 bg-clip-text text-transparent">AEGIS</span>
          </div>
          <p className="text-slate-500 dark:text-slate-400 text-base mb-10 font-medium">Начните защищать код уже сегодня</p>
          <SecurityIllustration />
          <div className="mt-10 space-y-3 text-left">
            {BENEFITS.map((b) => (
              <div key={b.icon} className="flex items-center gap-3 bg-white/60 dark:bg-slate-800/30 border border-violet-200/60 dark:border-slate-700/30 rounded-xl px-4 py-3">
                <span className="text-xl">{b.icon}</span>
                <span className="text-sm text-slate-600 dark:text-slate-300">{b.label}</span>
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
            <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">Создать аккаунт</h1>
          </div>

          {error && <div className="mb-6"><Alert>{error}</Alert></div>}

          <form onSubmit={onSubmit} className="space-y-5">
            <FormField label="Электронная почта">
              <TextInput name="email" type="email" required autoFocus placeholder="you@example.com" />
            </FormField>
            <FormField label="Пароль" hint="Минимум 8 символов">
              <TextInput name="password" type="password" required placeholder="••••••••" />
            </FormField>
            <FormField label="Подтверждение пароля">
              <TextInput name="confirm" type="password" required placeholder="••••••••" />
            </FormField>
            <div className="pt-1">
              <PrimaryButton disabled={pending}>{pending ? "Создание..." : "Создать аккаунт →"}</PrimaryButton>
            </div>
          </form>

          <div className="mt-6 pt-6 border-t border-slate-200 dark:border-slate-800 text-center">
            <p className="text-slate-500 text-sm">
              Уже есть аккаунт?{" "}
              <Link to="/login" className="text-indigo-600 dark:text-indigo-400 hover:text-indigo-500 dark:hover:text-indigo-300 font-medium transition-colors">
                Войти
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
