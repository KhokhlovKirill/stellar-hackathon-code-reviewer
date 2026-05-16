import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { AegisLogo } from "../components/AegisLogo";

const HOST = "aegis.khokhlovkirill.ru";

// ── Browser mockup ────────────────────────────────────────────────────────────

function BrowserMockup({ children, url }: { children: React.ReactNode; url?: string }) {
  return (
    <div className="max-w-full rounded-xl sm:rounded-2xl overflow-hidden shadow-2xl shadow-black/40 border border-white/10 bg-[#1e1e2e]">
      <div className="flex items-center gap-2 px-3 sm:px-4 py-2.5 sm:py-3 bg-[#16161e] border-b border-white/5">
        <div className="flex gap-1.5">
          <div className="w-3 h-3 rounded-full bg-red-500/80" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <div className="w-3 h-3 rounded-full bg-green-500/80" />
        </div>
        <div className="flex-1 mx-4">
          <div className="bg-[#2a2a3e] rounded-md px-3 py-1 text-xs text-slate-400 font-mono text-center truncate">
            {url ?? HOST}
          </div>
        </div>
      </div>
      {children}
    </div>
  );
}

function VSCodeMockup({ children }: { children: React.ReactNode }) {
  return (
    <div className="max-w-full rounded-xl sm:rounded-2xl overflow-hidden shadow-2xl shadow-black/40 border border-white/10 bg-[#1e1e1e]">
      <div className="flex items-center gap-2 px-3 sm:px-4 py-2.5 bg-[#323233] border-b border-black/30">
        <div className="flex gap-1.5">
          <div className="w-3 h-3 rounded-full bg-red-500/80" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <div className="w-3 h-3 rounded-full bg-green-500/80" />
        </div>
        <span className="min-w-0 truncate text-xs text-slate-400 ml-2 font-mono">my-project — Visual Studio Code</span>
      </div>
      {children}
    </div>
  );
}

// ── Mock screens ──────────────────────────────────────────────────────────────

function MockWebDashboard() {
  return (
    <div className="bg-[#020617] p-3 sm:p-4 text-[10px] sm:text-xs font-mono min-h-[260px] flex flex-col sm:flex-row gap-3">
      <div className="w-full sm:w-44 shrink-0 space-y-1">
        <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-2 px-2">Проекты</div>
        {["backend-api", "mobile-app", "data-pipeline"].map((p, i) => (
          <div key={p} className={`px-2 py-1.5 rounded-lg flex items-center gap-2 ${i === 0 ? "bg-indigo-500/20 text-indigo-300" : "text-slate-500"}`}>
            <div className="w-1.5 h-1.5 rounded-full bg-current" />
            {p}
          </div>
        ))}
      </div>
      <div className="flex-1 space-y-2">
        <div className="flex items-center justify-between mb-3">
          <span className="text-slate-300 font-semibold text-[11px]">backend-api / PR #47</span>
          <div className="bg-red-500/20 text-red-400 text-[10px] px-2 py-0.5 rounded-full border border-red-500/30">3 КРИТИЧЕСКИХ</div>
        </div>
        {[
          { sev: "critical", file: "auth/jwt.py:42",      title: "Захардкоженный JWT-ключ" },
          { sev: "high",     file: "api/users.py:87",     title: "SQL-инъекция" },
          { sev: "high",     file: "utils/upload.py:23",  title: "Обход пути" },
          { sev: "medium",   file: "config.py:12",        title: "Утечка данных" },
        ].map((f) => (
          <div key={f.file} className="flex items-start gap-2 bg-white/3 rounded-lg p-2 border border-white/5">
            <div className={`mt-0.5 text-[10px] px-1.5 py-0.5 rounded font-bold shrink-0 ${
              f.sev === "critical" ? "bg-red-500/20 text-red-400" :
              f.sev === "high"     ? "bg-orange-500/20 text-orange-400" :
                                     "bg-yellow-500/20 text-yellow-400"
            }`}>{f.sev === "critical" ? "КРИТ" : f.sev === "high" ? "ВЫСОК" : "СРЕДН"}</div>
            <div>
              <div className="text-slate-300 font-medium">{f.title}</div>
              <div className="text-slate-600 text-[10px]">{f.file}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function MockVSCode() {
  return (
    <div className="flex min-h-[260px]">
      <div className="w-8 sm:w-10 bg-[#333333] flex flex-col items-center pt-3 gap-3 border-r border-black/30">
        {["M", "⬡", "🛡", "⚙"].map((icon, i) => (
          <div key={i} className={`text-xs w-6 h-6 flex items-center justify-center rounded ${i === 2 ? "text-white" : "text-slate-500"}`}>{icon}</div>
        ))}
      </div>
      <div className="w-32 sm:w-52 bg-[#252526] border-r border-black/20 text-[9px] sm:text-[10px] font-mono">
        <div className="px-3 py-2 text-[9px] uppercase tracking-wider text-slate-500 border-b border-black/20">Aegis Security</div>
        <div className="px-2 py-1.5">
          <div className="text-slate-400 text-[9px] uppercase tracking-wider mb-1.5">Репозитории</div>
          <div className="pl-2 space-y-0.5">
            <div className="text-indigo-400 flex items-center gap-1"><span>▾</span> backend-api</div>
            <div className="pl-3 space-y-0.5 text-slate-500">
              {["PR #47 — fix/auth", "PR #45 — feat/api", "PR #43 — chore"].map((pr, i) => (
                <div key={i} className={`flex items-center gap-1.5 px-1 py-0.5 rounded ${i === 0 ? "bg-indigo-500/20 text-indigo-300" : ""}`}>
                  <span className="text-[8px]">⬟</span> {pr}
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="px-2 mt-2">
          <div className="text-slate-400 text-[9px] uppercase tracking-wider mb-1.5">Уязвимости (PR #47)</div>
          <div className="space-y-0.5 pl-2">
            {[
              { sev: "🔴", name: "Захардкоженный JWT-ключ" },
              { sev: "🟠", name: "SQL-инъекция" },
              { sev: "🟠", name: "Обход пути" },
            ].map((f) => (
              <div key={f.name} className="text-slate-400 flex items-center gap-1 truncate">
                <span className="text-[9px]">{f.sev}</span> {f.name}
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="flex-1 min-w-0 bg-[#1e1e1e] p-2 sm:p-3 font-mono text-[9px] sm:text-[10px] overflow-hidden">
        <div className="text-slate-500 mb-2">auth/jwt.py</div>
        <div className="space-y-0.5 leading-relaxed">
          <div><span className="text-slate-600 w-5 inline-block text-right mr-3">40</span><span className="text-blue-400">def</span> <span className="text-yellow-300">create_token</span><span className="text-slate-300">(user_id):</span></div>
          <div className="bg-red-500/15 border-l-2 border-red-500 -mx-3 px-3">
            <span className="text-slate-600 w-5 inline-block text-right mr-3">41</span>
            <span className="text-slate-400">SECRET = </span><span className="text-green-400">"hardcoded-key-123"</span>
          </div>
          <div><span className="text-slate-600 w-5 inline-block text-right mr-3">42</span><span className="text-slate-300">    token = jwt.encode(</span></div>
          <div><span className="text-slate-600 w-5 inline-block text-right mr-3">43</span><span className="text-slate-300">        payload, SECRET, </span><span className="text-green-400">"HS256"</span><span className="text-slate-300">)</span></div>
        </div>
        <div className="mt-3 bg-red-950/60 border border-red-800/50 rounded-lg p-2">
          <div className="text-red-400 font-semibold mb-0.5">🛡️ Aegis: CWE-321 — Захардкоженный криптоключ</div>
          <div className="text-slate-400">JWT-секрет должен поступать из переменной окружения.</div>
          <div className="flex gap-2 mt-1.5">
            <div className="text-indigo-400 cursor-pointer">💬 Спросить Aegis</div>
            <div className="text-emerald-400 cursor-pointer">🔧 Исправить</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MockChatStream() {
  return (
    <div className="bg-[#020617] p-4 text-xs font-mono min-h-[240px] flex flex-col gap-2">
      <div className="flex gap-2 items-start">
        <div className="w-6 h-6 rounded-full bg-slate-700 flex items-center justify-center text-[10px] shrink-0">U</div>
        <div className="bg-slate-800/60 rounded-xl px-3 py-2 text-slate-300 max-w-[80%]">
          Как исправить CWE-321 в JWT?
        </div>
      </div>
      <div className="flex gap-2 items-start">
        <div className="w-6 h-6 rounded-full bg-indigo-600/30 border border-indigo-500/40 flex items-center justify-center text-[10px] shrink-0">⬡</div>
        <div className="bg-indigo-500/10 border border-indigo-500/20 rounded-xl px-3 py-2 text-slate-300 flex-1">
          <div className="text-indigo-400 text-[10px] mb-1">Aegis AI</div>
          Перенесите секрет в переменную окружения. Вот исправление:
          <div className="mt-2 bg-slate-900 rounded-lg p-2 border border-slate-800">
            <div className="text-green-400 text-[9px] mb-1">diff --git a/auth/jwt.py b/auth/jwt.py</div>
            <div className="text-red-400">- SECRET = "hardcoded-key-123"</div>
            <div className="text-green-400">+ SECRET = os.environ["JWT_SECRET"]</div>
          </div>
          <div className="flex gap-2 mt-2">
            <div className="bg-indigo-600/30 text-indigo-300 rounded-md px-2 py-0.5 cursor-pointer">Применить патч</div>
            <div className="bg-slate-700/50 text-slate-400 rounded-md px-2 py-0.5 cursor-pointer">Скопировать</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MockScanSummary() {
  return (
    <div className="bg-[#020617] p-4 text-xs font-mono min-h-[120px]">
      <div className="flex items-center justify-between mb-3">
        <span className="text-slate-400 text-[11px] font-semibold">Итоги сканирования PR #47</span>
        <span className="text-emerald-400 text-[10px]">✓ завершено за 18 сек</span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
        {[
          { label: "Критических", val: "3", cls: "text-red-400 bg-red-500/10 border-red-500/20" },
          { label: "Высоких",     val: "2", cls: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
          { label: "Средних",     val: "1", cls: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20" },
          { label: "Низких",      val: "0", cls: "text-slate-500 bg-slate-500/10 border-slate-500/20" },
        ].map((s) => (
          <div key={s.label} className={`rounded-lg p-2 border text-center ${s.cls}`}>
            <div className="text-base font-black">{s.val}</div>
            <div className="text-[9px] opacity-70">{s.label}</div>
          </div>
        ))}
      </div>
      <div className="text-slate-500 text-[10px]">Проверено 4 файла · 2 детектора · AI-судья</div>
    </div>
  );
}

// ── UI components ─────────────────────────────────────────────────────────────

function Step({ n, icon, title, desc }: { n: number; icon: string; title: string; desc: string }) {
  return (
    <div className="flex gap-4">
      <div className="shrink-0 flex flex-col items-center">
        <div className="w-10 h-10 rounded-2xl bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-black text-sm">
          {n}
        </div>
        {n < 4 && <div className="w-px flex-1 mt-2 bg-gradient-to-b from-indigo-500/30 to-transparent min-h-[32px]" />}
      </div>
      <div className="pb-8">
        <div className="text-2xl mb-1">{icon}</div>
        <h3 className="font-bold text-slate-900 dark:text-white mb-1">{title}</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{desc}</p>
      </div>
    </div>
  );
}

function FeatureCard({ icon, title, desc }: { icon: string; title: string; desc: string }) {
  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl sm:rounded-2xl p-4 sm:p-5 hover:border-indigo-300 dark:hover:border-indigo-500/40 hover:shadow-lg hover:shadow-indigo-500/5 transition-all">
      <div className="text-2xl mb-3">{icon}</div>
      <h4 className="font-bold text-slate-900 dark:text-white mb-1.5">{title}</h4>
      <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{desc}</p>
    </div>
  );
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div className="text-center">
      <div className="text-3xl font-black bg-gradient-to-r from-indigo-400 to-violet-400 bg-clip-text text-transparent">{value}</div>
      <div className="text-sm text-slate-500 dark:text-slate-400 mt-1">{label}</div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function LandingPage() {
  const { user } = useAuth();
  const [tab, setTab] = useState<"web" | "vscode">("web");

  return (
    <div className="overflow-x-hidden">

      {/* ── Hero ─────────────────────────────────────────────────────────────── */}
      <section className="relative min-h-[auto] lg:min-h-[90vh] flex items-center overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-[-20%] left-[10%] w-[600px] h-[600px] rounded-full bg-indigo-600/20 blur-[120px]" />
          <div className="absolute bottom-[-10%] right-[5%] w-[500px] h-[500px] rounded-full bg-violet-600/15 blur-[120px]" />
        </div>

        <div className="relative mx-auto max-w-7xl px-4 sm:px-6 py-12 sm:py-16 lg:py-24 w-full">
          <div className="grid lg:grid-cols-2 gap-10 lg:gap-16 items-center">
            <div>
              <div className="inline-flex items-center gap-2 bg-indigo-500/10 border border-indigo-500/20 rounded-full px-4 py-1.5 text-sm text-indigo-400 mb-6">
                <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse" />
                AI-ревью безопасности кода
              </div>

              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black leading-[1.05] tracking-tight text-slate-900 dark:text-white mb-6">
                Находи уязвимости{" "}
                <span className="bg-gradient-to-r from-indigo-400 via-violet-400 to-indigo-500 bg-clip-text text-transparent">
                  до ревью
                </span>
              </h1>

              <p className="text-base sm:text-lg lg:text-xl text-slate-500 dark:text-slate-400 leading-relaxed mb-8 max-w-lg">
                Aegis анализирует pull request'ы с помощью ансамбля языковых моделей, находит SQL-инъекции, XSS, захардкоженные ключи и 50+ классов уязвимостей — прямо в VS Code или в браузере.
              </p>

              <div className="flex flex-col sm:flex-row sm:flex-wrap gap-3">
                <a
href="/aegis-security-0.2.0.vsix"
                  download
                  className="inline-flex items-center justify-center gap-2.5 px-6 py-3.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-base transition-all shadow-lg shadow-indigo-500/30 hover:shadow-indigo-500/40 hover:-translate-y-0.5"
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  Скачать для VS Code
                </a>

                {user ? (
                  <Link
                    to="/dashboard"
                    className="inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-900 dark:text-white font-semibold text-base transition-all hover:-translate-y-0.5"
                  >
                    Открыть дашборд
                  </Link>
                ) : (
                  <Link
                    to="/register"
                    className="inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-900 dark:text-white font-semibold text-base transition-all hover:-translate-y-0.5"
                  >
                    Попробовать
                  </Link>
                )}
              </div>

              <div className="mt-10 flex flex-wrap gap-4 text-xs text-slate-500 dark:text-slate-500">
                {["CWE Top 25 покрыт", "OWASP Top 10", "Ансамбль языковых моделей", "Self-hosted"].map((t) => (
                  <div key={t} className="flex items-center gap-1.5">
                    <svg className="w-3.5 h-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    {t}
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div className="relative">
                <div className="flex gap-2 mb-4 justify-center">
                  {(["web", "vscode"] as const).map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setTab(t)}
                      className={`px-4 py-1.5 rounded-full text-xs font-semibold transition-all ${
                        tab === t
                          ? "bg-indigo-600 text-white shadow-lg shadow-indigo-500/30"
                          : "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
                      }`}
                    >
                      {t === "web" ? "Веб-платформа" : "Расширение VS Code"}
                    </button>
                  ))}
                </div>

                {tab === "web" ? (
                  <BrowserMockup url={`${HOST} · PR #47 — Результаты сканирования`}>
                    <MockWebDashboard />
                  </BrowserMockup>
                ) : (
                  <VSCodeMockup>
                    <MockVSCode />
                  </VSCodeMockup>
                )}

                <div className="absolute -bottom-3 right-2 sm:-bottom-4 sm:-right-4 bg-emerald-500 text-white text-[11px] sm:text-xs font-bold px-3 py-1.5 rounded-full shadow-lg shadow-emerald-500/30">
                  3 уязвимости найдено
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Stats bar ────────────────────────────────────────────────────────── */}
      <section className="border-y border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-slate-900/50 backdrop-blur-sm">
        <div className="mx-auto max-w-5xl px-4 py-10 grid grid-cols-2 sm:grid-cols-4 gap-6">
          <Stat value="50+" label="классов уязвимостей" />
          <Stat value="3" label="модели в ансамбле" />
          <Stat value="&lt;30 с" label="время сканирования" />
          <Stat value="CWE+OWASP" label="стандарты покрытия" />
        </div>
      </section>

      {/* ── How it works ─────────────────────────────────────────────────────── */}
      <section className="py-14 sm:py-20 lg:py-24 mx-auto max-w-7xl px-4 sm:px-6">
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 bg-violet-500/10 border border-violet-500/20 rounded-full px-4 py-1.5 text-sm text-violet-400 mb-4">
            Как это работает
          </div>
          <h2 className="text-3xl sm:text-4xl font-black text-slate-900 dark:text-white">От кода до исправления за минуту</h2>
        </div>

        <div className="grid lg:grid-cols-2 gap-10 lg:gap-16 items-start">
          <div className="space-y-0">
            <Step n={1} icon="🔐" title="Войди и подключи репозиторий"
              desc="Зарегистрируйся на веб-платформе или установи расширение VS Code. Подключи GitHub-репозиторий — Aegis увидит все ветки и запросы на слияние." />
            <Step n={2} icon="🔍" title="Выбери запрос на слияние и запусти скан"
              desc="В боковой панели VS Code или на веб-дашборде выбери нужный PR. Нажми «Сканировать» — ансамбль моделей анализирует изменения и находит уязвимости с указанием файла и строки." />
            <Step n={3} icon="🛡️" title="Изучи уязвимости"
              desc="Каждая уязвимость содержит: уровень критичности, CWE-код, описание атаки и рекомендацию по исправлению. VS Code показывает подсветку прямо в редакторе." />
            <Step n={4} icon="🔧" title="Получи исправление от AI и примени"
              desc="Кнопка «Спросить Aegis» открывает стриминговый чат. Агент генерирует патч — можно применить одним кликом прямо в VS Code или скачать файл исправления." />
          </div>

          <div className="lg:sticky lg:top-24 space-y-4">
            <BrowserMockup url={`${HOST} · AI-ассистент`}>
              <MockChatStream />
            </BrowserMockup>
            <BrowserMockup url={`${HOST} · Итоги сканирования`}>
              <MockScanSummary />
            </BrowserMockup>
          </div>
        </div>
      </section>

      {/* ── Product split ────────────────────────────────────────────────────── */}
      <section className="py-14 sm:py-20 lg:py-24 bg-slate-50 dark:bg-slate-950/50">
        <div className="mx-auto max-w-7xl px-4 sm:px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-black text-slate-900 dark:text-white mb-3">Два продукта, одна экосистема</h2>
            <p className="text-slate-500 dark:text-slate-400 text-lg max-w-2xl mx-auto">
              Веб-платформа и расширение VS Code синхронизированы — сканируй где удобно, смотри результаты везде.
            </p>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            {/* Web platform */}
            <div className="bg-white dark:bg-slate-900 rounded-2xl sm:rounded-3xl border border-slate-200 dark:border-slate-800 p-5 sm:p-8 hover:shadow-xl hover:shadow-indigo-500/5 transition-all">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-12 h-12 rounded-2xl bg-indigo-500/15 border border-indigo-500/20 flex items-center justify-center text-2xl">🌐</div>
                <div>
                  <h3 className="text-xl font-black text-slate-900 dark:text-white">Веб-платформа</h3>
                  <p className="text-sm text-indigo-400">{HOST}</p>
                </div>
              </div>

              <div className="mb-6 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-800">
                <BrowserMockup url={`${HOST} · Дашборд`}>
                  <MockWebDashboard />
                </BrowserMockup>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <FeatureCard icon="📋" title="Дашборд проектов" desc="Все репозитории и запросы на слияние с историей сканов" />
                <FeatureCard icon="💬" title="AI-чат" desc="Стриминговый чат с контекстом конкретной уязвимости" />
                <FeatureCard icon="🔗" title="Вебхуки" desc="Авто-скан при открытии запроса на слияние в GitHub/GitLab" />
                <FeatureCard icon="📚" title="База знаний" desc="Справочник CWE/OWASP с примерами уязвимого и безопасного кода" />
              </div>

              <div className="mt-6 flex flex-col sm:flex-row gap-3">
                <Link to="/register" className="flex-1 text-center py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm transition-all shadow-lg shadow-indigo-500/20">
                  Зарегистрироваться
                </Link>
                <Link to="/review" className="flex-1 text-center py-3 rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 font-semibold text-sm transition-all">
                  Быстрый скан
                </Link>
              </div>
            </div>

            {/* VS Code extension */}
            <div className="bg-white dark:bg-slate-900 rounded-2xl sm:rounded-3xl border border-slate-200 dark:border-slate-800 p-5 sm:p-8 hover:shadow-xl hover:shadow-violet-500/5 transition-all">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-12 h-12 rounded-2xl bg-violet-500/15 border border-violet-500/20 flex items-center justify-center text-2xl">⬡</div>
                <div>
                  <h3 className="text-xl font-black text-slate-900 dark:text-white">Расширение VS Code</h3>
                  <p className="text-sm text-violet-400">Aegis Security</p>
                </div>
              </div>

              <div className="mb-6 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-800">
                <VSCodeMockup>
                  <MockVSCode />
                </VSCodeMockup>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <FeatureCard icon="🌳" title="Боковая панель" desc="Дерево репозиториев и запросов на слияние прямо в IDE" />
                <FeatureCard icon="⚠️" title="Встроенная диагностика" desc="Подсветка и подсказки в коде для каждой уязвимости" />
                <FeatureCard icon="🤖" title="Исправление в один клик" desc="AI генерирует и применяет патч не выходя из редактора" />
                <FeatureCard icon="🔑" title="Безопасная авторизация" desc="Токен хранится в защищённом хранилище VS Code" />
              </div>

              <div className="mt-6">
                <a
href="/aegis-security-0.2.0.vsix"
                  download
                  className="flex items-center justify-center gap-2.5 w-full py-3 rounded-xl bg-violet-600 hover:bg-violet-500 text-white font-semibold text-sm transition-all shadow-lg shadow-violet-500/20"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
Скачать .vsix (v0.2.0)
                </a>
                <p className="text-center text-xs text-slate-500 mt-2">
                  Расширения — Установить из VSIX — перезагрузить окно
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Full workflow ─────────────────────────────────────────────────────── */}
      <section className="py-14 sm:py-20 lg:py-24 mx-auto max-w-7xl px-4 sm:px-6">
        <div className="text-center mb-12">
          <h2 className="text-3xl sm:text-4xl font-black text-slate-900 dark:text-white mb-3">Полный процесс в VS Code</h2>
          <p className="text-slate-500 dark:text-slate-400">От открытия запроса на слияние до применённого патча — без выхода из редактора</p>
        </div>

        <VSCodeMockup>
          <MockVSCode />
        </VSCodeMockup>

        <div className="grid sm:grid-cols-3 gap-4 mt-6">
          {[
            { icon: "🌳", title: "Боковая панель", desc: "Список репозиториев и запросов на слияние с иконками критичности" },
            { icon: "⚠️", title: "Диагностика в коде", desc: "Подсветка уязвимой строки, всплывающая карточка с описанием атаки" },
            { icon: "🔧", title: "Патч применён", desc: "AI-чат сгенерировал исправление, одна кнопка — код обновлён" },
          ].map((s) => (
            <div key={s.title} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
              <div className="text-3xl mb-3">{s.icon}</div>
              <h4 className="font-bold text-slate-900 dark:text-white mb-2">{s.title}</h4>
              <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Tech stack ───────────────────────────────────────────────────────── */}
      <section className="py-16 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/50">
        <div className="mx-auto max-w-5xl px-4 text-center">
          <p className="text-xs uppercase tracking-widest text-slate-400 dark:text-slate-600 mb-6">Технологии</p>
          <div className="flex flex-wrap justify-center gap-3">
            {[
              { label: "FastAPI",      color: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20" },
              { label: "OpenRouter",   color: "bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/20" },
              { label: "React + Vite", color: "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/20" },
              { label: "PostgreSQL",   color: "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20" },
              { label: "DeepSeek V4",  color: "bg-violet-500/10 text-violet-600 dark:text-violet-400 border-violet-500/20" },
              { label: "MiMo-V2",      color: "bg-pink-500/10 text-pink-600 dark:text-pink-400 border-pink-500/20" },
              { label: "Semgrep",      color: "bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20" },
              { label: "VS Code API",  color: "bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/20" },
            ].map((t) => (
              <span key={t.label} className={`px-4 py-2 rounded-full text-sm font-semibold border ${t.color}`}>{t.label}</span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Final CTA ────────────────────────────────────────────────────────── */}
      <section className="py-14 sm:py-20 lg:py-24 relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute inset-0 bg-gradient-to-r from-indigo-600/10 via-violet-600/10 to-indigo-600/10" />
        </div>
        <div className="relative mx-auto max-w-3xl px-4 text-center">
          <AegisLogo size={56} className="mx-auto mb-6" />
          <h2 className="text-3xl sm:text-5xl font-black text-slate-900 dark:text-white mb-4">
            Начни сканировать<br />
            <span className="bg-gradient-to-r from-indigo-400 to-violet-400 bg-clip-text text-transparent">уже сегодня</span>
          </h2>
          <p className="text-lg text-slate-500 dark:text-slate-400 mb-10">
            Ансамбль языковых моделей анализирует код и предлагает точные исправления.
          </p>
          <div className="flex flex-col sm:flex-row sm:flex-wrap justify-center gap-4">
            <a
href="/aegis-security-0.2.0.vsix"
              download
              className="inline-flex items-center justify-center gap-2.5 px-8 py-4 rounded-2xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-lg transition-all shadow-2xl shadow-indigo-500/30 hover:shadow-indigo-500/40 hover:-translate-y-0.5"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Скачать расширение
            </a>
            {user ? (
              <Link
                to="/dashboard"
                className="inline-flex items-center justify-center gap-2 px-8 py-4 rounded-2xl border-2 border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-900 dark:text-white font-bold text-lg transition-all hover:-translate-y-0.5"
              >
                Перейти в дашборд
              </Link>
            ) : (
              <Link
                to="/register"
                className="inline-flex items-center justify-center gap-2 px-8 py-4 rounded-2xl border-2 border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-900 dark:text-white font-bold text-lg transition-all hover:-translate-y-0.5"
              >
                Зарегистрироваться
              </Link>
            )}
          </div>
        </div>
      </section>

    </div>
  );
}
