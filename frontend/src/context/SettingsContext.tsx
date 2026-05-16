import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { getToken } from "../lib/token";

export type Lang = "ru" | "en";

// ── i18n dictionary ────────────────────────────────────────────────────────────
// Covers every interactive surface (nav, chat, finding/scan actions, settings,
// common labels). AI responses themselves switch via the `lang` field sent to
// the backend chat/scan/review endpoints.
const STRINGS = {
  ru: {
    "nav.product": "Продукт",
    "nav.review": "Анализ",
    "nav.projects": "Проекты",
    "nav.chat": "Чат",
    "nav.knowledge": "База знаний",
    "nav.settings": "Настройки",
    "nav.login": "Войти",
    "nav.register": "Регистрация",
    "nav.logout": "Выйти",

    "chat.assistant": "AI-ассистент по безопасности",
    "chat.placeholder": "Задайте вопрос по безопасности…",
    "chat.clear": "Очистить",
    "chat.send": "Отправить",
    "chat.retry": "⚠️ Не удалось получить ответ. Попробуйте ещё раз.",
    "chat.welcome":
      "Привет! Я Aegis AI — ваш помощник по безопасности кода. " +
      "Задайте вопрос об уязвимостях, настройке интеграций или результатах сканирования.",
    "chat.proposedPatch": "Предложенный патч",
    "chat.copy": "Скопировать",
    "chat.copied": "Скопировано",
    "chat.download": "Скачать .patch",
    "chat.dismiss": "Скрыть",
    "chat.stop": "Остановить",

    "action.ask": "Спросить Aegis",
    "action.explain": "Объяснить",
    "action.fix": "Исправить",
    "action.askFinding": "Спросить про эту находку",
    "action.explainFinding": "Объясни эту уязвимость подробно и почему она опасна",
    "action.fixFinding":
      "Сгенерируй полный безопасный фикс для этой находки в виде unified diff",
    "action.askScan": "Спросить про весь PR",
    "action.explainScan":
      "Объясни результаты security review этого PR, приоритизируй риски и предложи безопасный план исправления",
    "action.fixScan":
      "Подготовь общий план исправления всех находок этого PR с конкретными unified diff патчами",

    "settings.title": "Настройки",
    "settings.subtitle": "Язык интерфейса и ответов AI, тема оформления.",
    "settings.language": "Язык",
    "settings.languageDesc":
      "Язык интерфейса и язык, на котором Aegis AI отвечает в чате, summary и ревью.",
    "settings.theme": "Тема",
    "settings.themeDesc": "Светлое или тёмное оформление интерфейса.",
    "settings.ru": "Русский",
    "settings.en": "English",
    "settings.dark": "Тёмная",
    "settings.light": "Светлая",
    "settings.aiTitle": "Модели AI",
    "settings.aiDesc":
      "Ансамбль OpenRouter (DeepSeek / MiMo / Qwen3-Coder) + локальная дообученная " +
      "модель безопасности Don v3 (qwen3-coder-30b SFT + ORPO). Don запускается " +
      "локально и обязателен в ансамбле; язык ответов задаётся выше.",
    "settings.saved": "Сохранено",

    "common.loading": "Загрузка…",
    "common.error": "Ошибка",

    // ── Backend error details → localized text ───────────────────────────
    "err.invalid credentials": "Неверный email или пароль",
    "err.email already registered": "Этот email уже зарегистрирован",
    "err.unknown user": "Пользователь не найден",
    "err.missing bearer token": "Требуется вход в систему",
    "err.login required": "Требуется вход в систему",
    "err.invalid token": "Сессия недействительна — войдите снова",
    "err.invalid token signature": "Сессия недействительна — войдите снова",
    "err.invalid subject": "Сессия недействительна — войдите снова",
    "err.token expired": "Сессия истекла — войдите снова",
    "err.project not found": "Проект не найден",
    "err.repo not found": "Репозиторий не найден",
    "err.scan not found": "Скан не найден",
    "err.project name already exists": "Проект с таким названием уже существует",
    "err.language must be 'ru' or 'en'": "Язык должен быть 'ru' или 'en'",
    "err.Cannot parse GitHub repo URL": "Не удалось разобрать URL GitHub-репозитория",
    "err.Cannot parse repository URL": "Не удалось разобрать URL репозитория",
    "err.GitHub repo not found — check URL or token scope":
      "GitHub-репозиторий не найден — проверьте URL или права токена",
    "err.GitHub token invalid or expired":
      "GitHub-токен недействителен или истёк",
    "err.GitLab repo not found — check URL or token scope":
      "GitLab-репозиторий не найден — проверьте URL или права токена",
    "err.GitLab token invalid or expired":
      "GitLab-токен недействителен или истёк",
    "err.unauthorized": "Требуется вход в систему",
    "err.network": "Сервис недоступен — повторите попытку через несколько секунд",
    "err.generic": "Что-то пошло не так. Попробуйте ещё раз.",
    "err.login_failed": "Не удалось войти",
    "err.register_failed": "Не удалось зарегистрироваться",
    "err.project_load_failed": "Не удалось загрузить проект",
  },
  en: {
    "nav.product": "Product",
    "nav.review": "Review",
    "nav.projects": "Projects",
    "nav.chat": "Chat",
    "nav.knowledge": "Knowledge",
    "nav.settings": "Settings",
    "nav.login": "Sign in",
    "nav.register": "Sign up",
    "nav.logout": "Sign out",

    "chat.assistant": "AI security assistant",
    "chat.placeholder": "Ask a security question…",
    "chat.clear": "Clear",
    "chat.send": "Send",
    "chat.retry": "⚠️ Could not get a response. Please try again.",
    "chat.welcome":
      "Hi! I'm Aegis AI — your code security assistant. " +
      "Ask about vulnerabilities, integration setup, or scan results.",
    "chat.proposedPatch": "Proposed patch",
    "chat.copy": "Copy",
    "chat.copied": "Copied",
    "chat.download": "Download .patch",
    "chat.dismiss": "Dismiss",
    "chat.stop": "Stop",

    "action.ask": "Ask Aegis",
    "action.explain": "Explain",
    "action.fix": "Fix",
    "action.askFinding": "Ask about this finding",
    "action.explainFinding":
      "Explain this vulnerability in detail and why it is dangerous",
    "action.fixFinding":
      "Generate a complete secure fix for this finding as a unified diff",
    "action.askScan": "Ask about the whole PR",
    "action.explainScan":
      "Explain the security review for this PR, prioritize the risks and suggest the safest remediation plan",
    "action.fixScan":
      "Prepare an overall remediation plan for all findings in this PR with concrete unified diff patches",

    "settings.title": "Settings",
    "settings.subtitle": "Interface & AI response language, color theme.",
    "settings.language": "Language",
    "settings.languageDesc":
      "Interface language and the language Aegis AI replies in for chat, summaries and reviews.",
    "settings.theme": "Theme",
    "settings.themeDesc": "Light or dark interface appearance.",
    "settings.ru": "Русский",
    "settings.en": "English",
    "settings.dark": "Dark",
    "settings.light": "Light",
    "settings.aiTitle": "AI models",
    "settings.aiDesc":
      "OpenRouter ensemble (DeepSeek / MiMo / Qwen3-Coder) + the locally " +
      "fine-tuned security model Don v3 (qwen3-coder-30b SFT + ORPO). Don runs " +
      "locally and is mandatory in the ensemble; reply language is set above.",
    "settings.saved": "Saved",

    "common.loading": "Loading…",
    "common.error": "Error",

    // ── Backend error details → localized text ───────────────────────────
    "err.invalid credentials": "Invalid email or password",
    "err.email already registered": "This email is already registered",
    "err.unknown user": "User not found",
    "err.missing bearer token": "Sign-in required",
    "err.login required": "Sign-in required",
    "err.invalid token": "Session is invalid — please sign in again",
    "err.invalid token signature": "Session is invalid — please sign in again",
    "err.invalid subject": "Session is invalid — please sign in again",
    "err.token expired": "Session expired — please sign in again",
    "err.project not found": "Project not found",
    "err.repo not found": "Repository not found",
    "err.scan not found": "Scan not found",
    "err.project name already exists": "A project with this name already exists",
    "err.language must be 'ru' or 'en'": "Language must be 'ru' or 'en'",
    "err.Cannot parse GitHub repo URL": "Could not parse the GitHub repo URL",
    "err.Cannot parse repository URL": "Could not parse the repository URL",
    "err.GitHub repo not found — check URL or token scope":
      "GitHub repo not found — check the URL or token scope",
    "err.GitHub token invalid or expired":
      "GitHub token is invalid or expired",
    "err.GitLab repo not found — check URL or token scope":
      "GitLab repo not found — check the URL or token scope",
    "err.GitLab token invalid or expired":
      "GitLab token is invalid or expired",
    "err.unauthorized": "Sign-in required",
    "err.network": "Service unavailable — please retry in a few seconds",
    "err.generic": "Something went wrong. Please try again.",
    "err.login_failed": "Could not sign in",
    "err.register_failed": "Could not sign up",
    "err.project_load_failed": "Could not load the project",
  },
} as const;

export type StringKey = keyof (typeof STRINGS)["en"];

interface SettingsContextValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: StringKey) => string;
  /**
   * Localize an unknown thrown value (ApiError / Error / string) to the
   * active language. Maps known backend `detail` codes via the `err.*`
   * dictionary; falls back to a generic localized message rather than
   * leaking raw English ("Unauthorized", "Not Found", …) to the user.
   */
  localizeError: (err: unknown, fallbackKey?: StringKey) => string;
}

const SettingsContext = createContext<SettingsContextValue>({
  lang: "ru",
  setLang: () => {},
  t: (k) => k,
  localizeError: () => "Error",
});

const LS_KEY = "aegis-lang";

interface ErrorLike {
  detail?: unknown;
  message?: unknown;
  status?: unknown;
}

function extractDetail(err: unknown): { detail: string; status: number } {
  if (typeof err === "string") return { detail: err, status: 0 };
  const e = (err ?? {}) as ErrorLike;
  const detail =
    (typeof e.detail === "string" && e.detail) ||
    (typeof e.message === "string" && e.message) ||
    "";
  const status = typeof e.status === "number" ? e.status : 0;
  return { detail: detail.trim(), status };
}

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    try {
      const stored = localStorage.getItem(LS_KEY);
      if (stored === "ru" || stored === "en") return stored;
    } catch {
      /* ignore */
    }
    return "ru";
  });

  // Seed from backend: prefer the authenticated user's saved preference, then
  // the server policy default, and finally the in-memory default.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const token = getToken();
      if (token) {
        try {
          const r = await fetch("/api/ext/me/preferences", {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (r.ok) {
            const d = (await r.json()) as { language?: string };
            if (!cancelled && (d.language === "ru" || d.language === "en")) {
              setLangState(d.language);
              try {
                localStorage.setItem(LS_KEY, d.language);
              } catch {
                /* ignore */
              }
              return;
            }
          }
        } catch {
          /* network issue — fall through to defaults */
        }
      }

      let stored: string | null = null;
      try {
        stored = localStorage.getItem(LS_KEY);
      } catch {
        /* ignore */
      }
      if (stored === "ru" || stored === "en") return;

      try {
        const r = await fetch("/api/config/defaults");
        if (r.ok) {
          const d = (await r.json()) as { default_language?: string };
          if (
            !cancelled &&
            (d.default_language === "ru" || d.default_language === "en")
          ) {
            setLangState(d.default_language);
          }
        }
      } catch {
        /* offline — keep default */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    try {
      document.documentElement.setAttribute("lang", lang);
    } catch {
      /* ignore */
    }
  }, [lang]);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem(LS_KEY, l);
    } catch {
      /* ignore */
    }
    // Best-effort persistence to backend so the preference syncs across
    // devices (web + VS Code extension). Silently ignore network/auth errors.
    const token = getToken();
    if (token) {
      void fetch("/api/ext/me/preferences", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ language: l }),
      }).catch(() => {
        /* ignore */
      });
    }
  }, []);

  const t = useCallback(
    (key: StringKey) => STRINGS[lang][key] ?? STRINGS.en[key] ?? key,
    [lang],
  );

  const localizeError = useCallback(
    (err: unknown, fallbackKey: StringKey = "err.generic"): string => {
      const { detail, status } = extractDetail(err);
      const dict = STRINGS[lang];
      // 1. Exact backend detail code → localized text.
      if (detail) {
        const key = `err.${detail}` as StringKey;
        if (key in dict) return dict[key];
      }
      // 2. Network/backend-unavailable heuristic.
      if (
        /network error|failed to fetch|backend unavailable/i.test(detail) ||
        status === 502 ||
        status === 503
      ) {
        return dict["err.network"];
      }
      // 3. Bare auth status with no usable detail.
      if (status === 401 || status === 403 || /unauthorized/i.test(detail)) {
        return dict["err.unauthorized"];
      }
      // 4. A detail that's already human prose (not a raw status word) — show
      //    it as-is; otherwise the localized fallback.
      if (detail && !/^[a-z ]+$/.test(detail) && detail.length > 3) {
        return detail;
      }
      return dict[fallbackKey] ?? dict["err.generic"];
    },
    [lang],
  );

  const value = useMemo(
    () => ({ lang, setLang, t, localizeError }),
    [lang, setLang, t, localizeError],
  );

  return (
    <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
  );
}

export function useSettings() {
  return useContext(SettingsContext);
}
