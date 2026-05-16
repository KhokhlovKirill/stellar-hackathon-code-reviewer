import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

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
  },
} as const;

export type StringKey = keyof (typeof STRINGS)["en"];

interface SettingsContextValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: StringKey) => string;
}

const SettingsContext = createContext<SettingsContextValue>({
  lang: "ru",
  setLang: () => {},
  t: (k) => k,
});

const LS_KEY = "aegis-lang";

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

  // Seed from backend policy default only when the user has no stored choice.
  useEffect(() => {
    let stored: string | null = null;
    try {
      stored = localStorage.getItem(LS_KEY);
    } catch {
      /* ignore */
    }
    if (stored === "ru" || stored === "en") return;
    let cancelled = false;
    fetch("/api/config/defaults")
      .then((r) => (r.ok ? r.json() : null))
      .then((d: { default_language?: string } | null) => {
        if (cancelled || !d) return;
        if (d.default_language === "ru" || d.default_language === "en") {
          setLangState(d.default_language);
        }
      })
      .catch(() => {
        /* offline — keep default */
      });
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
  }, []);

  const t = useCallback(
    (key: StringKey) => STRINGS[lang][key] ?? STRINGS.en[key] ?? key,
    [lang],
  );

  const value = useMemo(() => ({ lang, setLang, t }), [lang, setLang, t]);

  return (
    <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
  );
}

export function useSettings() {
  return useContext(SettingsContext);
}
