import { RequireAuth } from "../context/AuthContext";
import { useSettings, type Lang } from "../context/SettingsContext";
import { useTheme } from "../context/ThemeContext";

function OptionRow({
  active,
  label,
  onClick,
}: {
  active: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex-1 px-4 py-3 rounded-xl border text-sm font-medium transition-all ${
        active
          ? "border-indigo-500 bg-indigo-50 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-300"
          : "border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:border-indigo-300 dark:hover:border-indigo-500/50"
      }`}
    >
      {label}
    </button>
  );
}

function Card({
  title,
  desc,
  children,
}: {
  title: string;
  desc: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
      <p className="font-semibold text-slate-900 dark:text-white">{title}</p>
      <p className="text-sm text-slate-500 dark:text-slate-400 mt-1 mb-4">
        {desc}
      </p>
      {children}
    </div>
  );
}

export function SettingsPage() {
  return (
    <RequireAuth>
      <SettingsContent />
    </RequireAuth>
  );
}

function SettingsContent() {
  const { lang, setLang, t } = useSettings();
  const { theme, toggle } = useTheme();

  return (
    <div className="mx-auto max-w-2xl px-4 sm:px-6 py-10 space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-1">
          {t("settings.title")}
        </h1>
        <p className="text-slate-500 dark:text-slate-400 text-sm">
          {t("settings.subtitle")}
        </p>
      </div>

      <Card title={t("settings.language")} desc={t("settings.languageDesc")}>
        <div className="flex gap-3">
          {(["ru", "en"] as Lang[]).map((l) => (
            <OptionRow
              key={l}
              active={lang === l}
              label={l === "ru" ? t("settings.ru") : t("settings.en")}
              onClick={() => setLang(l)}
            />
          ))}
        </div>
      </Card>

      <Card title={t("settings.theme")} desc={t("settings.themeDesc")}>
        <div className="flex gap-3">
          <OptionRow
            active={theme === "light"}
            label={t("settings.light")}
            onClick={() => {
              if (theme !== "light") toggle();
            }}
          />
          <OptionRow
            active={theme === "dark"}
            label={t("settings.dark")}
            onClick={() => {
              if (theme !== "dark") toggle();
            }}
          />
        </div>
      </Card>

      <Card title={t("settings.aiTitle")} desc={t("settings.aiDesc")}>
        <div className="flex flex-wrap gap-2">
          {["DeepSeek V4", "MiMo V2", "Qwen3-Coder", "Don v3 (local)"].map(
            (m) => (
              <span
                key={m}
                className="text-xs px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400"
              >
                {m}
              </span>
            ),
          )}
        </div>
      </Card>
    </div>
  );
}
