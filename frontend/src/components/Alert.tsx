import type { ReactNode } from "react";

const variants = {
  error:   { cls: "bg-red-50 dark:bg-red-500/10 border-red-300 dark:border-red-500/30 text-red-600 dark:text-red-300",    icon: "⛔" },
  warning: { cls: "bg-amber-50 dark:bg-amber-500/10 border-amber-300 dark:border-amber-500/30 text-amber-700 dark:text-amber-300", icon: "⚠️" },
  success: { cls: "bg-emerald-50 dark:bg-emerald-500/10 border-emerald-300 dark:border-emerald-500/30 text-emerald-700 dark:text-emerald-300", icon: "✅" },
  info:    { cls: "bg-indigo-50 dark:bg-indigo-500/10 border-indigo-200 dark:border-indigo-500/30 text-indigo-700 dark:text-indigo-300", icon: "ℹ️" },
};

export function Alert({
  children,
  variant = "error",
}: {
  children: ReactNode;
  variant?: keyof typeof variants;
}) {
  const v = variants[variant];
  return (
    <div className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-sm ${v.cls}`}>
      <span className="mt-0.5 shrink-0">{v.icon}</span>
      <span>{children}</span>
    </div>
  );
}
