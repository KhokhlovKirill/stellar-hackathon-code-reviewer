import type { Severity } from "./types";

export function severityLabel(sev: Severity | string, lang: "ru" | "en" = "ru"): string {
  const maps: Record<string, Record<string, string>> = {
    ru: { critical: "Критический", high: "Высокий", medium: "Средний", low: "Низкий", info: "Инфо" },
    en: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
  };
  return maps[lang][String(sev).toLowerCase()] ?? String(sev);
}

export function riskLabel(label: string, lang: "ru" | "en" = "ru"): string {
  const maps: Record<string, Record<string, string>> = {
    ru: { critical: "Критический", high: "Высокий", medium: "Средний", low: "Низкий", clean: "Чисто" },
    en: { critical: "Critical", high: "High", medium: "Medium", low: "Low", clean: "Clean" },
  };
  return maps[lang][label] ?? label;
}

export function severityBorder(sev: Severity | string): string {
  switch (String(sev).toLowerCase()) {
    case "critical": return "border-l-red-500";
    case "high":     return "border-l-orange-500";
    case "medium":   return "border-l-yellow-500";
    default:         return "border-l-slate-600";
  }
}

export function severityBadge(sev: Severity | string): string {
  switch (String(sev).toLowerCase()) {
    case "critical": return "bg-red-500/15 text-red-400 border border-red-500/30 ring-red-500/20";
    case "high":     return "bg-orange-500/15 text-orange-400 border border-orange-500/30";
    case "medium":   return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30";
    default:         return "bg-slate-700/50 text-slate-400 border border-slate-600/50";
  }
}

export function riskBadge(label: string): string {
  switch (label) {
    case "critical": return "bg-red-500/15 text-red-400 border border-red-500/30";
    case "high":     return "bg-orange-500/15 text-orange-400 border border-orange-500/30";
    case "medium":   return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30";
    default:         return "bg-slate-700/50 text-slate-400 border border-slate-600/50";
  }
}

export function riskScoreColor(score: number): string {
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-orange-400";
  if (score >= 25) return "text-yellow-400";
  return "text-emerald-400";
}

/* Legacy aliases kept for ReviewFindings compat */
export const severityPill = severityBadge;
export const riskPill = riskBadge;
