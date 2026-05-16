import { useState } from "react";
import { ProviderLogo, PROVIDERS, providerLabel } from "./ProviderLogo";

export function ProviderSelect({ defaultValue = "github" }: { defaultValue?: string }) {
  const [selected, setSelected] = useState(defaultValue);

  return (
    <>
      <input type="hidden" name="provider" value={selected} />
      <div className="grid grid-cols-3 gap-2">
        {PROVIDERS.map((p) => {
          const active = selected === p;
          return (
            <button
              key={p}
              type="button"
              onClick={() => setSelected(p)}
              className={`
                relative flex flex-col items-center gap-2 px-3 py-4 rounded-xl border-2
                transition-all duration-150 cursor-pointer select-none
                ${active
                  ? "border-indigo-500 bg-indigo-500/10 dark:bg-indigo-500/10"
                  : "border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 hover:border-slate-300 dark:hover:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800"
                }
              `}
            >
              {/* Active dot */}
              {active && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-indigo-500" />
              )}
              <span className={`transition-colors ${active ? "text-indigo-600 dark:text-indigo-300" : "text-slate-600 dark:text-slate-300"}`}>
                <ProviderLogo provider={p} size={22} />
              </span>
              <span className={`text-xs font-semibold transition-colors ${
                active ? "text-indigo-600 dark:text-indigo-300" : "text-slate-600 dark:text-slate-400"
              }`}>
                {providerLabel(p)}
              </span>
            </button>
          );
        })}
      </div>
    </>
  );
}
