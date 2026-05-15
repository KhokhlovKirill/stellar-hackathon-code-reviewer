import { useState } from "react";

export interface PillOption {
  value: string;
  label: string;
  color?: "red" | "orange" | "yellow" | "slate";
}

const colorMap = {
  red:    "border-red-500/60 bg-red-500/15 text-red-600 dark:text-red-400",
  orange: "border-orange-500/60 bg-orange-500/15 text-orange-600 dark:text-orange-400",
  yellow: "border-yellow-500/60 bg-yellow-500/15 text-yellow-600 dark:text-yellow-400",
  slate:  "border-indigo-500/60 bg-indigo-500/15 text-indigo-600 dark:text-indigo-300",
};

export function PillSelect({
  name,
  options,
  defaultValue,
}: {
  name: string;
  options: PillOption[];
  defaultValue: string;
}) {
  const [selected, setSelected] = useState(defaultValue);

  return (
    <>
      <input type="hidden" name={name} value={selected} />
      <div className="flex flex-wrap gap-1.5">
        {options.map((opt) => {
          const active = selected === opt.value;
          const colorCls = active ? (colorMap[opt.color ?? "slate"]) : "";
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => setSelected(opt.value)}
              className={`
                flex-1 min-w-fit text-xs font-medium py-2 px-3 rounded-lg border transition-all duration-150
                ${active
                  ? `${colorCls} shadow-sm`
                  : "border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:border-slate-300 dark:hover:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800"
                }
              `}
            >
              {opt.label}
            </button>
          );
        })}
      </div>
    </>
  );
}
