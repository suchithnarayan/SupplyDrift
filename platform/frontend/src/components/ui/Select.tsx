import {AnimatePresence, motion} from "framer-motion";
import {Check, ChevronDown} from "lucide-react";
import {useEffect, useRef, useState} from "react";
import {cn} from "../../lib/cn";

export interface SelectOption {
  value: string;
  label: string;
}

export function Select({
  value,
  onChange,
  options,
  disabled,
  placeholder = "Select…",
}: {
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  disabled?: boolean;
  placeholder?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const current = options.find((o) => o.value === value);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "flex w-full items-center justify-between gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-ink outline-none transition focus:border-accent/40 disabled:cursor-not-allowed disabled:opacity-60",
          open && "border-accent/40",
        )}
      >
        <span className={cn(!current && "text-faint")}>{current?.label ?? placeholder}</span>
        <ChevronDown className={cn("h-4 w-4 text-muted transition-transform", open && "rotate-180")} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{opacity: 0, y: -6}}
            animate={{opacity: 1, y: 0}}
            exit={{opacity: 0, y: -6}}
            transition={{duration: 0.14}}
            className="absolute z-50 mt-1.5 max-h-60 w-full overflow-auto rounded-xl border border-white/10 bg-[#0d1426] p-1 shadow-[0_24px_60px_-20px_rgba(0,0,0,0.9)]"
          >
            {options.map((o) => (
              <button
                key={o.value}
                type="button"
                onClick={() => {
                  onChange(o.value);
                  setOpen(false);
                }}
                className={cn(
                  "flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-sm transition",
                  o.value === value ? "bg-white/[0.07] text-ink" : "text-muted hover:bg-white/[0.05] hover:text-ink",
                )}
              >
                {o.label}
                {o.value === value && <Check className="h-3.5 w-3.5 text-brand" />}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
