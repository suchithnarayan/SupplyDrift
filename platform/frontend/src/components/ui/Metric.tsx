import {animate, useMotionValue} from "framer-motion";
import type {LucideIcon} from "lucide-react";
import {useEffect, useState} from "react";
import {GlassCard} from "./primitives";

function useCount(value: number) {
  const mv = useMotionValue(0);
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    const controls = animate(mv, value, {
      duration: 0.9,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (v) => setDisplay(Math.round(v)),
    });
    return controls.stop;
  }, [value, mv]);
  return display;
}

export function Metric({
  icon: Icon,
  label,
  value,
  note,
  accent = "text-brand",
}: {
  icon: LucideIcon;
  label: string;
  value: number;
  note?: string;
  accent?: string;
}) {
  const count = useCount(value);
  return (
    <GlassCard hover className="relative overflow-hidden">
      <div className="pointer-events-none absolute -right-8 -top-8 h-24 w-24 rounded-full bg-current opacity-[0.07] blur-2xl" />
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wider text-muted">{label}</span>
        <Icon className={`h-4 w-4 ${accent}`} />
      </div>
      <div className="mt-3 font-mono text-3xl font-semibold tabular-nums text-ink">
        {count.toLocaleString()}
      </div>
      {note && <div className="mt-1 text-xs text-faint">{note}</div>}
    </GlassCard>
  );
}
