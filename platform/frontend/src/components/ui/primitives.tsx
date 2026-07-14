import {motion} from "framer-motion";
import type {ReactNode} from "react";
import {cn} from "../../lib/cn";
import {SEVERITY_COLOR} from "../../lib/meta";

export function GlassCard({className, children, hover, ...rest}: {
  className?: string;
  children: ReactNode;
  hover?: boolean;
} & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("glass p-5", hover && "glass-hover cursor-pointer", className)} {...rest}>
      {children}
    </div>
  );
}

export function SectionTitle({title, sub, right}: {title: string; sub?: string; right?: ReactNode}) {
  return (
    <div className="mb-4 flex items-end justify-between gap-4">
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">{title}</h2>
        {sub && <p className="mt-1 text-xs text-faint">{sub}</p>}
      </div>
      {right}
    </div>
  );
}

export function SeverityPill({severity}: {severity: string}) {
  const color = SEVERITY_COLOR[severity] || SEVERITY_COLOR.unknown;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
      style={{
        color,
        background: `${color}1f`,
        boxShadow: `inset 0 0 0 1px ${color}40`,
      }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{background: color}} />
      {severity}
    </span>
  );
}

const STATUS_COLORS: Record<string, string> = {
  vulnerable: "#fb5a73",
  clean: "#45d483",
  failed: "#ff9d57",
  unsupported: "#8c97b0",
  unknown: "#5b6b8c",
  open: "#ff9d57",
  resolved: "#45d483",
  accepted: "#56b9ff",
  suppressed: "#8c97b0",
  enabled: "#45d483",
  disabled: "#5b6b8c",
};

export function StatusPill({status}: {status: string}) {
  const color = STATUS_COLORS[status] || "#8c97b0";
  return (
    <span
      className="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium capitalize"
      style={{color, background: `${color}1a`, boxShadow: `inset 0 0 0 1px ${color}33`}}
    >
      {status}
    </span>
  );
}

export function Tag({children}: {children: ReactNode}) {
  return (
    <span className="rounded-md bg-white/5 px-2 py-0.5 text-[11px] text-muted ring-1 ring-white/10">
      {children}
    </span>
  );
}

export function Skeleton({className}: {className?: string}) {
  return <div className={cn("skeleton h-4 w-full", className)} />;
}

export function EmptyState({title, hint}: {title: string; hint?: string}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center">
      <div className="grid h-12 w-12 place-items-center rounded-2xl bg-white/5 ring-1 ring-white/10">
        <span className="text-xl">◎</span>
      </div>
      <p className="text-sm font-medium text-ink">{title}</p>
      {hint && <p className="max-w-sm text-xs text-faint">{hint}</p>}
    </div>
  );
}

export function Button({
  children,
  variant = "primary",
  className,
  ...rest
}: {
  children: ReactNode;
  variant?: "primary" | "ghost" | "danger";
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const base =
    "inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-sm font-medium transition ring-focus disabled:opacity-50";
  const variants = {
    primary:
      "bg-gradient-to-r from-brand/90 to-accent/90 text-[#04121a] hover:from-brand hover:to-accent shadow-[0_8px_30px_-10px_rgba(45,212,191,0.6)]",
    ghost: "bg-white/5 text-ink ring-1 ring-white/10 hover:bg-white/10",
    danger: "bg-critical/15 text-critical ring-1 ring-critical/30 hover:bg-critical/25",
  };
  return (
    <button className={cn(base, variants[variant], className)} {...rest}>
      {children}
    </button>
  );
}

export const fadeUp = {
  initial: {opacity: 0, y: 12},
  animate: {opacity: 1, y: 0},
  exit: {opacity: 0, y: -8},
};

export function Stagger({children, className}: {children: ReactNode; className?: string}) {
  return (
    <motion.div
      className={className}
      initial="hidden"
      animate="show"
      variants={{
        hidden: {},
        show: {transition: {staggerChildren: 0.05}},
      }}
    >
      {children}
    </motion.div>
  );
}

export function StaggerItem({children, className}: {children: ReactNode; className?: string}) {
  return (
    <motion.div
      className={className}
      variants={{hidden: {opacity: 0, y: 14}, show: {opacity: 1, y: 0}}}
      transition={{duration: 0.4, ease: [0.22, 1, 0.36, 1]}}
    >
      {children}
    </motion.div>
  );
}
