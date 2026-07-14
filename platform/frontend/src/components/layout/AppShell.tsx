import {motion} from "framer-motion";
import {
  Boxes,
  LayoutDashboard,
  Laptop,
  Layers,
  LogOut,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import {useEffect, useState, type ReactNode} from "react";
import {NavLink, useLocation} from "react-router-dom";
import {canOperate, useAuth} from "../../lib/auth";
import {cn} from "../../lib/cn";
import {CommandPalette} from "./CommandPalette";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

export const NAV: NavItem[] = [
  {to: "/", label: "Dashboard", icon: LayoutDashboard},
  {to: "/inventory", label: "Inventory", icon: Boxes},
  {to: "/endpoints", label: "Endpoints", icon: Laptop},
  {to: "/analyzer", label: "SBOM Analyzer", icon: Layers},
  {to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert},
  {to: "/alerts", label: "Malware Analysis", icon: Siren},
  {to: "/sources", label: "Sources", icon: Settings2},
];

export function AppShell({children, onRefresh}: {children: ReactNode; onRefresh?: () => void}) {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const location = useLocation();
  const {user, authEnabled, logout} = useAuth();
  const nav: NavItem[] = canOperate(user?.role)
    ? [...NAV, {to: "/admin", label: "Access", icon: ShieldCheck}]
    : NAV;

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
  const current = nav.find((n) => n.to === location.pathname) ?? nav.find((n) => n.to !== "/" && location.pathname.startsWith(n.to));

  return (
    <div className="min-h-screen">
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />

      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-[248px] flex-col border-r border-white/8 bg-[#080d1a] lg:flex">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <div className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-brand to-brand-2 shadow-[0_8px_24px_-8px_rgba(45,212,191,0.7)]">
            <Workflow className="h-5 w-5 text-[#04121a]" />
          </div>
          <div>
            <div className="text-[15px] font-semibold leading-none brand-text">SupplyDrift</div>
            <div className="mt-1 text-[10px] uppercase tracking-[0.2em] text-faint">ghost deps</div>
          </div>
        </div>

        <nav className="mt-2 flex-1 space-y-1 px-3">
          {nav.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.to === "/"}>
              {({isActive}) => (
                <div
                  className={cn(
                    "group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition",
                    isActive ? "text-ink" : "text-muted hover:text-ink hover:bg-white/[0.04]",
                  )}
                >
                  {isActive && (
                    <motion.div
                      layoutId="nav-active"
                      className="absolute inset-0 rounded-xl bg-white/[0.06] ring-1 ring-white/10"
                      transition={{type: "spring", stiffness: 380, damping: 32}}
                    />
                  )}
                  <item.icon className={cn("relative h-[18px] w-[18px]", isActive && "text-brand")} />
                  <span className="relative font-medium">{item.label}</span>
                </div>
              )}
            </NavLink>
          ))}
        </nav>

        <button
          onClick={() => setPaletteOpen(true)}
          className="mx-3 mb-4 flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2.5 text-xs text-muted transition hover:bg-white/[0.06]"
        >
          <Search className="h-4 w-4" />
          <span className="flex-1 text-left">Search…</span>
          <kbd className="rounded bg-white/10 px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
        </button>
      </aside>

      {/* Main */}
      <div className="lg:pl-[248px]">
        <header className="sticky top-0 z-20 flex items-center justify-between gap-4 border-b border-white/8 bg-[#070b16]/92 px-6 py-4">
          <div>
            <h1 className="text-lg font-semibold text-ink">{current?.label ?? "SupplyDrift"}</h1>
            <p className="text-xs text-faint">Ground-truth software supply chain visibility</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-muted sm:flex">
              <span className="live-dot h-1.5 w-1.5 rounded-full bg-good" />
              live
            </span>
            {onRefresh && (
              <button
                onClick={onRefresh}
                className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-muted transition hover:bg-white/[0.07] hover:text-ink"
              >
                Refresh
              </button>
            )}
            {authEnabled && user && (
              <div className="flex items-center gap-2 border-l border-white/10 pl-3">
                <div className="hidden text-right sm:block">
                  <div className="text-xs font-medium text-ink">{user.username}</div>
                  <div className="text-[10px] uppercase tracking-wide text-faint">{user.role}</div>
                </div>
                <button
                  onClick={() => void logout()}
                  title="Sign out"
                  className="rounded-xl border border-white/10 bg-white/[0.03] p-2 text-muted transition hover:bg-critical/10 hover:text-critical"
                >
                  <LogOut className="h-4 w-4" />
                </button>
              </div>
            )}
          </div>
        </header>

        <main className="px-6 py-7">
          <div className="mx-auto max-w-[1400px]">{children}</div>
        </main>
      </div>
    </div>
  );
}
