import {AnimatePresence, motion} from "framer-motion";
import {CornerDownLeft, Search} from "lucide-react";
import {useEffect, useMemo, useState} from "react";
import {useNavigate} from "react-router-dom";
import {NAV} from "./AppShell";

export function CommandPalette({open, onClose}: {open: boolean; onClose: () => void}) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape" && open) onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  const items = useMemo(() => {
    const nav = NAV.map((n) => ({type: "nav" as const, label: n.label, to: n.to}));
    const actions = [
      {type: "search" as const, label: `Search packages for "${query}"`, to: `/analyzer?q=${encodeURIComponent(query)}`},
    ];
    const filtered = nav.filter((n) => n.label.toLowerCase().includes(query.toLowerCase()));
    return query ? [...filtered, ...actions] : nav;
  }, [query]);

  useEffect(() => setActive(0), [query, open]);

  if (!open) return null;

  const go = (to: string) => {
    navigate(to);
    onClose();
    setQuery("");
  };

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[14vh]"
        initial={{opacity: 0}}
        animate={{opacity: 1}}
        exit={{opacity: 0}}
        onClick={onClose}
      >
        <motion.div
          className="glass w-full max-w-xl overflow-hidden p-0"
          initial={{opacity: 0, y: -16, scale: 0.98}}
          animate={{opacity: 1, y: 0, scale: 1}}
          transition={{duration: 0.2}}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center gap-3 border-b border-white/8 px-4 py-3">
            <Search className="h-4 w-4 text-muted" />
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") setActive((a) => Math.min(a + 1, items.length - 1));
                if (e.key === "ArrowUp") setActive((a) => Math.max(a - 1, 0));
                if (e.key === "Enter" && items[active]) go(items[active].to);
              }}
              placeholder="Jump to a view or search packages…"
              className="flex-1 bg-transparent text-sm text-ink outline-none placeholder:text-faint"
            />
            <kbd className="rounded bg-white/10 px-1.5 py-0.5 font-mono text-[10px] text-muted">esc</kbd>
          </div>
          <div className="max-h-80 overflow-y-auto p-2">
            {items.map((item, i) => (
              <button
                key={item.label}
                onMouseEnter={() => setActive(i)}
                onClick={() => go(item.to)}
                className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left text-sm ${
                  i === active ? "bg-white/[0.07] text-ink" : "text-muted"
                }`}
              >
                <span>{item.label}</span>
                {i === active && <CornerDownLeft className="h-3.5 w-3.5 text-faint" />}
              </button>
            ))}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
