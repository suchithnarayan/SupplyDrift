import {AnimatePresence, motion} from "framer-motion";
import {CheckCircle2, Info, XCircle} from "lucide-react";
import {createContext, useCallback, useContext, useState, type ReactNode} from "react";

type ToastKind = "success" | "error" | "info";
interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

const ToastCtx = createContext<(message: string, kind?: ToastKind) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

const ICONS = {success: CheckCircle2, error: XCircle, info: Info};
const COLORS = {success: "#45d483", error: "#fb5a73", info: "#56b9ff"};

let counter = 0;

export function ToastProvider({children}: {children: ReactNode}) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const push = useCallback((message: string, kind: ToastKind = "info") => {
    const id = ++counter;
    setToasts((t) => [...t, {id, kind, message}]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
  }, []);

  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-6 right-6 z-50 flex w-80 flex-col gap-2">
        <AnimatePresence>
          {toasts.map((t) => {
            const Icon = ICONS[t.kind];
            return (
              <motion.div
                key={t.id}
                initial={{opacity: 0, x: 40, scale: 0.95}}
                animate={{opacity: 1, x: 0, scale: 1}}
                exit={{opacity: 0, x: 40, scale: 0.95}}
                transition={{duration: 0.3, ease: [0.22, 1, 0.36, 1]}}
                className="glass pointer-events-auto flex items-start gap-3 p-3.5"
              >
                <Icon className="mt-0.5 h-5 w-5 shrink-0" style={{color: COLORS[t.kind]}} />
                <span className="text-sm text-ink">{t.message}</span>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </ToastCtx.Provider>
  );
}
