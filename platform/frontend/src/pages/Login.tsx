import {motion} from "framer-motion";
import {Workflow} from "lucide-react";
import {useState} from "react";
import {useAuth} from "../lib/auth";

export function Login() {
  const {login} = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <motion.div
        initial={{opacity: 0, y: 14}}
        animate={{opacity: 1, y: 0}}
        transition={{duration: 0.4, ease: [0.22, 1, 0.36, 1]}}
        className="w-full max-w-sm"
      >
        <div className="mb-6 flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl bg-gradient-to-br from-brand to-brand-2 shadow-[0_8px_24px_-8px_rgba(45,212,191,0.7)]">
            <Workflow className="h-6 w-6 text-[#04121a]" />
          </div>
          <div>
            <div className="text-lg font-semibold brand-text">SupplyDrift</div>
            <div className="text-[11px] uppercase tracking-[0.2em] text-faint">sign in</div>
          </div>
        </div>

        <form onSubmit={submit} className="glass space-y-4 p-6">
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Username</label>
            <input
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2.5 text-sm text-ink outline-none focus:border-accent/40"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2.5 text-sm text-ink outline-none focus:border-accent/40"
            />
          </div>
          {error && (
            <div className="rounded-lg bg-critical/10 px-3 py-2 text-xs text-critical ring-1 ring-critical/20">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={busy || !username || !password}
            className="w-full rounded-xl bg-gradient-to-r from-brand/90 to-accent/90 px-4 py-2.5 text-sm font-semibold text-[#04121a] transition hover:from-brand hover:to-accent disabled:opacity-50"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <p className="mt-4 text-center text-[11px] text-faint">
          First run? The admin is seeded from SUPPLYDRIFT_ADMIN_USER / _PASSWORD.
        </p>
      </motion.div>
    </div>
  );
}
