import {createContext, useCallback, useContext, useEffect, useState, type ReactNode} from "react";
import {api, onUnauthorized, setCsrf} from "./api";
import type {Role} from "./types";

interface CurrentUser {
  username: string;
  role: Role;
}

interface AuthState {
  ready: boolean;
  authEnabled: boolean;
  user: CurrentUser | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  reload: () => Promise<void>;
}

const AuthCtx = createContext<AuthState>(null as unknown as AuthState);

export function useAuth(): AuthState {
  return useContext(AuthCtx);
}

/** Role helpers — the UI hides what a role can't do; the backend still enforces it. */
export function canOperate(role?: Role): boolean {
  return role === "admin" || role === "member";
}
export function isAdmin(role?: Role): boolean {
  return role === "admin";
}

export function AuthProvider({children}: {children: ReactNode}) {
  const [ready, setReady] = useState(false);
  const [authEnabled, setAuthEnabled] = useState(true);
  const [user, setUser] = useState<CurrentUser | null>(null);

  const reload = useCallback(async () => {
    try {
      const me = await api.me();
      if (me.kind === "system") {
        setAuthEnabled(false);
        setUser({username: me.username || "local", role: "admin"});
      } else {
        setAuthEnabled(true);
        setCsrf(me.csrf_token || "");
        setUser({username: me.username || "", role: me.role || "viewer"});
      }
    } catch {
      // 401 -> auth is on but we're not logged in
      setAuthEnabled(true);
      setUser(null);
    } finally {
      setReady(true);
    }
  }, []);

  useEffect(() => {
    onUnauthorized(() => setUser(null));
    void reload();
  }, [reload]);

  const login = useCallback(async (username: string, password: string) => {
    const r = await api.login(username, password);
    setCsrf(r.csrf_token);
    setAuthEnabled(true);
    setUser({username: r.user.username, role: r.user.role});
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    setCsrf("");
    setUser(null);
  }, []);

  return (
    <AuthCtx.Provider value={{ready, authEnabled, user, login, logout, reload}}>
      {children}
    </AuthCtx.Provider>
  );
}
