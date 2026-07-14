import {AnimatePresence, motion} from "framer-motion";
import {createContext, useContext, useState, type ReactNode} from "react";
import {BrowserRouter, Route, Routes, useLocation} from "react-router-dom";
import {AppShell} from "./components/layout/AppShell";
import {ToastProvider} from "./components/ui/Toast";
import {fadeUp} from "./components/ui/primitives";
import {AuthProvider, useAuth} from "./lib/auth";
import {Admin} from "./pages/Admin";
import {Alerts} from "./pages/Alerts";
import {Analyzer} from "./pages/Analyzer";
import {AssetDetail} from "./pages/AssetDetail";
import {Dashboard} from "./pages/Dashboard";
import {Endpoints} from "./pages/Endpoints";
import {Inventory} from "./pages/Inventory";
import {Login} from "./pages/Login";
import {Sources} from "./pages/Sources";
import {Vulnerabilities} from "./pages/Vulnerabilities";

const RefreshContext = createContext(0);
export const useRefreshKey = () => useContext(RefreshContext);

function PageMotion({children}: {children: ReactNode}) {
  return (
    <motion.div {...fadeUp} transition={{duration: 0.35, ease: [0.22, 1, 0.36, 1]}}>
      {children}
    </motion.div>
  );
}

function Shell() {
  const [refreshKey, setRefreshKey] = useState(0);
  const location = useLocation();

  return (
    <RefreshContext.Provider value={refreshKey}>
      <AppShell onRefresh={() => setRefreshKey((k) => k + 1)}>
        <AnimatePresence mode="wait">
          <Routes location={location} key={location.pathname}>
            <Route path="/" element={<PageMotion><Dashboard /></PageMotion>} />
            <Route path="/inventory" element={<PageMotion><Inventory /></PageMotion>} />
            <Route path="/inventory/:id" element={<PageMotion><AssetDetail /></PageMotion>} />
            <Route path="/endpoints" element={<PageMotion><Endpoints /></PageMotion>} />
            <Route path="/analyzer" element={<PageMotion><Analyzer /></PageMotion>} />
            <Route path="/vulnerabilities" element={<PageMotion><Vulnerabilities /></PageMotion>} />
            <Route path="/alerts" element={<PageMotion><Alerts /></PageMotion>} />
            <Route path="/sources" element={<PageMotion><Sources /></PageMotion>} />
            <Route path="/admin" element={<PageMotion><Admin /></PageMotion>} />
          </Routes>
        </AnimatePresence>
      </AppShell>
    </RefreshContext.Provider>
  );
}

function Gate() {
  const {ready, user} = useAuth();
  if (!ready) {
    return (
      <div className="grid min-h-screen place-items-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-white/15 border-t-brand" />
      </div>
    );
  }
  return user ? <Shell /> : <Login />;
}

export function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <BrowserRouter>
          <Gate />
        </BrowserRouter>
      </AuthProvider>
    </ToastProvider>
  );
}
