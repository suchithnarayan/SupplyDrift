import {AnimatePresence, motion} from "framer-motion";
import {Code2, Pencil, Play, Plus, RefreshCw, Search, Square, Trash2, X} from "lucide-react";
import {useCallback, useEffect, useState} from "react";
import {useRefreshKey} from "../App";
import {useToast} from "../components/ui/Toast";
import {Button, EmptyState, GlassCard, Skeleton, StatusPill, Tag} from "../components/ui/primitives";
import {Select} from "../components/ui/Select";
import {api} from "../lib/api";
import {cn} from "../lib/cn";
import {relativeTime} from "../lib/meta";
import type {Connector, ScanRun} from "../lib/types";
import {useFetch} from "../lib/useFetch";

const RUN_STYLE: Record<string, {dot: string; text: string}> = {
  queued: {dot: "bg-amber-300", text: "text-amber-300"},
  running: {dot: "bg-accent animate-pulse", text: "text-accent"},
  succeeded: {dot: "bg-good", text: "text-good"},
  failed: {dot: "bg-critical", text: "text-critical"},
  canceled: {dot: "bg-muted", text: "text-muted"},
};

function runStatusText(run: ScanRun): string {
  const s = run.summary || {};
  const action = s.action === "refresh" ? "refresh" : "scan";
  const n = (key: string) => Number(s[key] ?? 0);
  switch (run.status) {
    case "queued":
      if (run.runner_available === false) return "Queued — no runner connected";
      if (run.runner_busy) return "Queued — runner busy, runs next";
      return action === "refresh" ? "Queued — refresh waiting" : "Queued — scan waiting";
    case "running":
      return action === "refresh" ? "Refreshing inventory…" : "Scanning components…";
    case "succeeded": {
      if (action === "refresh") {
        return `${n("discovered")} discovered · inventory refreshed`;
      }
      const parts = [`${n("scanned_ok")} scanned`, `${n("total_components")} components`];
      if (s.total_vulnerabilities != null) parts.push(`${n("total_vulnerabilities")} vulns`);
      else if (s.total_findings != null) parts.push(`${n("total_findings")} findings`);
      return parts.join(" · ");
    }
    case "failed":
      return run.error || "Scan failed";
    case "canceled":
      return run.error || "Scan canceled";
    default:
      return run.status;
  }
}

function ConnectorCard({connector, onEdit, onRemove}: {
  connector: Connector;
  onEdit: () => void;
  onRemove: () => void;
}) {
  const c = connector;
  const toast = useToast();
  const [run, setRun] = useState<ScanRun | null>(null);
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => {
    try {
      setRun(await api.getConnectorScanLatest(c.id));
    } catch {
      /* ignore */
    }
  }, [c.id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const active = run?.status === "queued" || run?.status === "running";

  useEffect(() => {
    if (!active) return;
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [active, refresh]);

  const scan = async () => {
    setBusy(true);
    try {
      const r = await api.triggerConnectorScan(c.id);
      setRun(r);
      if (r.runner_available === false) {
        toast(r.warning || "No runner is connected to claim this scan.", "error");
      }
    } finally {
      setBusy(false);
    }
  };

  const refreshInventory = async () => {
    setBusy(true);
    try {
      const r = await api.triggerConnectorRefresh(c.id);
      setRun(r);
      if (r.runner_available === false) {
        toast(r.warning || "No runner is connected to refresh this source.", "error");
      }
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    try {
      setRun(await api.cancelConnectorScan(c.id));
      toast("Scan stopped.", "success");
    } catch {
      toast("Could not stop the scan.", "error");
    } finally {
      setBusy(false);
    }
  };

  const style = run ? RUN_STYLE[run.status] : null;

  return (
    <GlassCard className="flex flex-col gap-2.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-medium text-ink">{c.name}</span>
            <Tag>{c.config.source_type}</Tag>
            <StatusPill status={c.config.enabled ? "enabled" : "disabled"} />
          </div>
          <div className="mt-1 text-xs capitalize text-faint">
            {c.config.kind} · updated {relativeTime(c.updated_at)}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {active ? (
            <button
              onClick={stop}
              disabled={busy}
              title="Stop this run (cancel the queued/running refresh or scan)"
              className="inline-flex items-center gap-1 rounded-lg bg-critical/15 px-2.5 py-1.5 text-xs font-medium text-critical ring-1 ring-critical/30 hover:bg-critical/25 disabled:opacity-50"
            >
              <Square className="h-3.5 w-3.5" />
              Stop
            </button>
          ) : (
            <>
              <button
                onClick={refreshInventory}
                disabled={busy}
                title="Refresh source inventory without scanning components"
                className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-white/[0.04] text-muted ring-1 ring-white/10 hover:bg-white/[0.08] hover:text-ink disabled:opacity-50"
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={scan}
                disabled={busy}
                title="Scan discovered components and vulnerabilities"
                className="inline-flex items-center gap-1 rounded-lg bg-brand/15 px-2.5 py-1.5 text-xs font-medium text-brand ring-1 ring-brand/30 hover:bg-brand/25 disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5" />
                Scan
              </button>
            </>
          )}
          <button onClick={onEdit} title="Edit" className="rounded-lg p-2 text-muted hover:bg-white/5 hover:text-ink">
            <Pencil className="h-4 w-4" />
          </button>
          <button onClick={onRemove} title="Remove" className="rounded-lg p-2 text-muted hover:bg-critical/10 hover:text-critical">
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      </div>

      {run && style && (
        <div className="flex items-center gap-2 border-t border-white/8 pt-2.5 text-xs">
          <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", style.dot)} />
          <span className={cn("min-w-0 truncate", style.text)} title={runStatusText(run)}>
            {runStatusText(run)}
          </span>
          {run.finished_at && (
            <span className="ml-auto shrink-0 text-faint">{relativeTime(run.finished_at)}</span>
          )}
        </div>
      )}
    </GlassCard>
  );
}

interface Field {
  path: string;
  label: string;
  placeholder?: string;
  list?: boolean;
  secret?: boolean;
}

const FORMS: Record<string, {kind: "registry" | "service" | "repo"; fields: Field[]}> = {
  dockerhub: {kind: "registry", fields: [
    {path: "connection.images", label: "Public images (no auth)", list: true, placeholder: "library/nginx:1.27, alpine:3.19"},
    {path: "connection.namespaces", label: "Namespaces (auto-list, optional)", list: true, placeholder: "acme, acme-internal"},
    {path: "connection.auth.username", label: "Username (optional)", placeholder: "docker-hub-user"},
    {path: "connection.auth.password", label: "Password / access token (optional)", secret: true, placeholder: "••••••••"},
    {path: "scan.repositories", label: "Repositories (glob)", list: true, placeholder: "*"},
  ]},
  ghcr: {kind: "registry", fields: [
    {path: "connection.images", label: "Public images (no token)", list: true, placeholder: "owner/repo:tag"},
    {path: "connection.owner", label: "Owner (org/user, for auto-list)", placeholder: "acme"},
    {path: "connection.owner_type", label: "Owner type", placeholder: "org"},
    {path: "connection.auth.username", label: "Username (optional)", placeholder: "gh-user"},
    {path: "connection.auth.token", label: "Classic PAT (read:packages)", secret: true, placeholder: "ghp_••••••"},
    {path: "scan.repositories", label: "Repositories (glob)", list: true, placeholder: "acme/*"},
  ]},
  harbor: {kind: "registry", fields: [
    {path: "connection.url", label: "Harbor URL", placeholder: "https://harbor.acme.io"},
    {path: "connection.images", label: "Public images (no auth)", list: true, placeholder: "project/repo:tag"},
    {path: "connection.auth.username", label: "Robot name (optional)", placeholder: "robot$scanner"},
    {path: "connection.auth.password", label: "Secret (optional)", secret: true, placeholder: "••••••••"},
    {path: "scan.projects", label: "Projects (glob)", list: true, placeholder: "team-*"},
  ]},
  ecr: {kind: "registry", fields: [
    {path: "connection.aws_auth.profile", label: "AWS profile", placeholder: "prod"},
    {path: "connection.aws_auth.role_arn", label: "Assume role ARN (optional)", placeholder: "arn:aws:iam::123:role/Scanner"},
    {path: "connection.aws_auth.regions", label: "Regions", list: true, placeholder: "us-east-1, eu-west-1"},
    {path: "connection.account_id", label: "Account ID (optional)", placeholder: "123456789012"},
    {path: "scan.repositories", label: "Repositories (glob)", list: true, placeholder: "payments/*"},
  ]},
  kubernetes: {kind: "service", fields: [
    {path: "connection.kubeconfig", label: "Kubeconfig path", placeholder: "~/.kube/config"},
    {path: "connection.contexts", label: "Contexts (glob)", list: true, placeholder: "*"},
    {path: "connection.from_json", label: "Cluster dump JSON", placeholder: "/path/to/kubectl-get-all.json"},
    {path: "connection.manifests", label: "Manifest directory", placeholder: "/path/to/manifests"},
    {path: "connection.cluster_name", label: "Cluster name override", placeholder: "docker-desktop"},
    {path: "discovery.namespaces", label: "Namespaces", list: true, placeholder: "*"},
    {path: "discovery.object_kinds", label: "Object kinds", list: true, placeholder: "Deployment, StatefulSet, DaemonSet, CronJob, Job, Pod"},
  ]},
  eks: {kind: "service", fields: [
    {path: "connection.aws_auth.profile", label: "AWS profile", placeholder: "prod"},
    {path: "connection.aws_auth.role_arn", label: "Assume role ARN (optional)"},
    {path: "connection.aws_auth.regions", label: "Regions", list: true, placeholder: "us-east-1"},
    {path: "connection.clusters", label: "Clusters (glob)", list: true, placeholder: "*"},
  ]},
  ecs: {kind: "service", fields: [
    {path: "connection.aws_auth.profile", label: "AWS profile", placeholder: "prod"},
    {path: "connection.aws_auth.regions", label: "Regions", list: true, placeholder: "us-east-1"},
    {path: "connection.clusters", label: "Clusters (glob)", list: true, placeholder: "*"},
  ]},
  github: {kind: "repo", fields: [
    {path: "connection.repositories", label: "Public repos (no token)", list: true, placeholder: "octocat/Hello-World, owner/repo"},
    {path: "connection.owner", label: "Owner — org/user (for auto-list)", placeholder: "acme"},
    {path: "connection.owner_type", label: "Owner type", placeholder: "org"},
    {path: "connection.visibility", label: "Visibility", placeholder: "all | public | private"},
    {path: "connection.auth.token", label: "Classic PAT (optional)", secret: true, placeholder: "ghp_••••••"},
    {path: "scan.repositories", label: "Repo name globs", list: true, placeholder: "*"},
  ]},
};

function setPath(obj: Record<string, unknown>, path: string, value: unknown) {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    cur[parts[i]] = (cur[parts[i]] as Record<string, unknown>) || {};
    cur = cur[parts[i]] as Record<string, unknown>;
  }
  cur[parts[parts.length - 1]] = value;
}
function getPath(obj: Record<string, unknown> | undefined, path: string): unknown {
  return path.split(".").reduce<unknown>((o, k) => (o == null ? undefined : (o as Record<string, unknown>)[k]), obj);
}

export function Sources() {
  const refreshKey = useRefreshKey();
  const [bump, setBump] = useState(0);
  const {data, loading} = useFetch(() => api.listConnectors(), [refreshKey, bump]);
  const [editing, setEditing] = useState<Connector | "new" | null>(null);
  const [showConfig, setShowConfig] = useState<string | null>(null);
  const [typeF, setTypeF] = useState("");
  const [statusF, setStatusF] = useState("");
  const [searchF, setSearchF] = useState("");
  const toast = useToast();

  const configured = (data || []).filter((c) => FORMS[c.config?.source_type]);
  const sourceTypes = Array.from(new Set(configured.map((c) => c.config?.source_type).filter(Boolean)));
  const filtered = configured.filter((c) => {
    const enabled = c.config?.enabled ?? true;
    if (typeF && c.config?.source_type !== typeF) return false;
    if (statusF === "enabled" && !enabled) return false;
    if (statusF === "disabled" && enabled) return false;
    if (searchF && !`${c.name} ${c.config?.source_type || ""}`.toLowerCase().includes(searchF.toLowerCase()))
      return false;
    return true;
  });

  const remove = async (c: Connector) => {
    await api.deleteConnector(c.id);
    toast("Source removed", "success");
    setBump((b) => b + 1);
  };

  const exportConfig = async () => {
    const cfg = await api.getScannerConfig();
    setShowConfig(JSON.stringify(cfg, null, 2));
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <p className="max-w-xl text-sm text-muted">
          Connect registries and runtime services. Secret values are stored <span className="text-ink">encrypted</span> and
          masked in the browser. Runner tokens fetch plaintext through <code className="text-accent">/api/scanner/config</code>.
        </p>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={exportConfig}><Code2 className="h-4 w-4" /> Export config</Button>
          <Button onClick={() => setEditing("new")}><Plus className="h-4 w-4" /> Add source</Button>
        </div>
      </div>

      {configured.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
            <input
              value={searchF}
              onChange={(e) => setSearchF(e.target.value)}
              placeholder="Search sources…"
              className="w-56 rounded-xl border border-white/10 bg-white/[0.03] py-2 pl-9 pr-3 text-sm text-ink outline-none placeholder:text-faint focus:border-accent/40"
            />
          </div>
          <div className="w-40">
            <Select
              value={typeF}
              onChange={setTypeF}
              placeholder="Type"
              options={[{value: "", label: "All types"}, ...sourceTypes.map((t) => ({value: t, label: t}))]}
            />
          </div>
          <div className="flex rounded-lg bg-white/[0.03] p-0.5 ring-1 ring-white/10">
            {[["", "All"], ["enabled", "Enabled"], ["disabled", "Disabled"]].map(([val, label]) => (
              <button
                key={val || "all"}
                onClick={() => setStatusF(val)}
                className={cn(
                  "rounded-md px-2.5 py-1 text-xs font-medium transition",
                  statusF === val ? "bg-white/10 text-ink" : "text-muted hover:text-ink",
                )}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      )}

      {loading && !data ? (
        <Skeleton className="h-48 rounded-2xl" />
      ) : configured.length === 0 ? (
        <EmptyState title="No sources configured" hint="Add a registry or service to scan." />
      ) : filtered.length === 0 ? (
        <EmptyState title="No sources match" hint="Adjust the filters above." />
      ) : (
        <div className="grid items-start gap-3 md:grid-cols-2">
          {filtered.map((c) => (
            <ConnectorCard key={c.id} connector={c} onEdit={() => setEditing(c)} onRemove={() => remove(c)} />
          ))}
        </div>
      )}

      <AnimatePresence>
        {editing && (
          <SourceSheet
            connector={editing === "new" ? null : editing}
            onClose={() => setEditing(null)}
            onSaved={() => {
              setEditing(null);
              setBump((b) => b + 1);
              toast("Source saved", "success");
            }}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showConfig && (
          <motion.div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
            initial={{opacity: 0}} animate={{opacity: 1}} exit={{opacity: 0}} onClick={() => setShowConfig(null)}
          >
            <motion.div className="glass max-h-[80vh] w-full max-w-2xl overflow-auto p-5"
              initial={{scale: 0.96, opacity: 0}} animate={{scale: 1, opacity: 1}} exit={{scale: 0.96, opacity: 0}}
              onClick={(e) => e.stopPropagation()}>
              <div className="mb-3 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-ink">GET /api/scanner/config</h3>
                <button onClick={() => setShowConfig(null)} className="text-faint hover:text-ink"><X className="h-4 w-4" /></button>
              </div>
              <pre className="overflow-auto rounded-lg bg-black/30 p-4 font-mono text-xs text-muted ring-1 ring-white/5">{showConfig}</pre>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function SourceSheet({connector, onClose, onSaved}: {connector: Connector | null; onClose: () => void; onSaved: () => void}) {
  const toast = useToast();
  const [name, setName] = useState(connector?.name || "");
  const [sourceType, setSourceType] = useState(connector?.config?.source_type || "ghcr");
  const [enabled, setEnabled] = useState(connector?.config?.enabled ?? true);
  const [values, setValues] = useState<Record<string, string>>(() => {
    const init: Record<string, string> = {};
    const form = FORMS[connector?.config?.source_type || "ghcr"];
    const cfg = connector?.config as Record<string, unknown> | undefined;
    form?.fields.forEach((f) => {
      const v = getPath(cfg, f.path);
      init[f.path] = Array.isArray(v) ? (v as string[]).join(", ") : v != null ? String(v) : "";
    });
    return init;
  });
  const [saving, setSaving] = useState(false);

  const form = FORMS[sourceType];

  const onTypeChange = (t: string) => {
    setSourceType(t);
    setValues({});
  };

  const save = async () => {
    setSaving(true);
    const connection: Record<string, unknown> = {};
    const scan: Record<string, unknown> = {};
    const discovery: Record<string, unknown> = {};
    form.fields.forEach((f) => {
      const raw = (values[f.path] || "").trim();
      if (!raw) return;
      const value: unknown = f.list ? raw.split(",").map((s) => s.trim()).filter(Boolean) : raw;
      let target: Record<string, unknown>;
      let key: string;
      if (f.path.startsWith("scan.")) {
        target = scan;
        key = f.path.slice("scan.".length);
      } else if (f.path.startsWith("discovery.")) {
        target = discovery;
        key = f.path.slice("discovery.".length);
      } else if (f.path.startsWith("connection.")) {
        target = connection;
        key = f.path.slice("connection.".length);
      } else {
        target = connection;
        key = f.path;
      }
      setPath(target, key, value);
    });
    // mark env-based registry auth
    const auth = connection.auth as Record<string, unknown> | undefined;
    if (auth && Object.keys(auth).length) auth.provider = "env";

    const body = {name: name || sourceType, source_type: sourceType, kind: form.kind, enabled, connection, scan, discovery};
    try {
      await api.saveConnector(body, connector?.id);
      onSaved();
    } catch (e) {
      toast((e as Error).message, "error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <motion.div className="fixed inset-0 z-50 flex justify-end bg-black/55"
      initial={{opacity: 0}} animate={{opacity: 1}} exit={{opacity: 0}} onClick={onClose}>
      <motion.div className="h-full w-full max-w-md overflow-y-auto border-l border-white/10 bg-[#080c18] p-6"
        initial={{x: 40, opacity: 0.5}} animate={{x: 0, opacity: 1}} exit={{x: 40, opacity: 0}}
        transition={{type: "spring", stiffness: 320, damping: 34}} onClick={(e) => e.stopPropagation()}>
        <div className="mb-5 flex items-center justify-between">
          <h2 className="text-base font-semibold text-ink">{connector ? "Edit source" : "Add source"}</h2>
          <button onClick={onClose} className="text-faint hover:text-ink"><X className="h-5 w-5" /></button>
        </div>

        <div className="space-y-4">
          <Labeled label="Name">
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="ghcr-acme" className={inputCls} />
          </Labeled>
          <Labeled label="Source type">
            <Select
              value={sourceType}
              onChange={onTypeChange}
              disabled={!!connector}
              options={Object.keys(FORMS).map((t) => ({value: t, label: t}))}
            />
          </Labeled>

          {form.kind === "registry" && (
            <p className="rounded-lg bg-white/[0.03] px-3 py-2 text-[11px] leading-relaxed text-faint ring-1 ring-white/8">
              Leave credentials blank to scan <span className="text-muted">public images anonymously</span> — list
              explicit images, or set namespaces/owner to auto-list public repos. (Public GHCR needs the explicit list.)
            </p>
          )}
          {form.kind === "repo" && (
            <p className="rounded-lg bg-white/[0.03] px-3 py-2 text-[11px] leading-relaxed text-faint ring-1 ring-white/8">
              Leave the PAT blank to scan <span className="text-muted">public repos anonymously</span> — list explicit
              public repos, or set an owner to auto-list. A classic PAT is needed only for private repos.
            </p>
          )}

          {form.fields.map((f) => {
            const leaf = f.path.split(".").pop() || f.path;
            const configured = f.secret && (connector?.secrets_configured || []).includes(leaf);
            return (
              <Labeled
                key={f.path}
                label={f.label}
                hint={f.secret ? (configured ? "stored encrypted — leave blank to keep" : "stored encrypted") : undefined}
              >
                <input
                  type={f.secret ? "password" : "text"}
                  value={values[f.path] || ""}
                  onChange={(e) => setValues((v) => ({...v, [f.path]: e.target.value}))}
                  placeholder={configured ? "•••••••• (configured)" : f.placeholder}
                  className={cn(inputCls, f.secret && "font-mono")}
                />
              </Labeled>
            );
          })}

          <label className="flex items-center gap-2 text-sm text-muted">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="accent-brand" />
            Enabled (included in scanner config)
          </label>

          <div className="flex gap-2 pt-2">
            <Button onClick={save} disabled={saving} className="flex-1 justify-center">{saving ? "Saving…" : "Save source"}</Button>
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}

const inputCls =
  "w-full rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-ink outline-none placeholder:text-faint focus:border-accent/40";

function Labeled({label, hint, children}: {label: string; hint?: string; children: React.ReactNode}) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs font-medium text-muted">{label}</span>
        {hint && <span className="text-[10px] text-faint">{hint}</span>}
      </div>
      {children}
    </div>
  );
}
