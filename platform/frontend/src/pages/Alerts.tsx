import {CalendarClock, ExternalLink, Play, ShieldAlert, Slack} from "lucide-react";
import {useCallback, useEffect, useState} from "react";
import {useRefreshKey} from "../App";
import {Cell, DataTable, Row} from "../components/ui/DataTable";
import {Pagination} from "../components/ui/Pagination";
import {EmptyState, GlassCard, Skeleton, Tag} from "../components/ui/primitives";
import {api} from "../lib/api";
import {cn} from "../lib/cn";
import {relativeTime, safeExternalHref} from "../lib/meta";
import type {MalwareSettings, ScanRun} from "../lib/types";
import {useFetch, usePaginated} from "../lib/useFetch";

export function Alerts() {
  const [tab, setTab] = useState<"alerts" | "config">("alerts");
  const {data: settings, reload: reloadSettings} = useFetch(() => api.getMalwareSettings(), []);

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-5 w-5 text-critical" />
        <h1 className="text-lg font-semibold text-ink">Malware Analysis</h1>
        {settings && !settings.malware_enabled && (
          <span className="rounded-md bg-amber-400/10 px-2 py-0.5 text-[11px] font-medium text-amber-300 ring-1 ring-amber-400/20">
            disabled
          </span>
        )}
        <div className="ml-auto flex rounded-lg bg-white/[0.03] p-0.5 ring-1 ring-white/10">
          {(["alerts", "config"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "rounded-md px-3 py-1 text-xs font-medium transition",
                tab === t ? "bg-white/10 text-ink" : "text-muted hover:text-ink",
              )}
            >
              {t === "config" ? "Configuration" : "Alerts"}
            </button>
          ))}
        </div>
      </div>

      {settings?.malware_enabled && <ScheduleStatus settings={settings} />}

      {tab === "alerts" ? (
        <AlertsPane enabled={!!settings?.malware_enabled} />
      ) : settings ? (
        <ConfigPane settings={settings} onSaved={reloadSettings} />
      ) : (
        <Skeleton className="h-64 rounded-2xl" />
      )}
    </div>
  );
}

function untilLabel(iso: string): string {
  const secs = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  if (secs <= 0) return "due now";
  if (secs < 60) return `in ${secs}s`;
  const m = Math.round(secs / 60);
  if (m < 60) return `in ${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return `in ${h}h`;
  return `in ${Math.round(h / 24)}d`;
}

function ScheduleStatus({settings}: {settings: MalwareSettings}) {
  const [run, setRun] = useState<ScanRun | null>(null);
  useEffect(() => {
    api.getLatestMalwareRun().then(setRun).catch(() => {});
  }, []);
  const last = settings.malware_last_run_at;
  const next = settings.malware_next_run_at;
  const nextPast = !!next && new Date(next).getTime() < Date.now();
  return (
    <GlassCard className="flex flex-wrap items-center gap-x-8 gap-y-2 text-sm">
      <div className="flex items-center gap-2">
        <CalendarClock className="h-4 w-4 text-accent" />
        <span className="text-muted">Scheduled</span>
        <span className="font-medium text-ink">every {settings.malware_interval_minutes} min</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-muted">Last scan</span>
        {last ? (
          <span className="text-ink">
            {relativeTime(last)}
            {run?.summary && (
              <span className="ml-1.5 text-faint">
                · {run.summary.new ?? 0} new · {run.summary.active_total ?? run.summary.matched ?? 0} active
              </span>
            )}
          </span>
        ) : (
          <span className="text-faint">never run</span>
        )}
      </div>
      <div className="flex items-center gap-2">
        <span className="text-muted">Next scan</span>
        <span className={cn(nextPast ? "text-amber-300" : "text-ink")}>
          {next ? untilLabel(next) : `within ${settings.malware_interval_minutes} min`}
        </span>
      </div>
    </GlassCard>
  );
}

function SavableField({
  value, onSave, type = "text", width = "w-24", mono, placeholder,
}: {
  value: string | number;
  onSave: (v: string) => Promise<void>;
  type?: string;
  width?: string;
  mono?: boolean;
  placeholder?: string;
}) {
  const [val, setVal] = useState(String(value));
  const [state, setState] = useState<"idle" | "saving" | "saved">("idle");
  useEffect(() => {
    setVal(String(value));
  }, [value]);
  const dirty = val !== String(value);
  const save = async () => {
    setState("saving");
    try {
      await onSave(val);
      setState("saved");
      setTimeout(() => setState("idle"), 2000);
    } catch {
      setState("idle");
    }
  };
  return (
    <div className="flex items-center gap-2">
      <input
        type={type}
        value={val}
        placeholder={placeholder}
        onChange={(e) => setVal(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && dirty) save();
        }}
        className={cn(
          width,
          "rounded-lg border border-white/10 bg-white/[0.03] px-2 py-1.5 text-sm text-ink outline-none focus:border-accent/40",
          mono && "font-mono text-xs",
        )}
      />
      <button
        onClick={save}
        disabled={!dirty || state === "saving"}
        className={cn(
          "rounded-lg px-2.5 py-1.5 text-xs font-medium ring-1 transition",
          state === "saved"
            ? "bg-good/15 text-good ring-good/30"
            : dirty
              ? "bg-brand/15 text-brand ring-brand/30 hover:bg-brand/25"
              : "bg-white/5 text-faint ring-white/10",
        )}
      >
        {state === "saving" ? "Saving…" : state === "saved" ? "Saved ✓" : "Save"}
      </button>
    </div>
  );
}

const STATUSES: [string, string][] = [["active", "Active"], ["", "All"]];

function AlertsPane({enabled}: {enabled: boolean}) {
  const refreshKey = useRefreshKey();
  const [status, setStatus] = useState("active");
  const {items, loading, page, setPage, total, totalPages} = usePaginated(
    (p, l) => api.getAlerts(status, p, l),
    [status, refreshKey],
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        {STATUSES.map(([value, label]) => (
          <button
            key={value || "all"}
            onClick={() => setStatus(value)}
            className={cn(
              "rounded-full px-3 py-1.5 text-xs font-medium ring-1 transition",
              status === value ? "bg-white/10 text-ink ring-white/20" : "bg-white/[0.03] text-muted ring-white/10 hover:text-ink",
            )}
          >
            {label}
          </button>
        ))}
        <div className="ml-auto">
          <RunAnalysis enabled={enabled} />
        </div>
      </div>

      {loading && items.length === 0 ? (
        <Skeleton className="h-64 rounded-2xl" />
      ) : items.length === 0 ? (
        <EmptyState
          title="No malware alerts"
          hint={enabled
            ? "OSV MAL-* advisories matched against your inventory appear here. Hit Run analysis, or wait for the interval."
            : "Malware analysis is off. Enable it in Configuration, then run an analysis."}
        />
      ) : (
        <>
          <DataTable columns={["Advisory", "Package", "Ecosystem", "Affected assets", "Sources", "First seen", "Status"]}>
            {items.map((a) => {
              const advisoryHref = safeExternalHref(a.advisory_url);
              return (
              <Row key={a.id}>
                <Cell>
                  {advisoryHref ? (
                    <a href={advisoryHref} target="_blank" rel="noreferrer"
                       className="inline-flex items-center gap-1 font-mono text-critical hover:underline">
                      {a.advisory_id}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  ) : (
                    <span className="inline-flex items-center gap-1 font-mono text-critical">{a.advisory_id}</span>
                  )}
                </Cell>
                <Cell>
                  <span className="font-medium text-ink">{a.package}</span>
                  <span className="ml-1.5 font-mono text-faint">@{a.version}</span>
                  {a.alert_count <= 1 && (
                    <span className="ml-2 rounded bg-critical/20 px-1.5 py-0.5 text-[10px] font-semibold text-critical">NEW</span>
                  )}
                </Cell>
                <Cell><Tag>{a.ecosystem || "—"}</Tag></Cell>
                <Cell className="font-mono">{a.asset_count}</Cell>
                <Cell className="text-[12px] text-muted">{a.sources.join(", ") || "—"}</Cell>
                <Cell className="text-[12px] text-faint">{relativeTime(a.first_alerted_at)}</Cell>
                <Cell><Tag>{a.status}</Tag></Cell>
              </Row>
              );
            })}
          </DataTable>
          <Pagination page={page} totalPages={totalPages} total={total} onPage={setPage} />
        </>
      )}
    </div>
  );
}

const RUN_LABEL: Record<string, string> = {queued: "queued", running: "running…", failed: "failed", canceled: "canceled"};

function RunAnalysis({enabled}: {enabled: boolean}) {
  const [run, setRun] = useState<ScanRun | null>(null);
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => {
    try {
      setRun(await api.getLatestMalwareRun());
    } catch {
      /* ignore */
    }
  }, []);
  useEffect(() => {
    refresh();
  }, [refresh]);
  const active = run?.status === "queued" || run?.status === "running";
  useEffect(() => {
    if (!active) return;
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [active, refresh]);

  const go = async () => {
    setBusy(true);
    try {
      setRun(await api.triggerMalwareScan());
    } finally {
      setBusy(false);
    }
  };

  let badge: string | null = run ? RUN_LABEL[run.status] || null : null;
  if (run?.status === "succeeded") badge = `✓ ${run.summary.new ?? 0} new · ${run.summary.active_total ?? 0} active`;

  return (
    <div className="flex items-center gap-2">
      {badge && <span className="whitespace-nowrap text-[11px] text-faint">{badge}</span>}
      <button
        onClick={go}
        disabled={busy || active || !enabled}
        title={enabled ? "Queue a malware analysis run" : "Enable malware analysis in Configuration first"}
        className="inline-flex items-center gap-1.5 rounded-lg bg-brand/15 px-3 py-1.5 text-sm text-brand ring-1 ring-brand/30 hover:bg-brand/25 disabled:opacity-50"
      >
        <Play className="h-3.5 w-3.5" />
        {active ? "Running…" : "Run analysis"}
      </button>
    </div>
  );
}

function Toggle({on, onClick}: {on: boolean; onClick: () => void}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "relative h-5 w-9 rounded-full ring-1 transition",
        on ? "bg-good/30 ring-good/40" : "bg-white/5 ring-white/10",
      )}
    >
      <span className={cn("absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all", on ? "left-4" : "left-0.5")} />
    </button>
  );
}

function ConfigPane({settings, onSaved}: {settings: MalwareSettings; onSaved: () => void}) {
  const [saving, setSaving] = useState(false);
  const save = async (patch: Partial<MalwareSettings>) => {
    setSaving(true);
    try {
      await api.updateMalwareSettings(patch);
      onSaved();
    } finally {
      setSaving(false);
    }
  };
  const d = settings;

  return (
    <GlassCard className="space-y-6">
      {/* master switch */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-sm font-medium text-ink">Enable malware analysis</div>
          <p className="mt-0.5 max-w-lg text-xs text-faint">
            Checks your ingested packages against OSV's curated malicious-package (MAL-*) feed on an interval.
            A separate malware runner does the OSV fetch.
          </p>
        </div>
        <Toggle on={d.malware_enabled} onClick={() => save({malware_enabled: !d.malware_enabled})} />
      </div>

      <div className={cn("space-y-6 border-t border-white/8 pt-5", !d.malware_enabled && "pointer-events-none opacity-40")}>
        {/* platform alerts (default on) */}
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="text-sm text-ink">Platform alerts</div>
            <p className="text-xs text-faint">In-app alerts on the Alerts tab. On by default.</p>
          </div>
          <Toggle on={d.platform_alerts_enabled} onClick={() => save({platform_alerts_enabled: !d.platform_alerts_enabled})} />
        </div>

        {/* interval */}
        <div className="flex items-center justify-between gap-4 text-sm text-ink">
          <div>
            <div>Scan interval</div>
            <p className="text-xs text-faint">Minutes between automatic analyses. Click Save to apply.</p>
          </div>
          <SavableField type="number" width="w-24" value={d.malware_interval_minutes}
            onSave={(v) => save({malware_interval_minutes: Math.max(1, Number(v) || 60)})} />
        </div>

        {/* Slack (optional) */}
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Slack className="h-4 w-4 text-brand" />
              <div>
                <div className="text-sm text-ink">Slack alerts <span className="text-faint">(optional)</span></div>
                <p className="text-xs text-faint">Notify a channel when new malware is found.</p>
              </div>
            </div>
            <Toggle on={d.slack_enabled} onClick={() => save({slack_enabled: !d.slack_enabled})} />
          </div>
          {d.slack_enabled && (
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 pl-6">
              <div className="flex items-center gap-2 text-xs text-muted">
                webhook env
                <SavableField mono width="w-52" value={d.slack_webhook_env}
                  onSave={(v) => save({slack_webhook_env: v})} />
                <span className={cn(d.slack_webhook_configured ? "text-good" : "text-faint")}>
                  {d.slack_webhook_configured ? "✓ set" : "unset"}
                </span>
              </div>
              <div className="flex items-center gap-2 text-xs text-muted">
                channel
                <SavableField width="w-36" value={d.slack_channel} placeholder="#security"
                  onSave={(v) => save({slack_channel: v})} />
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center justify-between border-t border-white/8 pt-4 text-xs text-faint">
        <span>{d.malware_last_run_at ? `last analysis ${relativeTime(d.malware_last_run_at)}` : "never run"}</span>
        <span>{saving ? "saving…" : "toggles apply instantly · fields use Save"}</span>
      </div>
    </GlassCard>
  );
}
