import {Boxes, Ghost, Package, ScanLine, ShieldAlert, Siren} from "lucide-react";
import {Link} from "react-router-dom";
import {useRefreshKey} from "../App";
import {SeverityBars, SourceDonut} from "../components/charts/Charts";
import {Metric} from "../components/ui/Metric";
import {EmptyState, GlassCard, SectionTitle, SeverityPill, Skeleton, StaggerItem, Stagger} from "../components/ui/primitives";
import {api} from "../lib/api";
import {relativeTime} from "../lib/meta";
import {useFetch} from "../lib/useFetch";

export function Dashboard() {
  const refreshKey = useRefreshKey();
  const {data, loading} = useFetch(() => api.getSummary(), [refreshKey]);

  if (loading && !data) {
    return (
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {Array.from({length: 4}).map((_, i) => (
          <Skeleton key={i} className="h-28 rounded-2xl" />
        ))}
      </div>
    );
  }
  if (!data) return null;

  const vuln = data.vulnerability_status.vulnerable_packages ?? 0;

  return (
    <div className="space-y-6">
      {data.malware.active > 0 && (
        <Link
          to="/alerts"
          className="flex items-center gap-3 rounded-2xl border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-critical ring-1 ring-critical/20 transition hover:bg-critical/15"
        >
          <Siren className="h-5 w-5 shrink-0" />
          <span className="font-semibold">
            {data.malware.active} malicious package{data.malware.active === 1 ? "" : "s"} detected in your SBOM
          </span>
          <span className="ml-auto text-xs text-critical/80">View alerts →</span>
        </Link>
      )}
      <Stagger className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          {icon: ScanLine, label: "Scanned", value: data.scan.scanned, note: `${data.scan.pending} pending · ${data.scan.total} identified`, accent: "text-brand"},
          {icon: Boxes, label: "Assets", value: data.assets.total, note: `${data.assets.stale} stale`, accent: "text-accent"},
          {icon: Package, label: "Packages", value: data.components.total, note: "distinct components", accent: "text-violet"},
          {icon: ShieldAlert, label: "Vulnerable", value: vuln, note: "packages with CVEs", accent: "text-critical"},
        ].map((m) => (
          <StaggerItem key={m.label}>
            <Metric {...m} />
          </StaggerItem>
        ))}
      </Stagger>

      {data.ghost.repo_packages > 0 && (
        <Link
          to="/inventory?asset_type=repository"
          className="flex flex-col gap-3 rounded-2xl border border-violet/30 bg-violet/[0.06] px-5 py-4 ring-1 ring-violet/10 transition hover:bg-violet/[0.1] sm:flex-row sm:items-center"
        >
          <div className="flex items-center gap-4">
            <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-violet/15 ring-1 ring-violet/25">
              <Ghost className="h-6 w-6 text-violet" />
            </span>
            <div className="leading-none">
              <div className="text-3xl font-semibold text-violet">{data.ghost.percent}%</div>
              <div className="mt-1 text-xs font-medium uppercase tracking-wide text-violet/80">Ghost dependencies</div>
            </div>
          </div>
          <p className="text-sm text-muted sm:ml-2">
            <span className="font-semibold text-ink">{data.ghost.ghost_packages}</span> of{" "}
            <span className="font-semibold text-ink">{data.ghost.repo_packages}</span> repository packages are
            installed <span className="text-ink">non-traditionally</span> (curl&nbsp;|&nbsp;bash, unpinned
            actions, vendored binaries, direct downloads…) — ground truth that traditional SBOM
            scanners miss entirely.
          </p>
        </Link>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <GlassCard className="lg:col-span-1">
          <SectionTitle title="Source mix" sub="Where ground truth comes from" />
          <SourceDonut byType={data.assets.by_type} />
        </GlassCard>

        <GlassCard className="lg:col-span-2">
          <SectionTitle title="Findings by severity" sub="Across the supply chain" />
          <div className="pt-2">
            <SeverityBars bySeverity={data.findings.by_severity} />
          </div>
        </GlassCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <GlassCard className="lg:col-span-2">
          <SectionTitle title="Top packages" sub="By asset reach" />
          <div className="space-y-1">
            {data.components.top.length === 0 && <EmptyState title="No packages yet" />}
            {data.components.top.slice(0, 8).map((c) => (
              <div key={c.id} className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-white/[0.03]">
                <span className="grid h-7 w-7 place-items-center rounded-md bg-white/5 text-[10px] uppercase text-faint ring-1 ring-white/10">
                  {c.ecosystem.slice(0, 3)}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm text-ink">{c.name}</div>
                  <div className="truncate font-mono text-[11px] text-faint">{c.version}</div>
                </div>
                <span className="rounded-md bg-white/5 px-2 py-0.5 font-mono text-xs text-muted">{c.asset_count}</span>
              </div>
            ))}
          </div>
        </GlassCard>

        <GlassCard className="lg:col-span-3">
          <SectionTitle title="Latest findings" sub="Most recent across all sources" right={<Link to="/vulnerabilities" className="text-xs text-accent hover:underline">View all →</Link>} />
          <div className="space-y-1">
            {data.findings.latest.length === 0 && <EmptyState title="No findings" />}
            {data.findings.latest.slice(0, 6).map((f) => (
              <div key={f.id} className="flex items-center gap-3 rounded-lg px-2 py-2.5 hover:bg-white/[0.03]">
                <SeverityPill severity={f.severity} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm text-ink">{f.title}</div>
                  <div className="truncate text-[11px] text-faint">{f.asset_name || f.finding_type}</div>
                </div>
                <span className="shrink-0 text-[11px] text-faint">{relativeTime(f.last_seen_at)}</span>
              </div>
            ))}
          </div>
        </GlassCard>
      </div>
    </div>
  );
}
