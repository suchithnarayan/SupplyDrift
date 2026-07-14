import {ArrowLeft, Boxes, FileWarning, GitBranch, Ghost, Package, Route as RouteIcon, ShieldAlert} from "lucide-react";
import {useState} from "react";
import {Link, useParams} from "react-router-dom";
import {Cell, DataTable, Row} from "../components/ui/DataTable";
import {Pagination} from "../components/ui/Pagination";
import {EmptyState, GlassCard, SeverityPill, Skeleton, Tag} from "../components/ui/primitives";
import {api} from "../lib/api";
import {cn} from "../lib/cn";
import {assetMeta} from "../lib/meta";
import type {AssetDetail as AssetDetailT} from "../lib/types";
import {useFetch, usePaginated} from "../lib/useFetch";

type Tab = "overview" | "components" | "ghost" | "vulnerabilities" | "relationships" | "provenance";

export function AssetDetail() {
  const {id = ""} = useParams();
  const {data, loading} = useFetch(() => api.getAsset(id), [id]);
  const [tab, setTab] = useState<Tab>("overview");

  if (loading && !data) return <Skeleton className="h-96 rounded-2xl" />;
  if (!data) return <EmptyState title="Asset not found" />;

  const meta = assetMeta(data.asset_type);
  const isImage = data.asset_type === "container_image";
  const isRepo = data.asset_type === "repository";
  const provenance = (data.raw_metadata?.provenance as Record<string, unknown>) || null;

  const tabs: {id: Tab; label: string; icon: typeof Package; show: boolean}[] = [
    {id: "overview", label: "Overview", icon: Boxes, show: true},
    {id: "components", label: `Components (${data.component_count})`, icon: Package, show: true},
    // Ghost/shadow dependency findings (non-CVE) — the deps syft misses. For
    // non-repo assets these are other non-CVE findings, so label them "Findings".
    {id: "ghost", label: `${isRepo ? "Ghost deps" : "Findings"} (${data.ghost_finding_count})`,
     icon: isRepo ? Ghost : FileWarning, show: data.ghost_finding_count > 0},
    {id: "vulnerabilities", label: `Vulnerabilities (${data.vuln_count})`, icon: ShieldAlert, show: true},
    {id: "relationships", label: "Relationships", icon: GitBranch, show: data.relationships.length > 0},
    {id: "provenance", label: "Provenance", icon: RouteIcon, show: isImage},
  ];

  return (
    <div className="space-y-5">
      <Link to="/inventory" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink">
        <ArrowLeft className="h-4 w-4" /> Inventory
      </Link>

      <GlassCard>
        <div className="flex items-start gap-4">
          <span className="grid h-12 w-12 place-items-center rounded-xl bg-white/5 ring-1 ring-white/10">
            <meta.icon className={cn("h-6 w-6", meta.accent)} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg font-semibold text-ink">{data.display_name}</h2>
              <Tag>{meta.label}</Tag>
              {(data.tags || []).map((t) => (
                <Tag key={t}>{t}</Tag>
              ))}
            </div>
            <div className="mt-1 truncate font-mono text-xs text-faint">{data.external_id}</div>
            <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted">
              <span>Provider · <span className="text-ink">{data.provider}</span></span>
              <span>Environment · <span className="text-ink">{data.environment || "—"}</span></span>
              <span>Owner · <span className="text-ink">{data.owner || "—"}</span></span>
              <span>Source · <span className="text-ink">{data.connector_name || "—"}</span></span>
            </div>
          </div>
        </div>
      </GlassCard>

      <div className="flex flex-wrap gap-1.5">
        {tabs.filter((t) => t.show).map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm transition",
              tab === t.id ? "bg-white/10 text-ink ring-1 ring-white/15" : "text-muted hover:text-ink",
            )}
          >
            <t.icon className="h-3.5 w-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && <Overview data={data} />}
      {tab === "components" && <Components id={data.id} />}
      {tab === "ghost" && <FindingsTab id={data.id} kind="ghost" isRepo={isRepo} />}
      {tab === "vulnerabilities" && <FindingsTab id={data.id} kind="cve" isRepo={isRepo} />}
      {tab === "relationships" && <Relationships data={data} />}
      {tab === "provenance" && <Provenance details={data.details} provenance={provenance} />}
    </div>
  );
}

function KeyVals({obj}: {obj: Record<string, unknown>}) {
  const entries = Object.entries(obj).filter(([, v]) => v !== "" && v != null && typeof v !== "object");
  if (entries.length === 0) return <EmptyState title="No details" />;
  return (
    <div className="grid gap-x-8 gap-y-2.5 sm:grid-cols-2">
      {entries.map(([k, v]) => (
        <div key={k} className="flex flex-col">
          <span className="text-[11px] uppercase tracking-wide text-faint">{k.replace(/_/g, " ")}</span>
          <span className="break-all font-mono text-sm text-ink">{String(v)}</span>
        </div>
      ))}
    </div>
  );
}

function Overview({data}: {data: AssetDetailT}) {
  return (
    <GlassCard>
      <KeyVals obj={data.details} />
    </GlassCard>
  );
}

function Components({id}: {id: string}) {
  const {items, loading, page, setPage, total, totalPages} = usePaginated(
    (p, l) => api.getAssetComponents(id, p, l),
    [id],
  );
  if (loading && items.length === 0) return <Skeleton className="h-64 rounded-2xl" />;
  if (items.length === 0) return <EmptyState title="No components" />;
  return (
    <div className="space-y-4">
      <DataTable columns={["Package", "Version", "Ecosystem", "Path", "Findings"]}>
        {items.map((c) => (
          <Row key={c.id + (c.evidence_path || "")}>
            <Cell className="font-medium">
              <span className="inline-flex items-center gap-1.5">
                {c.name}
                {c.source === "repo_scan" && (
                  <span
                    title="Found non-traditionally — missed by syft / traditional SBOM scanners"
                    className="inline-flex items-center gap-1 rounded-md bg-violet/15 px-1.5 py-0.5 text-[10px] font-medium text-violet ring-1 ring-violet/25"
                  >
                    <Ghost className="h-3 w-3" /> ghost
                  </span>
                )}
              </span>
            </Cell>
            <Cell className="font-mono text-muted">{c.version || "—"}</Cell>
            <Cell><Tag>{c.ecosystem || "—"}</Tag></Cell>
            <Cell className="max-w-xs truncate font-mono text-[11px] text-faint">{c.evidence_path || "—"}</Cell>
            <Cell>
              {c.finding_count > 0 ? (
                <span className="rounded-md bg-critical/15 px-2 py-0.5 font-mono text-xs text-critical">{c.finding_count}</span>
              ) : (
                <span className="font-mono text-faint">0</span>
              )}
            </Cell>
          </Row>
        ))}
      </DataTable>
      <Pagination page={page} totalPages={totalPages} total={total} onPage={setPage} />
    </div>
  );
}

function FindingsTab({id, kind, isRepo}: {id: string; kind: "cve" | "ghost"; isRepo: boolean}) {
  const {items, loading, page, setPage, total, totalPages} = usePaginated(
    (p, l) => api.getAssetFindings(id, p, l, {kind}),
    [id, kind],
  );
  if (loading && items.length === 0) return <Skeleton className="h-64 rounded-2xl" />;
  if (items.length === 0)
    return (
      <EmptyState
        title={kind === "cve" ? "No vulnerabilities" : isRepo ? "No ghost dependencies" : "No findings"}
        hint={
          kind === "cve"
            ? "CVEs are synced from the scanners (syft → grype)."
            : isRepo
              ? "Non-traditional dependencies (curl|bash, unpinned actions, binary downloads…) the scanner flagged appear here."
              : undefined
        }
      />
    );
  return (
    <div className="space-y-3">
      {items.map((f) => (
        <GlassCard key={f.id}>
          <div className="flex items-start gap-3">
            <SeverityPill severity={f.severity} />
            <div className="flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-mono font-medium text-ink">{f.title}</h3>
                {f.finding_type && <Tag>{f.finding_type}</Tag>}
              </div>
              {f.component_name && (
                <div className="mt-1 text-sm text-muted">
                  Package · <span className="font-medium text-ink">{f.component_name}</span>
                  {f.component_version && <span className="font-mono text-faint"> @ {f.component_version}</span>}
                  {f.component_ecosystem && <span className="ml-1.5 inline-flex"><Tag>{f.component_ecosystem}</Tag></span>}
                </div>
              )}
              {f.description && <p className="mt-1 text-sm text-muted">{f.description}</p>}
              {f.fix_recommendation && (
                <p className="mt-2 rounded-lg bg-good/10 px-3 py-2 text-xs text-good ring-1 ring-good/20">
                  ↳ {f.fix_recommendation}
                </p>
              )}
            </div>
          </div>
        </GlassCard>
      ))}
      <Pagination page={page} totalPages={totalPages} total={total} onPage={setPage} />
    </div>
  );
}

function Relationships({data}: {data: AssetDetailT}) {
  return (
    <DataTable columns={["Source", "Relationship", "Target"]}>
      {data.relationships.map((r, i) => (
        <Row key={i}>
          <Cell className="text-ink">{r.source_name}</Cell>
          <Cell><Tag>{r.relationship_type}</Tag></Cell>
          <Cell className="text-ink">{r.target_name}</Cell>
        </Row>
      ))}
    </DataTable>
  );
}

function Provenance({details, provenance}: {details: Record<string, unknown>; provenance: Record<string, unknown> | null}) {
  const src = provenance || {
    discovery_source: details.discovery_source,
    source_reference: details.source_reference,
  };
  return (
    <div className="space-y-4">
      <GlassCard>
        <div className="mb-3 flex items-center gap-2 text-sm text-muted">
          <RouteIcon className="h-4 w-4 text-brand" /> Where this image came from
        </div>
        <KeyVals obj={src} />
      </GlassCard>
      {provenance?.context ? (
        <GlassCard>
          <div className="mb-3 text-[11px] uppercase tracking-wide text-faint">discovery context</div>
          <pre className="overflow-x-auto rounded-lg bg-black/30 p-3 font-mono text-xs text-muted ring-1 ring-white/5">
            {JSON.stringify(provenance.context, null, 2)}
          </pre>
        </GlassCard>
      ) : null}
    </div>
  );
}
