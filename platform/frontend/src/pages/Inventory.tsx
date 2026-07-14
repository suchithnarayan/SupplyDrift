import {Search} from "lucide-react";
import {useState} from "react";
import {useNavigate} from "react-router-dom";
import {useRefreshKey} from "../App";
import {Cell, DataTable, Row} from "../components/ui/DataTable";
import {Pagination} from "../components/ui/Pagination";
import {Select} from "../components/ui/Select";
import {EmptyState, Skeleton, Tag} from "../components/ui/primitives";
import {api} from "../lib/api";
import {cn} from "../lib/cn";
import {ASSET_TYPES, assetMeta, relativeTime} from "../lib/meta";
import {usePaginated} from "../lib/useFetch";

const CHIPS = ["", ...Object.keys(ASSET_TYPES)];
const SCAN_FILTERS: [string, string][] = [["", "All"], ["scanned", "Scanned"], ["discovered", "Pending"]];
const PROVIDERS = ["", "github", "gitlab", "docker_hub", "github_ghcr", "aws_ecr", "harbor",
  "quay", "kubernetes", "eks", "endpoint-collector", "registry"];
const providerOpts = PROVIDERS.map((p) => ({value: p, label: p ? p.replace(/_/g, " ") : "All providers"}));

const SCAN_BADGE: Record<string, [string, string]> = {
  scanned: ["Scanned", "text-good bg-good/10 ring-good/20"],
  discovered: ["Pending", "text-amber-300 bg-amber-400/10 ring-amber-400/20"],
  scanning: ["Scanning", "text-accent bg-accent/10 ring-accent/20"],
  failed: ["Failed", "text-critical bg-critical/10 ring-critical/20"],
};
function ScanBadge({status}: {status: string}) {
  const [label, cls] = SCAN_BADGE[status] || ["Pending", "text-muted bg-white/5 ring-white/10"];
  return <span className={cn("rounded-md px-2 py-0.5 text-[11px] font-medium ring-1", cls)}>{label}</span>;
}

export function Inventory() {
  const refreshKey = useRefreshKey();
  const [type, setType] = useState("");
  const [search, setSearch] = useState("");
  const [scanStatus, setScanStatus] = useState("");
  const [provider, setProvider] = useState("");
  const [vulnerable, setVulnerable] = useState(false);
  const {items, loading, page, setPage, total, totalPages} = usePaginated(
    (p, l) => api.listAssets(type, search, scanStatus, p, l, {provider, vulnerable}),
    [type, search, scanStatus, provider, vulnerable, refreshKey],
  );
  const navigate = useNavigate();

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        {CHIPS.map((c) => {
          const meta = c ? assetMeta(c) : null;
          const active = type === c;
          return (
            <button
              key={c || "all"}
              onClick={() => setType(c)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-medium transition ring-1",
                active
                  ? "bg-white/10 text-ink ring-white/20"
                  : "bg-white/[0.03] text-muted ring-white/10 hover:text-ink",
              )}
            >
              {meta && <meta.icon className={cn("h-3.5 w-3.5", active && meta.accent)} />}
              {c ? meta!.label : "All assets"}
            </button>
          );
        })}
        <div className="ml-auto flex items-center gap-2">
          <div className="w-40"><Select value={provider} onChange={setProvider} options={providerOpts} placeholder="Provider" /></div>
          <button
            onClick={() => setVulnerable((v) => !v)}
            className={cn(
              "rounded-lg px-2.5 py-1.5 text-xs font-medium ring-1 transition",
              vulnerable ? "bg-critical/15 text-critical ring-critical/30" : "bg-white/[0.03] text-muted ring-white/10 hover:text-ink",
            )}
          >
            Vulnerable only
          </button>
          <div className="flex rounded-lg bg-white/[0.03] p-0.5 ring-1 ring-white/10">
            {SCAN_FILTERS.map(([val, label]) => (
              <button
                key={val || "all"}
                onClick={() => setScanStatus(val)}
                className={cn(
                  "rounded-md px-2.5 py-1 text-xs font-medium transition",
                  scanStatus === val ? "bg-white/10 text-ink" : "text-muted hover:text-ink",
                )}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search assets…"
              className="w-56 rounded-xl border border-white/10 bg-white/[0.03] py-2 pl-9 pr-3 text-sm text-ink outline-none placeholder:text-faint focus:border-accent/40"
            />
          </div>
        </div>
      </div>

      {loading && items.length === 0 ? (
        <Skeleton className="h-64 rounded-2xl" />
      ) : items.length === 0 ? (
        <EmptyState title="No assets match" hint="Sync a scanner or adjust the filter." />
      ) : (
        <>
        <DataTable columns={["Asset", "Type", "Scan", "Provider", "Packages", "Findings", "Seen"]}>
          {items.map((a) => {
            const meta = assetMeta(a.asset_type);
            return (
              <Row key={a.id} onClick={() => navigate(`/inventory/${a.id}`)}>
                <Cell>
                  <div className="flex items-center gap-2.5">
                    <span className="grid h-8 w-8 place-items-center rounded-lg bg-white/5 ring-1 ring-white/10">
                      <meta.icon className={cn("h-4 w-4", meta.accent)} />
                    </span>
                    <div className="min-w-0">
                      <div className="truncate font-medium text-ink">{a.display_name}</div>
                      <div className="truncate font-mono text-[11px] text-faint">{a.external_id}</div>
                    </div>
                  </div>
                </Cell>
                <Cell><Tag>{meta.label}</Tag></Cell>
                <Cell><ScanBadge status={a.scan_status} /></Cell>
                <Cell className="text-muted">{a.provider}</Cell>
                <Cell><span className="font-mono">{a.component_count}</span></Cell>
                <Cell>
                  {a.finding_count > 0 ? (
                    <span className="rounded-md bg-critical/15 px-2 py-0.5 font-mono text-xs text-critical">{a.finding_count}</span>
                  ) : (
                    <span className="font-mono text-faint">0</span>
                  )}
                </Cell>
                <Cell className="text-[11px] text-faint">{relativeTime(a.last_seen_at)}</Cell>
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
