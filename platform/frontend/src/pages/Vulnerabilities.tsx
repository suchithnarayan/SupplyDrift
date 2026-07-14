import {Search} from "lucide-react";
import {useState} from "react";
import {Link} from "react-router-dom";
import {useRefreshKey} from "../App";
import {Cell, DataTable, Row} from "../components/ui/DataTable";
import {Pagination} from "../components/ui/Pagination";
import {Select} from "../components/ui/Select";
import {EmptyState, SeverityPill, Skeleton, Tag} from "../components/ui/primitives";
import {api} from "../lib/api";
import {cn} from "../lib/cn";
import {usePaginated} from "../lib/useFetch";

const SEVERITIES = ["", "critical", "high", "medium", "low"];

const ECOSYSTEMS = ["", "npm", "pypi", "deb", "apk", "golang", "maven", "gem", "cargo",
  "rpm", "nuget", "composer", "github-actions", "oci", "generic"];
const ASSET_TYPES = ["", "repository", "container_image", "k8s_workload", "endpoint", "cloud_workload"];
const opts = (values: string[], allLabel: string) =>
  values.map((v) => ({value: v, label: v ? v.replace(/_/g, " ") : allLabel}));

export function Vulnerabilities() {
  const refreshKey = useRefreshKey();
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [ecosystem, setEcosystem] = useState("");
  const [assetType, setAssetType] = useState("");
  const {items, loading, page, setPage, total, totalPages} = usePaginated(
    (p, l) => api.getVulnerabilities(search, severity, p, l, {ecosystem, assetType}),
    [search, severity, ecosystem, assetType, refreshKey],
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search CVE or package…"
            className="w-64 rounded-xl border border-white/10 bg-white/[0.03] py-2 pl-9 pr-3 text-sm text-ink outline-none placeholder:text-faint focus:border-accent/40"
          />
        </div>
        {SEVERITIES.map((s) => (
          <button
            key={s || "all"}
            onClick={() => setSeverity(s)}
            className={cn(
              "rounded-full px-3 py-1.5 text-xs font-medium capitalize ring-1 transition",
              severity === s ? "bg-white/10 text-ink ring-white/20" : "bg-white/[0.03] text-muted ring-white/10 hover:text-ink",
            )}
          >
            {s || "all"}
          </button>
        ))}
        <div className="w-40"><Select value={ecosystem} onChange={setEcosystem} options={opts(ECOSYSTEMS, "All ecosystems")} placeholder="Ecosystem" /></div>
        <div className="w-44"><Select value={assetType} onChange={setAssetType} options={opts(ASSET_TYPES, "All asset types")} placeholder="Asset type" /></div>
      </div>

      {loading && items.length === 0 ? (
        <Skeleton className="h-64 rounded-2xl" />
      ) : items.length === 0 ? (
        <EmptyState title="No vulnerabilities" hint="CVEs are synced from the scanners (syft → grype). Run a scan to populate them." />
      ) : (
        <>
        <DataTable columns={["Vulnerability", "Severity", "Package", "Version", "Affected asset", "Fix"]}>
          {items.map((v) => (
            <Row key={v.id}>
              <Cell className="font-mono text-ink">{v.title}</Cell>
              <Cell><SeverityPill severity={v.severity} /></Cell>
              <Cell>
                <span className="font-medium text-ink">{v.component_name || "—"}</span>
                {v.component_ecosystem && <span className="ml-2 inline-flex"><Tag>{v.component_ecosystem}</Tag></span>}
              </Cell>
              <Cell className="font-mono text-muted">{v.component_version || "—"}</Cell>
              <Cell>
                {v.asset_id ? (
                  <Link to={`/inventory/${v.asset_id}`} className="text-accent hover:underline">
                    {v.asset_name || "—"}
                  </Link>
                ) : (
                  <span className="text-faint">—</span>
                )}
              </Cell>
              <Cell className="text-[12px] text-muted">{v.fix_recommendation || <span className="text-faint">no fix</span>}</Cell>
            </Row>
          ))}
        </DataTable>
        <Pagination page={page} totalPages={totalPages} total={total} onPage={setPage} />
        </>
      )}
    </div>
  );
}
