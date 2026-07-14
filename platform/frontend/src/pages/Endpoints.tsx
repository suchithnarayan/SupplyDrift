import {Cpu, Laptop, Package, Search, UserRound} from "lucide-react";
import {useState} from "react";
import {useNavigate} from "react-router-dom";
import {useRefreshKey} from "../App";
import {Pagination} from "../components/ui/Pagination";
import {EmptyState, GlassCard, Skeleton, StaggerItem, Stagger} from "../components/ui/primitives";
import {api} from "../lib/api";
import {relativeTime} from "../lib/meta";
import {usePaginated} from "../lib/useFetch";

const filterInput =
  "w-44 rounded-xl border border-white/10 bg-white/[0.03] py-2 pl-9 pr-3 text-sm text-ink outline-none placeholder:text-faint focus:border-accent/40";

export function Endpoints() {
  const refreshKey = useRefreshKey();
  const [search, setSearch] = useState("");
  const [os, setOs] = useState("");
  const [department, setDepartment] = useState("");
  const {items, loading, page, setPage, total, totalPages} = usePaginated(
    (p, l) => api.listAssets("endpoint", search, "", p, l, {os, department}),
    [search, os, department, refreshKey],
    60,
  );
  const navigate = useNavigate();

  const filterBar = (
    <div className="flex flex-wrap items-center gap-2">
      {[
        {value: search, set: setSearch, placeholder: "Search hostname…"},
        {value: os, set: setOs, placeholder: "OS…"},
        {value: department, set: setDepartment, placeholder: "Department…"},
      ].map((f) => (
        <div key={f.placeholder} className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <input value={f.value} onChange={(e) => f.set(e.target.value)} placeholder={f.placeholder} className={filterInput} />
        </div>
      ))}
    </div>
  );

  if (loading && items.length === 0) {
    return (
      <div className="space-y-4">
        {filterBar}
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({length: 3}).map((_, i) => (
            <Skeleton key={i} className="h-44 rounded-2xl" />
          ))}
        </div>
      </div>
    );
  }
  if (items.length === 0)
    return (
      <div className="space-y-4">
        {filterBar}
        <EmptyState title="No endpoints match" hint="Post a host SBOM to POST /api/sync/endpoints with device + employee metadata." />
      </div>
    );

  return (
    <div className="space-y-4">
    {filterBar}
    <Stagger className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {items.map((e) => (
        <StaggerItem key={e.id}>
          <GlassCard hover onClick={() => navigate(`/inventory/${e.id}`)} className="h-full">
            <div className="flex items-start justify-between">
              <span className="grid h-11 w-11 place-items-center rounded-xl bg-good/10 ring-1 ring-good/25">
                <Laptop className="h-5 w-5 text-good" />
              </span>
              {e.finding_count > 0 && (
                <span className="rounded-md bg-critical/15 px-2 py-0.5 font-mono text-xs text-critical">
                  {e.finding_count} findings
                </span>
              )}
            </div>
            <div className="mt-3">
              <div className="truncate text-base font-semibold text-ink">{e.endpoint_hostname || e.display_name}</div>
              <div className="mt-1 flex items-center gap-1.5 text-xs text-muted">
                <UserRound className="h-3.5 w-3.5" />
                {e.endpoint_employee_name || e.owner || "Unassigned"}
                {e.endpoint_department && <span className="text-faint">· {e.endpoint_department}</span>}
              </div>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3 border-t border-white/8 pt-3 text-xs">
              <div className="flex items-center gap-1.5 text-muted">
                <Cpu className="h-3.5 w-3.5 text-accent" />
                {e.endpoint_os_name || "—"} {e.endpoint_os_version || ""}
              </div>
              <div className="flex items-center gap-1.5 text-muted">
                <Package className="h-3.5 w-3.5 text-violet" />
                {e.component_count} packages
              </div>
            </div>
            <div className="mt-3 text-[11px] text-faint">
              Last check-in · {relativeTime(e.endpoint_last_checkin_at || e.last_seen_at)}
            </div>
          </GlassCard>
        </StaggerItem>
      ))}
    </Stagger>
    <Pagination page={page} totalPages={totalPages} total={total} onPage={setPage} />
    </div>
  );
}
