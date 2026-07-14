import {ChevronRight, Layers, Search} from "lucide-react";
import {useEffect, useState} from "react";
import {useSearchParams} from "react-router-dom";
import {Cell, DataTable, Row} from "../components/ui/DataTable";
import {Pagination} from "../components/ui/Pagination";
import {EmptyState, GlassCard, SectionTitle, Tag} from "../components/ui/primitives";
import {api} from "../lib/api";
import {cn} from "../lib/cn";
import {assetMeta} from "../lib/meta";
import type {Page, PackageFamily, PackageTarget, PackageVersion} from "../lib/types";

function emptyPage<T>(): Page<T> {
  return {items: [], total: 0, limit: 50, offset: 0};
}
const pages = (p: Page<unknown>) => Math.max(1, Math.ceil(p.total / p.limit));

export function Analyzer() {
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") || "");
  const [families, setFamilies] = useState<Page<PackageFamily>>(emptyPage());
  const [familyPage, setFamilyPage] = useState(1);
  const [pkg, setPkg] = useState<PackageFamily | null>(null);
  const [versions, setVersions] = useState<PackageVersion[]>([]);
  const [version, setVersion] = useState<string | null>(null);
  const [targets, setTargets] = useState<Page<PackageTarget>>(emptyPage());
  const [targetPage, setTargetPage] = useState(1);

  // New query resets to the first page of results.
  useEffect(() => setFamilyPage(1), [query]);
  useEffect(() => {
    if (query.trim().length < 2) {
      setFamilies(emptyPage());
      return;
    }
    const t = setTimeout(
      () => api.searchPackages(query, familyPage).then(setFamilies).catch(() => setFamilies(emptyPage())),
      200,
    );
    return () => clearTimeout(t);
  }, [query, familyPage]);

  // Affected-asset targets paginate independently.
  useEffect(() => {
    if (!pkg || !version) {
      setTargets(emptyPage());
      return;
    }
    api.getPackageTargets(pkg, version, targetPage).then(setTargets).catch(() => setTargets(emptyPage()));
  }, [pkg, version, targetPage]);

  const pickPkg = async (p: PackageFamily) => {
    setPkg(p);
    setVersion(null);
    setTargets(emptyPage());
    const res = await api.getPackageVersions(p);
    setVersions(res.items);
  };
  const pickVersion = (v: string) => {
    setVersion(v);
    setTargetPage(1);
  };

  return (
    <div className="space-y-5">
      <div className="relative">
        <Search className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-faint" />
        <input
          autoFocus
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search a package across every SBOM (e.g. openssl, requests)…"
          className="w-full rounded-2xl border border-white/10 bg-white/[0.03] py-4 pl-12 pr-4 text-base text-ink outline-none placeholder:text-faint focus:border-accent/40"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Step 1: families */}
        <GlassCard className="lg:col-span-1">
          <SectionTitle title="Packages" sub={families.total ? `${families.total.toLocaleString()} matches` : "Type to search"} />
          <div className="space-y-1">
            {families.items.length === 0 && <EmptyState title="No matches" hint="Search a package name." />}
            {families.items.map((f) => (
              <button
                key={f.name + f.ecosystem}
                onClick={() => pickPkg(f)}
                className={cn(
                  "flex w-full items-center gap-2 rounded-lg px-3 py-2.5 text-left transition",
                  pkg?.name === f.name && pkg?.ecosystem === f.ecosystem ? "bg-white/[0.07]" : "hover:bg-white/[0.04]",
                )}
              >
                <Layers className="h-4 w-4 text-violet" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm text-ink">{f.name}</div>
                  <div className="text-[11px] text-faint">{f.ecosystem} · {f.version_count} versions · {f.asset_count} assets</div>
                </div>
                <ChevronRight className="h-4 w-4 text-faint" />
              </button>
            ))}
          </div>
          <Pagination page={familyPage} totalPages={pages(families)} total={families.total} onPage={setFamilyPage} />
        </GlassCard>

        {/* Step 2: versions */}
        <GlassCard className="lg:col-span-1">
          <SectionTitle title="Versions" sub={pkg ? pkg.name : "Pick a package"} />
          <div className="space-y-1">
            {!pkg && <EmptyState title="Select a package" />}
            {versions.map((v) => (
              <button
                key={v.version}
                onClick={() => pickVersion(v.version)}
                className={cn(
                  "flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left transition",
                  version === v.version ? "bg-white/[0.07]" : "hover:bg-white/[0.04]",
                )}
              >
                <span className="font-mono text-sm text-ink">{v.version || "unknown"}</span>
                <span className="flex items-center gap-2 text-[11px] text-faint">
                  <span>{v.asset_count} assets</span>
                  {v.finding_count > 0 && <span className="text-critical">{v.finding_count} CVE</span>}
                </span>
              </button>
            ))}
          </div>
        </GlassCard>

        {/* Step 3: targets */}
        <GlassCard className="lg:col-span-1">
          <SectionTitle title="Affected assets" sub={version ? `${pkg?.name} @ ${version}` : "Pick a version"} />
          <div className="space-y-2">
            {!version && <EmptyState title="Select a version" />}
            {targets.items.map((t) => {
              const meta = assetMeta(t.asset_type);
              return (
                <div key={t.id + t.evidence_path} className="rounded-lg bg-white/[0.03] p-3 ring-1 ring-white/8">
                  <div className="flex items-center gap-2">
                    <meta.icon className={cn("h-4 w-4", meta.accent)} />
                    <span className="truncate text-sm text-ink">{t.display_name}</span>
                    <Tag>{meta.label}</Tag>
                  </div>
                  {t.evidence_path && (
                    <div className="mt-1.5 truncate font-mono text-[11px] text-faint">{t.evidence_path}</div>
                  )}
                </div>
              );
            })}
          </div>
        </GlassCard>
      </div>

      {version && targets.items.length > 0 && (
        <>
          <DataTable columns={["Asset", "Type", "Source", "Evidence path"]}>
            {targets.items.map((t) => {
              const meta = assetMeta(t.asset_type);
              return (
                <Row key={"row" + t.id + t.evidence_path}>
                  <Cell className="text-ink">{t.display_name}</Cell>
                  <Cell><Tag>{meta.label}</Tag></Cell>
                  <Cell className="text-muted">{t.source || "—"}</Cell>
                  <Cell className="max-w-md truncate font-mono text-[11px] text-faint">{t.evidence_path || "—"}</Cell>
                </Row>
              );
            })}
          </DataTable>
          <Pagination page={targetPage} totalPages={pages(targets)} total={targets.total} onPage={setTargetPage} />
        </>
      )}
    </div>
  );
}
