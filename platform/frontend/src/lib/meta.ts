import {Boxes, Cloud, Container, GitBranch, Laptop, Package, Server, type LucideIcon} from "lucide-react";

export interface AssetMeta {
  label: string;
  icon: LucideIcon;
  accent: string; // tailwind text-color class
  glow: string; // "r, g, b" for rgb(...)
}

/** Asset-type metadata (label + icon + accent). Keyed by the backend asset_type. */
export const ASSET_TYPES: Record<string, AssetMeta> = {
  container_image: {label: "Container Image", icon: Container, accent: "text-brand", glow: "45, 212, 191"},
  repository: {label: "Repository", icon: GitBranch, accent: "text-violet", glow: "167, 139, 250"},
  k8s_cluster: {label: "K8s Cluster", icon: Boxes, accent: "text-accent", glow: "86, 185, 255"},
  k8s_workload: {label: "K8s Workload", icon: Server, accent: "text-accent", glow: "86, 185, 255"},
  ecs_workload: {label: "ECS Workload", icon: Cloud, accent: "text-warn", glow: "255, 157, 87"},
  endpoint: {label: "Endpoint", icon: Laptop, accent: "text-good", glow: "69, 212, 131"},
};

const DEFAULT_META: AssetMeta = {label: "Asset", icon: Package, accent: "text-muted", glow: "139, 151, 176"};

export function assetMeta(assetType: string): AssetMeta {
  return ASSET_TYPES[assetType] || DEFAULT_META;
}

export const SEVERITY_COLOR: Record<string, string> = {
  critical: "#fb5a73",
  high: "#ff9d57",
  medium: "#f5c451",
  low: "#56b9ff",
  info: "#8c97b0",
  unknown: "#5b6b8c",
};

/**
 * Return a URL only if it is a safe http(s) link, else `undefined`. Guards against
 * stored `javascript:`/`data:` URLs (e.g. an advisory_url from a scan/feed) becoming
 * an XSS sink when bound to an `<a href>`. Parsed with the URL API so scheme tricks
 * (leading whitespace/controls, mixed case) can't slip through.
 */
export function safeExternalHref(url?: string | null): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url, window.location.origin);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? url : undefined;
  } catch {
    return undefined;
  }
}

/** Compact "Nx ago" relative time. */
export function relativeTime(iso?: string | null): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const secs = Math.round((Date.now() - then) / 1000);
  if (secs < 0) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.round(months / 12)}y ago`;
}
