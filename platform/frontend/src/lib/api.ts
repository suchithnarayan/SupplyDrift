import type {
  AssetComponent,
  AssetDetail,
  AssetListItem,
  Connector,
  Finding,
  MalwareAlert,
  MalwareSettings,
  Page,
  PackageFamily,
  PackageTarget,
  PackageVersion,
  ApiToken,
  AuthMe,
  AuthUser,
  ScanRun,
  Summary,
} from "./types";

function withPage(params: URLSearchParams, page: number, limit: number): URLSearchParams {
  params.set("limit", String(limit));
  params.set("offset", String((page - 1) * limit));
  return params;
}

let _csrf = "";
let _onUnauthorized: (() => void) | null = null;

/** The CSRF token from /login or /me — sent on cookie-authed mutations. */
export function setCsrf(token: string): void {
  _csrf = token || "";
}

/** Registered by the auth context so a 401 anywhere bounces back to login. */
export function onUnauthorized(cb: () => void): void {
  _onUnauthorized = cb;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method || "GET").toUpperCase();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string>),
  };
  if (method !== "GET" && method !== "HEAD" && _csrf) {
    headers["X-CSRF-Token"] = _csrf;
  }
  const response = await fetch(path, {credentials: "include", ...init, headers});
  if (response.status === 401 && _onUnauthorized) {
    _onUnauthorized();
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error((payload as {error?: string}).error || `Request failed (${response.status})`);
  }
  return payload as T;
}

export const api = {
  getSummary: () => request<Summary>("/api/summary"),

  listAssets: (
    assetType = "", search = "", scanStatus = "", page = 1, limit = 50,
    extra: {provider?: string; vulnerable?: boolean; os?: string; department?: string} = {},
  ) => {
    const params = new URLSearchParams();
    if (assetType) params.set("asset_type", assetType);
    if (search) params.set("search", search);
    if (scanStatus) params.set("scan_status", scanStatus);
    if (extra.provider) params.set("provider", extra.provider);
    if (extra.vulnerable) params.set("vulnerable", "true");
    if (extra.os) params.set("os", extra.os);
    if (extra.department) params.set("department", extra.department);
    return request<Page<AssetListItem>>(`/api/assets?${withPage(params, page, limit)}`);
  },
  getAsset: (id: string) => request<AssetDetail>(`/api/assets/${id}`),
  getAssetComponents: (id: string, page = 1, limit = 50) =>
    request<Page<AssetComponent>>(`/api/assets/${id}/components?${withPage(new URLSearchParams(), page, limit)}`),
  // `kind`: "cve" (Vulnerabilities tab) or "ghost" (non-CVE shadow findings).
  getAssetFindings: (id: string, page = 1, limit = 50, opts: {type?: string; kind?: string} = {}) => {
    const params = new URLSearchParams();
    if (opts.type) params.set("finding_type", opts.type);
    if (opts.kind) params.set("kind", opts.kind);
    return request<Page<Finding>>(`/api/assets/${id}/findings?${withPage(params, page, limit)}`);
  },

  // SBOM analyzer
  searchPackages: (search = "", page = 1, limit = 50) => {
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    return request<Page<PackageFamily>>(`/api/sbom/packages?${withPage(params, page, limit)}`);
  },
  getPackageVersions: (family: PackageFamily, page = 1, limit = 200) => {
    const params = new URLSearchParams();
    params.set("name", family.name);
    if (family.ecosystem) params.set("ecosystem", family.ecosystem);
    return request<Page<PackageVersion>>(`/api/sbom/versions?${withPage(params, page, limit)}`);
  },
  getPackageTargets: (family: PackageFamily, version: string, page = 1, limit = 50) => {
    const params = new URLSearchParams();
    params.set("name", family.name);
    if (family.ecosystem) params.set("ecosystem", family.ecosystem);
    if (version) params.set("version", version);
    return request<Page<PackageTarget>>(`/api/sbom/assets?${withPage(params, page, limit)}`);
  },

  getVulnerabilities: (
    search = "", severity = "", page = 1, limit = 50,
    extra: {ecosystem?: string; assetType?: string} = {},
  ) => {
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    if (severity) params.set("severity", severity);
    if (extra.ecosystem) params.set("ecosystem", extra.ecosystem);
    if (extra.assetType) params.set("asset_type", extra.assetType);
    return request<Page<Finding>>(`/api/vulnerabilities?${withPage(params, page, limit)}`);
  },
  // Repo ghost-dependency / non-CVE findings (asset detail).
  getFindings: (severity = "", type = "") => {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (type) params.set("finding_type", type);
    return request<Finding[]>(`/api/findings?${params}`);
  },

  // OSV malware monitoring
  getAlerts: (status = "", page = 1, limit = 50) => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    return request<Page<MalwareAlert>>(`/api/alerts?${withPage(params, page, limit)}`);
  },
  getMalwareSettings: () => request<MalwareSettings>("/api/settings/malware"),
  updateMalwareSettings: (body: Partial<MalwareSettings>) =>
    request<MalwareSettings>("/api/settings/malware", {method: "PUT", body: JSON.stringify(body)}),
  // "Run analysis now" — enqueues a malware job for the malware runner; returns the run.
  triggerMalwareScan: () => request<ScanRun>("/api/malware/scan", {method: "POST"}),
  getLatestMalwareRun: () =>
    request<Page<ScanRun>>("/api/scan/runs?job_type=malware&limit=1").then((p) => p.items[0] ?? null),

  // Sources / connectors
  // UI-driven scan queue (runners pick up the jobs)
  triggerConnectorScan: (id: string) => request<ScanRun>(`/api/connectors/${id}/scan`, {method: "POST"}),
  triggerConnectorRefresh: (id: string) =>
    request<ScanRun>(`/api/connectors/${id}/refresh`, {method: "POST"}),
  cancelConnectorScan: (id: string) =>
    request<ScanRun | null>(`/api/connectors/${id}/scan/cancel`, {method: "POST"}),
  getConnectorScanLatest: (id: string) => request<ScanRun | null>(`/api/connectors/${id}/scan/latest`),
  getScanRuns: (connectorId = "", status = "", page = 1, limit = 50) => {
    const params = new URLSearchParams();
    if (connectorId) params.set("connector_id", connectorId);
    if (status) params.set("status", status);
    return request<Page<ScanRun>>(`/api/scan/runs?${withPage(params, page, limit)}`);
  },

  listConnectors: () => request<Connector[]>("/api/connectors"),
  saveConnector: (body: unknown, id?: string) =>
    request<Connector>(id ? `/api/connectors/${id}` : "/api/connectors", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(body),
    }),
  deleteConnector: (id: string) => request<{deleted: boolean}>(`/api/connectors/${id}`, {method: "DELETE"}),
  getScannerConfig: () => request<unknown>("/api/scanner/config"),

  // ── auth ──────────────────────────────────────────────────────────────
  me: () => request<AuthMe>("/api/auth/me"),
  login: (username: string, password: string) =>
    request<{user: AuthUser; csrf_token: string}>("/api/auth/login", {
      method: "POST", body: JSON.stringify({username, password}),
    }),
  logout: () => request<{status: string}>("/api/auth/logout", {method: "POST"}),
  changePassword: (old_password: string, new_password: string) =>
    request<{status: string}>("/api/auth/change-password", {
      method: "POST", body: JSON.stringify({old_password, new_password}),
    }),

  // ── admin: users (admin) + tokens (member+, scoped) ───────────────────
  listUsers: () => request<AuthUser[]>("/api/admin/users"),
  createUser: (body: {username: string; password: string; role: string}) =>
    request<AuthUser>("/api/admin/users", {method: "POST", body: JSON.stringify(body)}),
  updateUser: (id: string, body: {role?: string; disabled?: boolean; password?: string}) =>
    request<AuthUser>(`/api/admin/users/${id}`, {method: "PUT", body: JSON.stringify(body)}),
  deleteUser: (id: string) => request<{deleted: boolean}>(`/api/admin/users/${id}`, {method: "DELETE"}),
  listTokens: () => request<ApiToken[]>("/api/admin/tokens"),
  createToken: (body: {name: string; scope: string}) =>
    request<ApiToken & {token: string}>("/api/admin/tokens", {method: "POST", body: JSON.stringify(body)}),
  revokeToken: (id: string) => request<{revoked: boolean}>(`/api/admin/tokens/${id}`, {method: "DELETE"}),
};
