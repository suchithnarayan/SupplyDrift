export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";
export type VulnStatus = "unknown" | "clean" | "vulnerable" | "failed" | "unsupported";

export type Role = "admin" | "member" | "viewer";

export interface AuthUser {
  id: string;
  username: string;
  role: Role;
  disabled: boolean;
  created_at: string;
  last_login_at?: string | null;
}

export interface AuthMe {
  kind: "user" | "system" | "token";
  username?: string;
  role?: Role;
  csrf_token?: string;
  scope?: string;
}

export interface ApiToken {
  id: string;
  name: string;
  scope: string;
  created_by?: string;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
  token?: string; // present only in the create response
}

export interface ComponentSummary {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  asset_count: number;
}

export interface Finding {
  id: string;
  finding_type: string;
  severity: string;
  title: string;
  description?: string;
  fix_recommendation?: string;
  status?: string;
  last_seen_at?: string;
  component_name?: string;
  component_version?: string;
  component_ecosystem?: string;
  component_purl?: string;
  asset_id?: string;
  asset_name?: string;
  evidence?: Record<string, unknown>;
}

export interface AssetListItem {
  id: string;
  asset_type: string;
  display_name: string;
  external_id: string;
  provider: string;
  owner?: string;
  environment?: string;
  scan_status: string;
  last_scanned_at?: string | null;
  component_count: number;
  finding_count: number;
  last_seen_at: string;
  first_seen_at?: string;
  connector_name?: string;
  tags?: string[];
  // endpoint_assets join (present on endpoint assets)
  endpoint_hostname?: string;
  endpoint_os_name?: string;
  endpoint_os_version?: string;
  endpoint_employee_name?: string;
  endpoint_department?: string;
  endpoint_last_checkin_at?: string;
}

export interface AssetRelationship {
  source_name: string;
  relationship_type: string;
  target_name: string;
}

export interface AssetComponent {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  package_manager: string;
  purl: string;
  license?: string;
  source?: string;
  evidence_path?: string;
  layer_digest?: string;
  finding_count: number;
}

export interface AssetDetail extends AssetListItem {
  raw_metadata: Record<string, unknown>;
  details: Record<string, unknown>;
  relationships: AssetRelationship[];
  vuln_count: number;
  ghost_finding_count: number;
}

export interface PackageFamily {
  name: string;
  ecosystem: string;
  package_manager?: string;
  sample_purl?: string;
  component_count?: number;
  version_count?: number;
  asset_count?: number;
}

export interface PackageVersion {
  version: string;
  component_count?: number;
  asset_count: number;
  finding_count: number;
  last_seen_at?: string;
  sample_purl?: string;
}

export interface PackageTarget {
  id: string;
  asset_type: string;
  display_name: string;
  name?: string;
  version?: string;
  ecosystem?: string;
  source?: string;
  evidence_path?: string;
}

export interface Connector {
  id: string;
  name: string;
  config: {
    source_type: string;
    kind: string;
    enabled: boolean;
    [key: string]: unknown;
  };
  status?: string;
  schedule?: string;
  created_at?: string;
  updated_at?: string;
  last_sync_at?: string | null;
  secrets_configured?: string[]; // which auth secrets are set (values never sent to the UI)
}

export interface ScanRun {
  id: string;
  connector_id: string | null;
  source_name: string;
  job_type: string;
  status: string; // queued | running | succeeded | failed | canceled
  requested_at: string;
  claimed_at: string | null;
  claimed_by: string | null;
  finished_at: string | null;
  summary: Record<string, any>;
  error: string | null;
  // Present on enqueue/latest for a queued job: whether a runner is connected to
  // claim it, whether the runner is currently busy on another scan (so this one
  // waits its turn), plus a human-readable warning when no runner is connected.
  runner_available?: boolean;
  runner_busy?: boolean;
  warning?: string;
}

export interface MalwareAlert {
  id: string;
  advisory_id: string;
  package: string;
  version: string;
  ecosystem: string;
  advisory_url: string;
  sources: string[];
  status: string;
  asset_count: number;
  affected_asset_ids: string[];
  alert_count: number;
  first_alerted_at: string;
  last_seen_at: string;
}

export interface MalwareSettings {
  malware_enabled: boolean;
  platform_alerts_enabled: boolean;
  slack_enabled: boolean;
  slack_webhook_env: string;
  slack_channel: string;
  malware_interval_minutes: number;
  malware_first_run_lookback_minutes: number;
  malware_last_run_at: string;
  malware_next_run_at: string;
  slack_webhook_configured: boolean;
}

export interface Summary {
  assets: {total: number; by_type: Record<string, number>; stale: number};
  components: {total: number; top: ComponentSummary[]};
  findings: {by_severity: Record<string, number>; latest: Finding[]};
  connectors: {total: number};
  scan: {total: number; scanned: number; pending: number; failed: number; by_status: Record<string, number>};
  malware: {active: number};
  vulnerability_status: {
    checked_packages: number | null;
    vulnerable_packages: number | null;
    clean_packages: number | null;
    failed_packages: number | null;
    last_checked_at: string | null;
  };
  ghost: {repo_packages: number; ghost_packages: number; percent: number};
}
