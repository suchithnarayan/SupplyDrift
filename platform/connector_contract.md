# Source Sync Contract

External scanners submit source-scoped data to dedicated endpoints. The platform
normalizes packages, versions, package paths, target identity, raw SBOMs, and
findings into the datastore (MySQL in the docker-compose deployment, or a SQLite
file for single-node/dev).

## Authentication

Auth is **on by default** (`SUPPLYDRIFT_AUTH=disabled` turns it off). Every caller
resolves to a principal with capabilities:

| Principal | Plane | Capabilities |
|---|---|---|
| `admin` user | session cookie | read, operate, admin (users + tokens) |
| `member` user | session cookie | read, operate, mint scoped tokens |
| `viewer` user | session cookie | read |
| `runner` token | `Bearer` | claim/complete, `malware/cursor`+`match`, ingest/sync, scanner-config |
| `ingest` token | `Bearer` | ingest/sync only |
| `readonly` token | `Bearer` | GET only |

Policy: GET `/api/*` needs **read**; mutations need **operate**; the queue M2M routes
(`/api/scan/runs/claim`, `/complete`, `/api/malware/cursor`, `/match`) need a token's
**queue** cap; `/api/ingest` + `/api/sync/*` need **ingest**; `/api/scanner/config`
needs **queue or operate**; `/api/admin/users*` and `/api/demo/*` are **admin**;
`/api/admin/tokens` needs **operate**; `/api/auth/me` + `/api/auth/change-password`
need any authenticated principal. Public: static assets, `/api/health`,
`/api/auth/login`, `/api/auth/logout`.

- **Humans** sign in with a session cookie and send `X-CSRF-Token` on cookie-authed
  POST/PUT/DELETE (bearer requests are exempt). Roles, first-run admin seeding, and
  the disable switch are covered in [README.md → Authentication](README.md#authentication).
- **Scanners/runners** attach `Authorization: Bearer <token>` to the config fetch,
  claim/complete, and the ingest/sync push. **In compose this is zero-touch** — the
  platform generates a `runner` token on first boot and shares it over an internal
  volume the runners read; resolution order is `SUPPLYDRIFT_RUNNER_TOKEN` env →
  `SUPPLYDRIFT_RUNNER_TOKEN_FILE` (default `/run/supplydrift/runner.token`) → none.

```text
POST /api/auth/login             # {username,password} -> session cookie + csrf_token
POST /api/auth/logout            # clears the cookie
GET  /api/auth/me                # current principal (+ csrf_token)
POST /api/auth/change-password   # {old_password, new_password}; session users only, rotates the session
GET/POST/PUT/DELETE /api/admin/users    # admin only
GET/POST/DELETE     /api/admin/tokens   # member+ (scoped); admins see/revoke all
GET  /api/health                 # public liveness (used by the compose healthcheck)
```

## Endpoints (one per source type)

```text
POST /api/sync/repositories          # repo / workflow SBOMs (github-shadow-deps)
POST /api/sync/container-images       # OCI image SBOMs (+ provenance metadata)
POST /api/sync/kubernetes-workloads   # running k8s workload SBOMs
POST /api/sync/ecs-workloads          # running ECS task SBOMs
POST /api/sync/endpoints              # developer-laptop / device SBOMs
```

Short aliases are accepted, e.g. `repository`, `registry`/`images`,
`kubernetes`/`k8s-workloads`, `ecs`, `laptops`/`devices`.

The platform does not schedule scans. Run scanners from a CLI, CI job, external
worker, or Kubernetes CronJob and call the matching endpoint with the result.

### Endpoint (developer laptop) payload

The `endpoints` endpoint accepts a host SBOM plus device + employee metadata in
`asset.details` (populated into the `endpoint_assets` table):

```json
{
  "asset": {
    "asset_type": "endpoint",
    "provider": "kandji",
    "external_id": "endpoint:LT-ACME-0421",
    "display_name": "LT-ACME-0421 (j.rivera)",
    "details": {
      "hostname": "lt-acme-0421.local", "os_name": "macOS", "os_version": "15.4",
      "device_type": "laptop", "employee_name": "Jordan Rivera",
      "employee_email": "j.rivera@acme.com", "department": "Payments Engineering",
      "last_checkin_at": "2026-06-05T22:10:00+00:00"
    }
  },
  "cyclonedx": { "...": "host package SBOM" }
}
```

#### Native collector batches (`endpoint-dep-inventory`)

`/api/sync/endpoints` **also accepts the syft endpoint collector's native batch
format** directly — point its `SBOM_SERVER_URL` at this endpoint and it just works.
The collector runs on each device, scans with syft, and POSTs batched
`{endpoint, scanner, source, packages[], dependency_edges[], batch_*}` JSON
(optionally `Content-Encoding: gzip`, with a `Bearer` token the platform ignores).
The platform translates each batch into one `endpoint` asset (`external_id =
endpoint:<endpoint.id>`, details from `endpoint.{hostname,os,kernel,arch,username}`)
plus its `packages[]` as components; batches accumulate on the same asset (idempotent
upsert). No agent-side change is needed beyond the URL.

**Vulnerability batches.** The collector also runs grype on the syft SBOM and POSTs
a separate, minimal `{endpoint, vulnerabilities[]}` batch (same endpoint block) where
each entry is `{name, version, purl, id, severity, fix}`. The platform turns each into
a **CVE finding** (`finding_type=cve`) linked to its component by purl, and rolls them
into per-package vulnerability status. The asset `provider` is fixed to
`endpoint-collector` so the syft (SBOM) and grype (vuln) streams map to one asset.

### Container-image provenance ("where it came from")

Container-image syncs may include a `provenance` block in `asset.details`. The
platform stores `discovery_source` + `source_reference` columns, keeps the full
block in `raw_metadata`, and creates `built_from` / `discovered_in` relationships
when `source_repository` / `discovered_in` resolve to a known asset:

```json
{"asset": { "details": { "provenance": {
  "discovery_source": "kubernetes",
  "source_repository": "github.com/acme/payments-api",
  "discovered_in": "prod-eks-1/payments/Deployment/payments-api/payments",
  "context": {"connector": "eks", "cluster": "prod-eks-1", "namespace": "payments"}
}}}}
```

## CycloneDX Payload

The request body may be a raw CycloneDX document:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": []
}
```

A wrapper with target context is preferred:

```json
{
  "asset": {
    "asset_type": "container_image",
    "provider": "aws_ecr",
    "external_id": "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-api@sha256:9c2d",
    "display_name": "payments-api@sha256:9c2d",
    "owner": "payments-platform",
    "environment": "production",
    "details": {
      "registry_type": "ecr",
      "registry_url": "123456789012.dkr.ecr.us-east-1.amazonaws.com",
      "repository": "payments-api",
      "digest": "sha256:9c2d8bb9e8b91f2c4e5f6a7b8c9d0e1f"
    }
  },
  "cyclonedx": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
    "version": 1,
    "components": [
      {
        "type": "library",
        "bom-ref": "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.18?arch=amd64",
        "name": "openssl",
        "version": "1.1.1f-1ubuntu2.18",
        "purl": "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.18?arch=amd64",
        "properties": [
          {"name": "supplydrift:path", "value": "/var/lib/dpkg/status"}
        ]
      }
    ]
  }
}
```

## Normalized Payload

Source endpoints also accept the internal normalized shape when a scanner has
already resolved components and package paths:

```json
{
  "assets": [],
  "components": [],
  "component_usages": [],
  "relationships": [],
  "findings": [],
  "raw_sboms": []
}
```

This is the **preferred** shape for large inventories: the **image-scanner** and
**endpoint collector** feed the full SBOM to grype on the runner, then extract only
the required fields — component `name/version/purl/ecosystem/package_manager` and
CVE `findings` (`finding_type=cve`) — and POST this compact payload (gzipped, via
`Content-Encoding: gzip`) instead of the raw CycloneDX/grype documents. Components
are deduped by purl; CVE findings reference them by purl (no package data is
copied into findings). Sending the full CycloneDX wrapper is still supported.

Keep each call scoped to the endpoint source. Repository syncs should not submit
container registry inventory, and Kubernetes workload syncs should not submit
repository dependencies.

## Package Path

For CycloneDX components, include a component property:

```json
{"name": "supplydrift:path", "value": "/usr/local/lib/python/site-packages/requests-2.31.0.dist-info"}
```

The platform also recognizes `supplydrift:evidence_path`, `evidence_path`,
`path`, `filePath`, `location`, `cdx:location:path`, and
`syft:location:0:path`.

## Vulnerabilities (from the scan payload)

Vulnerabilities are **CVE findings carried in the scan payload itself** — every
scanner runs grype (image/github use grype's *native* JSON, the endpoint collector
sends a minimal vuln batch) and emits `findings` with `finding_type: "cve"`,
`severity`, the affected `component_ref`, and a **`fix_recommendation`** ("Upgrade
<pkg> to <version>", taken from grype's `vulnerability.fix.versions`; blank when
grype has no fix). The platform stores them as findings and rolls them up into
`component_vulnerability_status` (provider `grype`).

```text
GET /api/vulnerabilities?severity=&search=&limit=&offset=   # CVE findings (the single view)
GET /api/findings?limit=&offset=                            # raw findings, all finding_types
```

There is **no external OSV check** and **no accept/dismiss** — the old
`POST /api/vulnerabilities/check` and `PATCH /api/findings/{id}` endpoints were removed.

## Pagination

Heavy list endpoints (`/api/assets`, `/api/vulnerabilities`, `/api/components`,
`/api/sbom/packages|versions|assets`, `/api/assets/{id}/components|findings`) accept
`limit` (≤200) + `offset` (or `page`) and return `{items, total, limit, offset}`.
Omitting `limit` returns a plain list (legacy-capped). Counts are computed with
index-backed subqueries (no component×finding cross product), so even
10k-component images list instantly.

## Asset scan status

Each asset has `scan_status` (`discovered`/`scanning`/`scanned`/`failed`) and
`last_scanned_at`. A normal scan payload marks its assets `scanned`; a
`{"discovery_only": true}` push leaves them `discovered`. `GET /api/summary`
returns a `scan` aggregate `{total, scanned, pending, failed}`.

## Malware monitoring (OSV)

The platform watches OSV's **malicious-package** feed (`MAL-*` advisories) and
alerts when a flagged package is present in the inventory. Malware-only — distinct
from the CVE findings above. It runs as a **queue-driven runner** (same model as
image/github): the OSV network fetch happens on the runner, the match happens
in-platform, close to the data. Architecture, diagram, and the local script are in
[docs/malware-analysis.md](docs/malware-analysis.md).

```text
malware-runner (--serve):
  POST /api/scan/runs/claim {job_type:'malware'}   # claim a queued malware run
  GET  /api/malware/cursor                          # delta window {since, now}
  → fetch OSV MAL-* feed since `since`  (on the runner)
  POST /api/malware/match {specs, scanned_at}       # platform matches vs components, upserts alerts, Slack
  POST /api/scan/runs/{id}/complete {summary}
```

```text
POST /api/malware/scan            # enqueue a malware analysis run (202, deduped);
                                  # the UI "Run analysis" button + the interval scheduler hit this
GET  /api/malware/cursor          # delta window for the runner
POST /api/malware/match           # runner -> platform: match specs, upsert alerts + malware findings,
                                  # advance cursor, Slack on NEW; no-op if malware_enabled=false
GET  /api/alerts?status=active    # paginated malware alerts; /api/summary gains malware:{active}
GET/PUT /api/settings/malware     # {malware_enabled, platform_alerts_enabled, slack_enabled,
                                  #  slack_webhook_env, slack_channel, malware_interval_minutes, ...}
```

`malware_enabled` is the master switch; **platform (in-app) alerts are on by
default**, Slack is optional. The Slack webhook is stored **by env-var name**
(`slack_webhook_env`); the value lives in the environment and is read at send time.

Scanners can also flag malicious packages **at scan time** with `--malware`
(local CLI): they query OSV `/v1/querybatch` (by purl) over the scanned SBOM and
fold `MAL-*` hits into the payload as `finding_type='malware'` findings (and a
`malware` array in `--report`).

## Source Configuration (UI-managed)

Registries and runtime services can be configured from the UI and stored in the
`connectors` table. **Credentials are entered directly** and stored **encrypted at
rest** (Fernet under `SUPPLYDRIFT_SECRET_KEY`, required) in a separate
`connector_secrets` table — never in the connector config JSON, and never returned to
the browser (`/api/connectors` exposes only a `secrets_configured: [...]` list).
They are decrypted only into `/api/scanner/config` responses for bearer-authenticated
`runner` tokens, where they are emitted inline as `auth: {provider: "static", ...}`.
Human sessions, including admins, receive masked values. Editing a connector is
write-only: leave a secret field blank to keep the stored value.

```text
GET    /api/connectors            # list configured sources
POST   /api/connectors            # create a source
GET    /api/connectors/{id}
PUT    /api/connectors/{id}        # update
DELETE /api/connectors/{id}
GET    /api/scanner/config         # assembled scanner config {registries, services, github}
```

A connector body:

```json
{
  "name": "ghcr-acme",
  "source_type": "ghcr",
  "kind": "registry",
  "enabled": true,
  "connection": {"owner": "acme", "auth": {"provider": "env", "token_env": "GH_PAT"}},
  "scan": {"repositories": ["acme/*"]}
}
```

`GET /api/scanner/config` returns `{version, registries[], services[], github[]}`.
Each runner reads its own section — the **image-scanner** reads
`registries`/`services`, the **github-shadow-deps** runner reads `github` (sources
of kind `repo`, type `github`). One feed serves both:

```bash
python3 image_scan.py --config-url http://platform:8765/api/scanner/config   # registries/services
python3 gbom_sync.py  --config-url http://platform:8765/api/scanner/config   # github repos
```

Each scanner also runs **standalone, offline** — pass a target directly and write
the result to a JSON file instead of pushing (`image_scan.py nginx:latest -o out.json`,
`gbom_sync.py ./repo -o out.json`, `collect-sbom-inventory.sh --output out.json`; add
`--report` for a flattened view). See each scanner's README. The JSON is the same
normalized payload, re-ingestable via `POST /api/ingest`.

### UI-driven scans (job queue + polling runners)

The **Scan** button on each Sources card enqueues a job; long-running runners poll,
claim, and execute it for that source (`--source <name>`), streaming results back.

```text
POST /api/connectors/{id}/scan        # UI: enqueue a scan for this connection -> 202 (queued run)
POST /api/connectors/{id}/refresh     # UI: enqueue an inventory refresh -> 202 (discovery only:
                                      # finds assets/topology and marks them pending; no SBOM/CVE scan)
GET  /api/connectors/{id}/scan/latest # UI badge: latest run for this connection
GET  /api/scan/runs?connector_id=&status=   # paginated run history
POST /api/scan/runs/claim             # runner: {job_type:'image'|'github', runner_id} -> claims oldest queued (atomic) or null
POST /api/scan/runs/{id}/complete     # runner: {status, summary, error, runner_id};
                                      # completion is bound to the claiming runner_id
POST /api/scan/runs/{id}/cancel       # UI "Stop": cancel a queued/running run
POST /api/connectors/{id}/scan/cancel # UI "Stop": cancel this connector's active run, if any
```

Runs live in `scan_runs` (`queued → running → succeeded|failed|canceled`). Enqueue is
**deduped** (one pending run per connector); claim is **atomic** (`UPDATE…RETURNING`),
so multiple runner replicas never double-scan. `source_type` picks the runner:
registry/service types → `image` runner, `github` → `github` runner. The runner is
the scanner in **`--serve`** mode (`image_scan.py --serve --config-url …`).

**Demo data (optional).** `POST /api/demo/reset` and `POST /api/demo/load` seed the
built-in demo inventory. They are **404 unless `SUPPLYDRIFT_DEMO` is set** and are
admin-gated; `reset` **wipes all data** first. Keep them off in production.

A `github` source is `{name, source_type: "github", connection: {owner | repositories,
auth: {token_env}}, scan: {repositories}}`. Its scan output is POSTed to
`/api/sync/repositories` as the normalized `{assets, components, component_usages,
findings}` shape. Each repo scan runs **three** engines, deduped into one payload:
the phantom-dependency engine (non-manifest deps → component + finding per
detection), **syft** (declared dependencies → components), and **grype** (CVE
findings over the syft SBOM, with `fix_recommendation`).

## Graph

```text
GET /api/graph          # {nodes, edges} from asset_relationships
GET /api/blast-radius    # component → affected assets + findings
```
