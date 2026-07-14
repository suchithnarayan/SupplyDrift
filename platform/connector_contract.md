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
| `admin` user | session cookie | read, operate, admin, queue, ingest |
| `member` user | session cookie | read, operate, mint ingest/readonly tokens |
| `viewer` user | session cookie | read |
| `runner` token | `Bearer` | claim/complete, `malware/cursor`+`match`, ingest/sync, scanner-config |
| `ingest` token | `Bearer` | ingest/sync only |
| `readonly` token | `Bearer` | GET only |

Policy: by default, GET `/api/*` needs **read** and mutations need **operate**; the
queue routes
(`/api/scan/runs/claim`, `/complete`, `/api/malware/cursor`, `/match`) need
**queue**; `/api/ingest` + `/api/sync/*` need **ingest**; `/api/scanner/config`
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
  volume the runners read; runner-side resolution order is
  `SUPPLYDRIFT_RUNNER_TOKEN` env → `SUPPLYDRIFT_RUNNER_TOKEN_FILE` (default
  `/run/supplydrift/runner.token`) → none.

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
POST /api/sync/kubernetes-workloads   # Kubernetes cluster/workload/image topology
POST /api/sync/ecs-workloads          # normalized ECS/cloud workload payloads
POST /api/sync/endpoints              # developer-laptop / device SBOMs
```

Short aliases are accepted, e.g. `repository`, `registry`/`images`,
`kubernetes`/`k8s-workloads`, `ecs`, `laptops`/`devices`.

The platform **does** enqueue source scans and inventory refreshes from the UI/API;
long-running image and GitHub runners claim that work from `scan_runs`. It also has
an interval scheduler that enqueues malware jobs. There is currently no recurring
per-connector scan scheduler: use the UI/API on demand, or invoke a scanner from a
CLI, CI worker, or Kubernetes CronJob and submit to the matching sync endpoint.

The ECS sync route accepts workload assets from external producers. The bundled
image runner's ECS connector currently discovers running image targets and keeps
`discovered_via`/provenance diagnostics, but does not emit ECS workload assets or
runtime topology.

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

`/api/sync/endpoints` **also accepts the Syft endpoint collector's native batch
format** directly; point its `SBOM_SERVER_URL` at this endpoint.
The collector runs on each device, scans with syft, and POSTs batched
`{endpoint, scanner, source, packages[], dependency_edges[], batch_*}` JSON
(optionally `Content-Encoding: gzip`). When auth is enabled, use an `ingest` or
`runner` bearer token; unauthenticated sync requests return `401`.
The platform translates each batch into one `endpoint` asset (`external_id =
endpoint:<endpoint.id>`, details from `endpoint.{hostname,os,kernel,arch,username}`)
plus its `packages[]` as components; batches accumulate on the same asset (idempotent
upsert). The current endpoint adapter does **not** persist `dependency_edges[]` or
collector heartbeat/liveness records, and it does not deduplicate native deliveries
by `(endpoint.id, scan_id, batch_id)`; repeated package batches remain safe because
asset/component/usage records are stable upserts. No agent-side change is needed
beyond the URL and bearer token.

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

This is the **preferred** shape for large inventories. The image and repository
scanners feed their SBOM to Grype when enabled, extract only required component/CVE
fields, and POST compact normalized payloads instead of raw Syft/Grype documents.
The image publisher gzip-compresses these requests by default and sets
`Content-Encoding: gzip`; the repository publisher currently sends plain JSON.
The endpoint collector also normalizes locally, but sends the native
package/vulnerability batches described above for the platform adapter to
translate. Unless a producer supplies an explicit component
`id`, component identity is the stable
tuple `(purl-or-CPE-or-ecosystem, name, version)`; it is not purl-only. Findings
normally reference the payload component `ref`, with purl variants used as a
fallback when Grype rewrites a CycloneDX bom-ref. Sending the full CycloneDX wrapper
is still supported.

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

Vulnerabilities are **CVE findings carried in the scan payload itself**. Grype is
enabled by default in the bundled image and GitHub runner configuration, but it is
still tool/configuration dependent: the GitHub scanner degrades to its
phantom-dependency results when Syft or Grype is unavailable, the endpoint
collector skips its optional vulnerability batch when Grype is unavailable, and
the image scanner retains a successful SBOM if its vulnerability pass fails. When
present, scanners emit `findings` with `finding_type: "cve"`, `severity`, the
affected `component_ref`, and a **`fix_recommendation`** ("Upgrade <pkg> to
<version>", taken from Grype fix versions; blank when Grype has no fix). The
platform stores them as findings and rolls them up into
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

Each asset has `scan_status` and `last_scanned_at`. Current ingestion writes
`discovered` for a `{"discovery_only": true}` payload and `scanned` for every other
payload, including a completed scan with an empty SBOM. A discovery-only refresh
does not downgrade an already-scanned asset. The schema/summary code also recognizes
reserved or legacy `scanning` and `failed` values, but bundled producers do not
currently assign them. `GET /api/summary` returns the aggregate
`{total, scanned, pending, failed}`; queue execution state belongs to `scan_runs`,
not the asset's `scan_status`.

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
  POST /api/malware/match {specs, scanned_at}       # platform matches/upserts when in-app alerts are enabled
  POST /api/scan/runs/{id}/complete {summary}
```

```text
POST /api/malware/scan            # enqueue a malware analysis run (202, deduped);
                                  # the UI "Run analysis" button + the interval scheduler hit this
GET  /api/malware/cursor          # delta window for the runner
POST /api/malware/match           # runner -> platform: match specs, upsert alerts + malware findings,
                                  # advance cursor, Slack on NEW; skipped if malware_enabled=false
GET  /api/alerts?status=active    # paginated malware alerts; /api/summary gains malware:{active}
GET/PUT /api/settings/malware     # {malware_enabled, platform_alerts_enabled, slack_enabled,
                                  #  slack_webhook_env, slack_channel, malware_interval_minutes, ...}
```

`malware_enabled` is the master switch and is off by default; once enabled,
**platform (in-app) alerts are on by default**. In the current implementation,
turning `platform_alerts_enabled` off also suppresses matching/upserts and therefore
Slack dispatch. Slack is optional and fires only for newly created alerts. The
webhook is stored **by env-var name** (`slack_webhook_env`); the value lives in the
environment and is read at send time. Active alerts are additive: there is no
automatic reconciliation or resolve/acknowledge route when inventory later changes.

The image and repository scanners can also flag malicious packages **at scan
time** with `--malware` (local CLI): they query OSV `/v1/querybatch` over the
scanned SBOM and fold `MAL-*` hits into the payload as
`finding_type='malware'` findings (and a `malware` array in `--report`). The
endpoint collector supports the same networked lookup only with local
`--output --malware`; it adds malware results to that diagnostic output and does
not add them to its connected SBOM/vulnerability upload batches.

## Source Configuration (UI-managed)

Registries, runtime services, and GitHub repositories can be configured from the UI and stored in the
`connectors` table. **Credentials are entered directly** and stored **encrypted at
rest** (Fernet under `SUPPLYDRIFT_SECRET_KEY`, required) in a separate
`connector_secrets` table — never in the connector config JSON, and never returned to
the browser (`/api/connectors` exposes only a `secrets_configured: [...]` list).
They are decrypted only into `/api/scanner/config` responses for bearer-authenticated
`runner` tokens, where they are emitted inline as `auth: {provider: "static", ...}`.
Human sessions, including admins, receive masked values. Editing a connector is
write-only: leave a secret field blank to keep the stored value.

After claiming a run, bundled runners append `connector_id=<claimed-id>` to the
config request, so only that connector's secret is returned during normal operation.
This is operational response scoping, **not token-to-connector authorization**: a
`runner` token is globally privileged and can omit or change that query parameter.
Protect and rotate runner tokens accordingly.

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
of kind `repo`, type `github`). One feed serves both. From the repository root,
against the host-exposed local platform, and with a UI-minted runner token
available through `SUPPLYDRIFT_RUNNER_TOKEN[_FILE]`:

```bash
python3 image-scanner/image_scan.py --config-url http://127.0.0.1:8765/api/scanner/config
python3 github-shadow-deps/gbom_sync.py --config-url http://127.0.0.1:8765/api/scanner/config
```

Each scanner also runs **standalone** — pass a target directly and write JSON instead
of pushing (`image_scan.py nginx:latest -o out.json`, `gbom_sync.py ./repo -o
out.json`, or `collect-sbom-inventory.sh --output out.json`). Image and repository
commands without `--report` write an **array** of normalized payloads; each array
element, not the array wrapper, can be submitted to `/api/ingest` or the matching
`/api/sync/*` route. Their `--report` output is flattened for people and is not an
ingest payload. The endpoint collector's local `--output` aggregate is likewise a
diagnostic format; normal server mode sends its supported native batches directly
to `/api/sync/endpoints`. See each scanner's README for its exact output contract.

### UI-driven scans (job queue + polling runners)

The **Scan** button on each Sources card enqueues a job; long-running runners poll,
claim, and execute it for that source (`--source <name>`), streaming results back.

```text
POST /api/connectors/{id}/scan        # UI: enqueue or reuse an active run -> 202
POST /api/connectors/{id}/refresh     # UI: enqueue an inventory refresh -> 202 (discovery only:
                                      # new assets are pending; scanned assets are not downgraded)
GET  /api/connectors/{id}/scan/latest # UI badge: latest run for this connection
GET  /api/scan/runs?connector_id=&status=   # paginated run history
POST /api/scan/runs/claim             # runner: {job_type:'image'|'github'|'malware', runner_id}
                                      # -> claims oldest queued for that type (atomic) or null
POST /api/scan/runs/{id}/complete     # runner: {status, summary, error, runner_id};
                                      # ownership checked when runner_id is supplied
POST /api/scan/runs/{id}/cancel       # UI "Stop": mark a queued/running run canceled
POST /api/connectors/{id}/scan/cancel # UI "Stop": cancel this connector's active run, if any
```

Runs live in `scan_runs` (`queued → running → succeeded|failed|canceled`). Enqueue
checks for and reuses an existing queued or running run for the connector. Claim
uses a dialect-agnostic compare-and-set: select the oldest queued ID, then update
it only while its status is still `queued`. A losing replica returns `null` and
polls again, so replicas do not double-scan. `source_type` picks the runner:
registry/service types → `image` runner, `github` → `github` runner. The runner is
the scanner in **`--serve`** mode (`image_scan.py --serve --config-url …`).

Bundled runners always send `runner_id`, so completion is normally accepted only
from the recorded claimer. The compatibility path still accepts a completion that
omits `runner_id`; ownership is therefore not an unconditional API guarantee.
Canceling a **running** run changes database/UI state only—it cannot signal or kill
the scanner process. If that runner later completes, its completion can overwrite
the canceled state.

Running jobs older than `SUPPLYDRIFT_SCAN_STALE_SECONDS` (default one hour) are
marked failed when run status is read. Platform startup reaps every previously
running job immediately because its original runner may no longer be alive. These
operations do not kill a scanner either; a genuine late completion can still
overwrite the reaped state.

Do not confuse `scan_runs` with `scan_jobs`. `scan_runs` is the user-visible queue
and run history. Each ingested payload also upserts an internal `scan_jobs` audit
row, but the two tables have no direct foreign key and the run-history API does not
expose `scan_jobs`; one queued source run can produce multiple payload/audit rows.

**Demo data (optional).** `POST /api/demo/reset` and `POST /api/demo/load` seed the
built-in demo inventory. They are **404 unless `SUPPLYDRIFT_DEMO` is set** and are
admin-gated; `reset` **wipes all data** first. Keep them off in production.

A `github` source is `{name, source_type: "github", connection: {owner | repositories,
auth: {token_env}}, scan: {repositories}}`. Its scan output is POSTed to
`/api/sync/repositories` as the normalized `{assets, components, component_usages,
findings}` shape. A full repo scan combines up to **three** engines into one payload:
the phantom-dependency engine (non-manifest deps → component + finding per
detection), **Syft** (declared dependencies → components), and **Grype** (CVE
findings over the Syft SBOM, with `fix_recommendation`). Syft/Grype are optional at
runtime; when unavailable, the repository scan still returns phantom-dependency
results.

## Graph

```text
GET /api/graph          # {nodes, edges} from asset_relationships
GET /api/blast-radius    # component → affected assets + findings
```
