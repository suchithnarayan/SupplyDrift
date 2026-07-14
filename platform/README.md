# SupplyDrift Platform

SupplyDrift is the product surface for phantom dependency analysis. The platform
stores scanner output, lets teams search packages across repository, image,
runtime, and endpoint SBOMs, and maintains vulnerability status for package
versions.

The UI is a React + TypeScript app in `frontend/`. The API is a FastAPI service
(uvicorn); the reusable `Store` class (`app.py`) owns core persistence,
ingestion, and query logic. `auth.py`/`authz.py` implement authentication and
RBAC, `server.py` owns the HTTP plus scheduler/policy plumbing
(`create_app(store)`), and `run.py` is the uvicorn launcher. The datastore is
**MySQL** via `SUPPLYDRIFT_DATABASE_URL` (the
docker-compose default) **or a SQLite file** (single-node/dev fallback when the
URL is unset) — the `Store` abstraction keeps the HTTP layer engine-agnostic.

## Run

Run the full stack with Docker (the UI is built into the image), or run the
platform directly on your machine.

### Run with Docker (no Node or Python needed on the host)

The platform image builds the SPA in a multi-stage Dockerfile, so the UI works out
of the box. From the repository root:

```bash
cp .env.example .env    # set admin login, MySQL passwords, SUPPLYDRIFT_SECRET_KEY
docker compose up -d                          # MySQL + platform :8765 + image/github/malware runners
docker compose up -d --scale image-runner=3   # more image workers
KUBECONFIG_HOST=$HOME/.kube/config docker compose up -d   # also enable Kubernetes scanning
```

Open <http://localhost:8765>. Compose runs MySQL as the datastore and generates
the runner token automatically (zero-touch — see Authentication below). Set
`SUPPLYDRIFT_SLACK_WEBHOOK` on the platform service to push malware alerts to
Slack.

Compose pins Nono and sets `SUPPLYDRIFT_TOOL_SANDBOX=required` for the image and
GitHub runners, so they fail before polling if the per-invocation Syft/Grype
sandbox is unavailable. That boundary covers untrusted parser child processes;
trusted parent-side connector, `kubectl`, and AWS discovery code remains outside
it and relies on the hardened container plus deployment egress policy. See the
[security boundary](../SECURITY.md#understand-the-sandbox-boundary),
[sandbox runtime](../supplydrift-sandbox/README.md), and
[architecture](../docs/architecture.md#per-invocation-parser-sandbox).

### Run locally without Docker

Prerequisites: Python 3.12+, and Node.js `^20.19.0` or `>=22.12.0` (only needed to
build the UI). This path uses the SQLite fallback datastore (a file under `data/`).

> **You must build the frontend once.** The backend serves the compiled UI from
> `frontend/dist`, which is a build artifact and is **not committed** (it's
> gitignored). On a fresh clone the API serves a plain `SupplyDrift API` text page
> instead of the UI until you build it. `STATIC_ROOT` is resolved once at startup,
> so build *before* you start `run.py` (or restart it after building).

1. Build the frontend — creates `frontend/dist`:

   ```bash
   cd platform/frontend
   npm ci
   npm run build
   cd ../..
   ```

2. Start the backend — serves the API **and** the built UI on one port:

   ```bash
   cd platform
   pip install -r requirements.txt
   SUPPLYDRIFT_AUTH=disabled python3 run.py --load-demo
   # Options: --host/--port/--db; --reload for development
   ```

   That command is the simplest **loopback-only development** start. To exercise
   authentication locally instead, seed the first admin and allow the session
   cookie over plain HTTP:

   ```bash
   SUPPLYDRIFT_ADMIN_USER=admin \
   SUPPLYDRIFT_ADMIN_PASSWORD='choose-a-password-of-at-least-8-characters' \
   SUPPLYDRIFT_INSECURE=1 \
   python3 run.py --load-demo
   ```

   `SUPPLYDRIFT_ADMIN_*` is used only while the database has no users. Set
   `SUPPLYDRIFT_SECRET_KEY` as well before saving connector credentials.

3. Open <http://127.0.0.1:8765>.

> This runs the **platform only** — no scan runners. The UI's **Scan** button will
> queue a job and show *"Queued — no runner connected"* until a runner is polling.
> To actually execute scans, start a runner from the **repository root in another
> shell** against the platform:
>
> ```bash
> python3 image-scanner/image_scan.py --serve \
>   --config-url http://127.0.0.1:8765/api/scanner/config --log-format json
> ```
>
> The command above works with the auth-disabled development start. With auth
> enabled, create a `runner` token under **Access → API tokens** and add
> `SUPPLYDRIFT_RUNNER_TOKEN=sdp_...` to the runner process. Install the image
> scanner's Python requirements and Syft/Grype first, or use the Compose runner
> image, which includes its scanner tools and sandbox configuration.

### Frontend dev server (hot reload)

For UI development, run Vite separately — it serves on `:5173` and proxies `/api`
to the backend on `:8765`, so the backend must also be running:

```bash
cd platform/frontend
npm install
npm run dev          # open http://127.0.0.1:5173 (not :8765)
```

## Configuration reference

All platform behavior is controlled by environment variables:

| Variable | Default | Effect |
| --- | --- | --- |
| `SUPPLYDRIFT_DATABASE_URL` | *(unset)* | SQLAlchemy URL for the datastore. Compose sets `mysql+pymysql://…@db:3306/…`. Unset → SQLite file. |
| `SUPPLYDRIFT_DB` | `data/supplydrift.db` | SQLite file path (used only when `SUPPLYDRIFT_DATABASE_URL` is unset). |
| `SUPPLYDRIFT_AUTH` | `enabled` | `disabled` turns off all authentication (trusted local/dev only — see Authentication). |
| `SUPPLYDRIFT_ADMIN_USER` / `SUPPLYDRIFT_ADMIN_PASSWORD` | *(unset)* | Seed the first admin **once, on an empty database**; ignored afterwards. |
| `SUPPLYDRIFT_SECRET_KEY` | *(unset)* | Fernet key that encrypts connector credentials at rest. **Required to store source credentials.** Generator one-liner in `.env.example`. |
| `SUPPLYDRIFT_RUNNER_TOKEN` | *(unset)* | Explicit `runner`-scope token for external runners (overrides the token file). |
| `SUPPLYDRIFT_RUNNER_TOKEN_FILE` | `/run/supplydrift/runner.token` | Zero-touch runner token file, generated on first boot and shared over the compose volume. |
| `SUPPLYDRIFT_PUBLIC_URL` | `http://127.0.0.1:8765` *(Compose sets `http://localhost:8765`)* | URL returned in scanner configuration and used for CORS. Set it explicitly outside Compose. |
| `SUPPLYDRIFT_SLACK_WEBHOOK` | *(unset)* | Default env var read for malware Slack alerts (settings store the env-var *name*, never the value). |
| `SUPPLYDRIFT_MAX_BODY_MB` | `64` | Request-body size cap for ingest/sync. |
| `SUPPLYDRIFT_MAX_DECOMPRESSED_MB` | `256` | Cap on gzip-decompressed request size (zip-bomb guard). |
| `SUPPLYDRIFT_SCAN_STALE_SECONDS` | `3600` | Running scans older than this are reaped as failed (dead-runner cleanup). |
| `SUPPLYDRIFT_LOGIN_IP_MAX_FAILS` | `50` | Per-IP failed-login throttle threshold (per-username throttling is separate). |
| `SUPPLYDRIFT_INSECURE` | *(unset)* | `1` = dev mode: session cookies work over plain http and interactive `/api/docs` is exposed. |
| `SUPPLYDRIFT_I_UNDERSTAND_AUTH_DISABLED` | *(unset)* | Must be `1` to serve auth-disabled beyond localhost: gates both `run.py` starting on a non-loopback host and the per-request middleware that refuses public peer addresses. |
| `SUPPLYDRIFT_DEMO` | *(unset)* | Enables the destructive `/api/demo/reset` + `/api/demo/load` routes (404 otherwise). |
| `SUPPLYDRIFT_LOAD_DEMO` | *(unset)* | Load demo data at boot (what `run.py --load-demo` sets). |
| `MALWARE_SCHEDULER` | *(on)* | `off` disables the interval-based malware-job enqueue scheduler. |

**Login cooldown:** five failed attempts for the same normalized username within
a fixed five-minute window cause subsequent attempts to return `429` until that
window expires. The per-IP threshold above uses the same five-minute window; set
it to `0` to disable only the IP limit. A successful login clears the username
counter but intentionally does not clear the IP counter. Counters are stored in
the database, so restarting the API does not reset the cooldown.

## Authentication

Auth is **on by default**. There are two planes:

- **Humans** sign in with a username/password; the server sets an httpOnly session
  cookie (CSRF-protected on writes). Roles: **admin** (manage users + tokens + all),
  **member** (read + operate + self-service non-runner scoped tokens), **viewer** (read-only).
- **Machines** use `Authorization: Bearer <token>` — scoped API tokens
  (`runner` / `ingest` / `readonly`), minted under **Access → API tokens**.
  `runner` tokens can fetch scanner credentials and require an admin.

  ```bash
  curl -H "Authorization: Bearer $READONLY_TOKEN" http://localhost:8765/api/summary
  ```

**First run:** set `SUPPLYDRIFT_ADMIN_USER` / `SUPPLYDRIFT_ADMIN_PASSWORD` in `.env`
(see `.env.example`). They seed the initial admin **once, on an empty database**, and
are **ignored on every later boot** (the check is "no users exist yet"). After you've
logged in, the platform itself no longer needs the seed password — the account lives
in the DB and you change it from the UI. However, `scripts/local-compose.sh doctor`
and `up` deliberately require a non-empty admin password on every preflight, so keep
it in the mode-600 `.env` while using that helper, or start the already-seeded
platform directly after removing it. If auth is on and these are unset with no users,
the API logs an error and protected API calls return `401` until you set them and
restart.

**Runners need no setup in compose:** the platform generates a `runner` token on
first boot and shares it over an internal volume that the runners mount read-only —
zero-touch. An *external* runner (can't mount the volume) uses `SUPPLYDRIFT_RUNNER_TOKEN`
set to a UI-minted `runner` token. Runner tokens are highly privileged — see the
trust model in [`../SECURITY.md`](../SECURITY.md).

**Disable** for a trusted local/dev network with `SUPPLYDRIFT_AUTH=disabled` (the API
is then unauthenticated). Behind TLS, cookies are `Secure`; for plain http set
`SUPPLYDRIFT_INSECURE=1`. The full machine contract (capability matrix, path
policy, runner token flow) is in [connector_contract.md](connector_contract.md).

## Product Surface

The UI is a dark, animated single-page app (React 19 + Vite, Tailwind v4 + Framer
Motion); data-heavy lists are server-paginated.

- `Dashboard`: asset **scan status** (identified vs scanned vs pending) / asset /
  package / vulnerability posture.
- `Asset Inventory`: every asset (repo, image, Kubernetes workload, endpoint, and
  externally ingested ECS/cloud workload),
  filterable by type and **scan status**, with a per-asset scan badge. The detail
  view has **paginated** Components, Vulnerabilities, and non-CVE Findings tabs,
  plus relationships and **provenance** for images. The bundled scanner emits workload
  topology for Kubernetes/EKS; its ECS connector currently discovers running
  image targets and provenance metadata, not ECS workload assets or topology.
- `Endpoints`: developer-laptop assets with OS / employee / department metadata.
- `SBOM Analyzer`: package search → version drill-down → affected targets (paginated).
- `Vulnerabilities`: the single security view — **CVE findings** synced from the
  scanners (syft → grype), each with the affected package, severity, and the
  recommended upgrade (`fix_recommendation`) **when the scanner supplies a fixed
  version**. No accept/dismiss; no external OSV check (vulnerabilities come
  straight from the scan payload).
- `Malware Analysis`: two panes — **Alerts** (OSV `MAL-*` advisories matched against
  the inventory: package, advisory link, affected assets, NEW badge, active status) and
  **Configuration** (master enable toggle, interval, platform alerts on-by-default,
  optional Slack). A **Run analysis** button enqueues a job for the `malware-runner`.
  A red banner surfaces on the dashboard when alerts are active. Architecture:
  [docs/malware-analysis.md](docs/malware-analysis.md).
- `Sources`: UI-managed registry, service, and GitHub source configuration;
  credentials are entered directly and stored encrypted (needs `SUPPLYDRIFT_SECRET_KEY`).
  Each card has a **Scan** button that queues a run for the long-running runners
  (image + github `--serve` containers in compose) with a live status badge — see
  the scan queue in [connector_contract.md](connector_contract.md).

## API overview

Scanners push to one sync endpoint per source type:

```text
POST /api/sync/repositories
POST /api/sync/container-images        # accepts image provenance metadata
POST /api/sync/kubernetes-workloads
POST /api/sync/ecs-workloads           # normalized workload data from external producers
POST /api/sync/endpoints               # developer laptops / devices
```

Aliases are available (e.g. `registry`, `images`, `k8s-workloads`, `laptops`).
Each endpoint accepts source-scoped CycloneDX or normalized payloads.

Read APIs back the UI and require a human role with `read` or a `readonly` bearer
token (`runner` and `ingest` tokens intentionally do not have general read access):

```text
GET /api/summary
GET /api/assets?asset_type=container_image&scan_status=scanned&limit=50&offset=0
GET /api/assets/{id}                        # slim: counts + relationships + details
GET /api/assets/{id}/components?limit=50    # paginated; per-component finding_count
GET /api/assets/{id}/findings?limit=50      # paginated; package + fix_recommendation
GET /api/vulnerabilities?severity=high&search=&limit=50   # the CVE-findings view
GET /api/sbom/packages?search=openssl&limit=50
GET /api/sbom/versions?name=openssl&ecosystem=deb&limit=50
GET /api/sbom/assets?name=openssl&ecosystem=deb&version=1.1.1f-1ubuntu2.18&limit=50
```

`GET /api/graph` (asset nodes connected by `asset_relationships`) and
`GET /api/blast-radius` (one component → affected assets + findings) exist as
**APIs only** — there is no UI graph view yet.

Payload shapes, the source-configuration API (`/api/connectors`,
`/api/scanner/config`), the scan queue, the malware API, and the pagination
contract are all specified in [connector_contract.md](connector_contract.md).

## Diagnostics

- [`scripts/diag_endpoint_sync.py`](scripts/diag_endpoint_sync.py) — explains
  package-count gaps between a local endpoint scan and what the platform stored
  (normalized component-identity dedup vs. raw Syft artifact count). Advisory only;
  not part of the normal flow.
- [`scripts/run_malware_analysis.py`](scripts/run_malware_analysis.py) — manual
  local-dev helper for OSV malware analysis. Its complete workflow currently
  requires `SUPPLYDRIFT_AUTH=disabled`; for an auth-enabled deployment use the
  bundled malware runner with a `runner` token (see
  [`docs/malware-analysis.md`](docs/malware-analysis.md)).
