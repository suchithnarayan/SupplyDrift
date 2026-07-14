# SupplyDrift Platform

SupplyDrift is the product surface for phantom dependency analysis. The platform
stores scanner output, lets teams search packages across repository, image,
runtime, and endpoint SBOMs, and maintains vulnerability status for package
versions.

The UI is a React + TypeScript app in `frontend/`. The API is a FastAPI service
(uvicorn); all business logic lives in a single reusable `Store` class (`app.py`),
`server.py` is the HTTP layer (`create_app(store)`), and `run.py` is the uvicorn
launcher. The datastore is **MySQL** via `SUPPLYDRIFT_DATABASE_URL` (the
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

### Run locally without Docker

Prerequisites: Python 3.12+, and Node.js 20+ (only needed to build the UI). This
path uses the SQLite fallback datastore (a file under `data/`).

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
   ```

2. Start the backend — serves the API **and** the built UI on one port:

   ```bash
   cd platform
   pip install -r requirements.txt
   python3 run.py --load-demo            # --host/--port/--db; --reload for dev
   # or directly: SUPPLYDRIFT_DB=data/supplydrift.db uvicorn server:api --port 8765
   ```

3. Open <http://127.0.0.1:8765>.

> This runs the **platform only** — no scan runners. The UI's **Scan** button will
> queue a job and show *"Queued — no runner connected"* until a runner is polling.
> To actually execute scans, start a runner against the platform:
>
> ```bash
> python3 image-scanner/image_scan.py --serve \
>   --config-url http://127.0.0.1:8765/api/scanner/config --log-format json
> ```

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
| `SUPPLYDRIFT_PUBLIC_URL` | `http://localhost:8765` | Public URL used for CORS origins and Slack alert links. |
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

## Authentication

Auth is **on by default**. There are two planes:

- **Humans** sign in with a username/password; the server sets an httpOnly session
  cookie (CSRF-protected on writes). Roles: **admin** (manage users + tokens + all),
  **member** (read + operate + self-service non-runner scoped tokens), **viewer** (read-only).
- **Machines** use `Authorization: Bearer <token>` — scoped API tokens
  (`runner` / `ingest` / `readonly`), minted under **Access → API tokens**.
  `runner` tokens can fetch scanner credentials and require an admin.

  ```bash
  curl -H "Authorization: Bearer sdp_..." http://localhost:8765/api/summary
  ```

**First run:** set `SUPPLYDRIFT_ADMIN_USER` / `SUPPLYDRIFT_ADMIN_PASSWORD` in `.env`
(see `.env.example`). They seed the initial admin **once, on an empty database**, and
are **ignored on every later boot** (the check is "no users exist yet"). After you've
logged in you can safely **remove the password from `.env`** — the account lives in the
DB and you change it from the UI. If auth is on and these are unset with no users, the
API logs an error and returns `401` for everything until you set them and restart.

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
- `Asset Inventory`: every asset (repo, image, k8s/ECS workload, endpoint),
  filterable by type and **scan status**, with a per-asset scan badge. The detail
  view has **paginated** Components (with per-component finding counts) and
  Findings (each showing the affected package + recommended upgrade), plus
  relationships and **provenance** for images.
- `Endpoints`: developer-laptop assets with OS / employee / department metadata.
- `SBOM Analyzer`: package search → version drill-down → affected targets (paginated).
- `Vulnerabilities`: the single security view — **CVE findings** synced from the
  scanners (syft → grype), each with the affected package, severity, and the
  **recommended upgrade** (`fix_recommendation`). No accept/dismiss; no external
  OSV check (vulnerabilities come straight from the scan payload).
- `Malware Analysis`: two panes — **Alerts** (OSV `MAL-*` advisories matched against
  the inventory: package, advisory link, affected assets, NEW/UPDATE) and
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
POST /api/sync/ecs-workloads
POST /api/sync/endpoints               # developer laptops / devices
```

Aliases are available (e.g. `registry`, `images`, `k8s-workloads`, `laptops`).
Each endpoint accepts source-scoped CycloneDX or normalized payloads.

Read APIs back the UI and are available to any authenticated principal:

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

`GET /api/graph` (asset/component graph) and `GET /api/blast-radius` (component →
affected assets) exist as **APIs only** — there is no UI graph view yet.

Payload shapes, the source-configuration API (`/api/connectors`,
`/api/scanner/config`), the scan queue, the malware API, and the pagination
contract are all specified in [connector_contract.md](connector_contract.md).

## Diagnostics

- [`scripts/diag_endpoint_sync.py`](scripts/diag_endpoint_sync.py) — explains
  package-count gaps between a local endpoint scan and what the platform stored
  (purl-identity dedup vs. raw Syft artifact count). Advisory only; not part of
  the normal flow.
- [`scripts/run_malware_analysis.py`](scripts/run_malware_analysis.py) — manual
  runner for OSV malware analysis (see [`docs/malware-analysis.md`](docs/malware-analysis.md)).
