# Running SupplyDrift Locally With Docker Compose

This guide runs the complete SupplyDrift platform on one workstation:

- React web application and API
- MySQL database
- image and Kubernetes scanner runner
- GitHub repository scanner runner
- OSV malware-analysis runner
- endpoint inventory collector running on the host

The helper script used throughout this guide keeps the normal workflow short:

```bash
./scripts/local-compose.sh doctor
./scripts/local-compose.sh up
./scripts/local-compose.sh endpoint /home
```

## 1. Prerequisites

Run the commands from a Linux or WSL bash shell at the repository root. On
Windows, enable Docker Desktop's WSL integration for the distribution containing
the repository.

Required for the Compose platform:

- Docker Engine and the Docker Compose plugin
- `curl`

Required only for endpoint scanning:

- Syft
- Grype
- `jq`, `gzip`, and standard Linux shell tools

Optional for Kubernetes scanning:

- a working `kubectl`
- a kubeconfig at `$HOME/.kube/config`
- Docker Desktop Kubernetes, kind, minikube, or another reachable cluster

Confirm Docker and, when needed, Kubernetes are reachable:

```bash
docker version
docker compose version
kubectl config current-context
kubectl get nodes
```

## 2. Create The Local Configuration

Create `.env` once. If it already exists, keep it and skip the copy. The file is
excluded from Git and must never be committed.

```bash
test -f .env || cp .env.example .env
chmod 600 .env
```

Edit `.env` and replace the example values for:

| Setting | Purpose |
| --- | --- |
| `SUPPLYDRIFT_ADMIN_USER` | First local administrator username |
| `SUPPLYDRIFT_ADMIN_PASSWORD` | First local administrator password |
| `SUPPLYDRIFT_SECRET_KEY` | Encrypts connector credentials stored in MySQL |
| `MYSQL_PASSWORD` | Password used by the application database account |
| `MYSQL_ROOT_PASSWORD` | MySQL administrative password |

Generate suitable values without inventing passwords manually:

```bash
openssl rand -hex 24
python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'
```

Use the hexadecimal command for passwords and the Python command for
`SUPPLYDRIFT_SECRET_KEY`. The admin account is seeded only when the database has
no users; changing `.env` later does not change an existing administrator's
password.

Check the environment without printing any secret values:

```bash
./scripts/local-compose.sh doctor
```

Endpoint tools and the endpoint token are reported as optional because the
platform can run without scanning the host.

## 3. Start The Platform

```bash
./scripts/local-compose.sh up
```

The helper performs the following operations:

1. validates Docker and `.env`
2. mounts `$HOME/.kube/config` when it exists
3. builds the current source tree
4. starts MySQL, the platform, and all three runners
5. waits for `GET /api/health` to succeed

Open <http://localhost:8765> and sign in with the administrator credentials from
`.env`.

Check service state at any time:

```bash
./scripts/local-compose.sh status
```

Every service should be running, and MySQL and the platform should report
`healthy`.

## 4. Add Local Test Sources

Sources are managed through **Sources -> Add source**. Public test targets do not
need credentials.

### Docker Hub

| Field | Value |
| --- | --- |
| Name | `Local DockerHub` |
| Source type | `dockerhub` |
| Public images | `hariprasadpo75/sample:updated` |
| Credentials | Leave blank |

Click **Scan**. A successful run creates a container-image asset with Syft
components and Grype findings.

### GitHub

| Field | Value |
| --- | --- |
| Name | `Local GitHub` |
| Source type | `github` |
| Public repos | `public-apis/public-apis` |
| Credentials | Leave blank |

Click **Refresh** first. Refresh verifies discovery without cloning or scanning
the repository. Then click **Scan** to run repository analysis, Syft, and Grype.

### Kubernetes

First make sure the runner can reach the cluster:

```bash
docker compose -p supplydrift-local exec image-runner kubectl get pods -A
```

For Docker Desktop Kubernetes, add this source:

| Field | Value |
| --- | --- |
| Name | `Local Kubernetes` |
| Source type | `kubernetes` |
| Kubeconfig path | `/home/app/.kube/config` |
| Contexts | `docker-desktop` |
| Cluster name | `docker-desktop` |
| Namespaces | `default` |
| Object kinds | `Deployment, ReplicaSet, Pod` |

Create a small workload when the namespace has nothing suitable to scan:

```bash
kubectl get deployment supplydrift-example -n default >/dev/null 2>&1 \
  || kubectl create deployment supplydrift-example --image=nginx:latest
kubectl rollout status deployment/supplydrift-example -n default
```

Click **Scan** on the Kubernetes source. Expected assets include the cluster,
workload, and running image. An image using `latest` should also produce a
mutable-image finding.

## 5. Configure And Run The Endpoint Scanner

The endpoint collector runs on the host, not inside Compose. In WSL it inventories
the WSL filesystem; it does not inventory the native Windows filesystem.

### Create The Token

In SupplyDrift, open **Access -> API tokens** and create a token with scope
**`ingest`**. Copy it when displayed; the value is shown only once.

Add the token to the gitignored `.env` file:

```dotenv
ENDPOINT_SCANNER_TOKEN=sdp_replace_with_the_generated_token
```

Keep `.env` private:

```bash
chmod 600 .env
./scripts/local-compose.sh doctor
```

The helper reads only this key, places the value in a temporary mode-600 file,
and removes that file after the collector exits. The token is never placed in a
process argument or printed in logs.

### Scan `/home`

```bash
./scripts/local-compose.sh endpoint /home
```

The first run is a forced full scan. It:

1. catalogs packages under `/home` with Syft
2. evaluates the SBOM with Grype
3. sends compressed vulnerability and package batches to
   `/api/sync/endpoints`
4. fails the command if an upload cannot be delivered
5. writes persistent local state under
   `$HOME/.local/state/supplydrift-endpoint`

The summary must show `status: success`, nonzero packages, all batches uploaded,
and zero queued, dropped, upload-failure, and scan-failure counts.

Scan only this repository when a shorter developer test is preferable:

```bash
./scripts/local-compose.sh endpoint "$PWD"
```

Test the normal repeat-run change gate without forcing Syft and Grype:

```bash
./scripts/local-compose.sh endpoint /home --incremental
```

When dependency-relevant files have not changed, the collector sends a small
heartbeat instead of repeating the complete scan. Keep the state directory to
preserve both this behavior and the endpoint identity.

Verify the result in **Endpoints**, then open the asset's **Components** and
**Findings** tabs. The same CVEs appear in the global **Vulnerabilities** view,
and endpoint packages are searchable in **SBOM Analyzer**.

## 6. Malware Analysis

Open **Malware Analysis**, enable analysis and platform alerts, then select
**Run analysis**. The malware runner retrieves the current OSV `MAL-*` delta and
matches it against ingested components. Disable scheduled analysis afterward
when only a one-time local test is required.

## 7. Observe And Verify The System

Follow every service:

```bash
./scripts/local-compose.sh logs
```

Follow only selected runners:

```bash
./scripts/local-compose.sh logs image-runner github-runner
```

Use `Ctrl+C` to stop following logs; the containers continue running.

An end-to-end local run should show:

- source cards ending in `succeeded`
- repository, image, Kubernetes, and endpoint assets
- nonzero component counts on scanned assets
- Grype CVE findings and available fix recommendations
- Kubernetes cluster-to-workload and workload-to-image graph edges
- no queued or dropped endpoint batches
- no unexpected traceback or error-level runner logs

Vulnerability totals are expected to change as images, repositories, and the
Grype database change. Validate behavior and nonzero inventory rather than
hard-coding exact CVE totals.

## 8. Stop, Restart, Or Reset

Stop and remove containers while preserving MySQL data and application state:

```bash
./scripts/local-compose.sh down
```

Start again with the same data:

```bash
./scripts/local-compose.sh up
```

For an intentional clean reset, remove the local Compose volumes:

```bash
docker compose -p supplydrift-local --env-file .env down -v
```

The `-v` operation permanently deletes the local MySQL database, users,
connectors, scan history, and generated runner token. Do not use it when data
must be retained.

## 9. Common Problems

### Port 8765 is already allocated

Only one local stack can bind the default port. Find the existing container:

```bash
docker ps --filter publish=8765
```

Stop the other Compose project before starting this one.

### Login fails after changing `.env`

The first administrator is seeded only on an empty database. Use the password
stored in the existing account, reset it through an administrator, or perform an
intentional volume reset.

### Endpoint upload returns 401 or 403

Confirm `ENDPOINT_SCANNER_TOKEN` contains an active `ingest` token, appears only
once in `.env`, and has no spaces around the `=`. Revoke and replace exposed
tokens rather than reusing them.

### Endpoint collector refuses the token file or `.env`

```bash
chmod 600 .env
```

The collector deliberately rejects broadly readable secret files.

### Kubernetes works on the host but not in the runner

```bash
docker compose -p supplydrift-local exec image-runner kubectl get pods -A
```

For Docker Desktop, use the `docker-desktop` context. Other local clusters may
need a kubeconfig server address reachable from containers rather than
`127.0.0.1`.

### A scan remains queued

Check that the appropriate runner is running and polling:

```bash
./scripts/local-compose.sh status
./scripts/local-compose.sh logs image-runner github-runner
```

Registry and Kubernetes jobs use `image-runner`; repository jobs use
`github-runner`; malware jobs use `malware-runner`.

## Security Notes

- Never commit `.env`, API tokens, connector credentials, or endpoint state.
- Keep authentication enabled, even for local testing.
- The local platform binds to `127.0.0.1` by default.
- `SBOM_ALLOW_INSECURE=true` is used by the helper only because the endpoint and
  platform communicate over localhost HTTP. Use HTTPS for remote endpoints.
- Public GitHub and DockerHub examples require no credentials.
- Image and repository runners require a pinned per-target Syft/Grype sandbox,
  use read-only root filesystems, and keep writable job state on ephemeral
  `tmpfs`. A structured warning identifies registry pulls that use the
  documented filesystem-only egress fallback on hosts without domain proxy
  enforcement.
- Parent-side Git, kubectl, and AWS CLI caches also live under that ephemeral
  `/tmp` home; kubeconfig and optional AWS credential files remain on their
  explicit read-only mounts.
- Revoke temporary endpoint tokens after testing when they are no longer needed.

For production endpoint scheduling, queue controls, full-filesystem scans, and
fleet rollout guidance, see
[`endpoint-dep-inventory/README.md`](../endpoint-dep-inventory/README.md).
