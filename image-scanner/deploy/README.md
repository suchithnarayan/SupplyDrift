# Scheduling SupplyDrift scans (any source)

The end goal: a **runner** keeps checking each configured source for new
images/workloads, builds their SBOMs, and syncs them to the **platform**, on a
schedule — with the runner on **separate compute** from the application.

## The model: platform vs runner

| | Platform | Runner |
|---|---|---|
| Role | Store + UI + sync/config API | Discover → pull → syft SBOM → push |
| Lifetime | One long-running service | Ephemeral, runs on a schedule, exits |
| Load | Light, steady (DB + HTTP) | Heavy, bursty (pulls + unpacks layers, runs syft) |
| State | The DB (persistent volume) | Stateless / disposable |
| Scale | Single instance | Many, in parallel (one per registry/cluster/region) |

Keep them apart: syft pulling and unpacking image layers is CPU/disk/RAM/network
intensive and must not contend with the API/UI. Run runners on a **separate node
pool / VM / CI runner / Fargate task**.

## One command scans every configured source

Configure sources **once** (UI → Sources, or a config file). Then the runner with
`--config-url` fetches **all enabled sources** (registries *and* services) and
scans them:

```bash
python3 image_scan.py --config-url https://platform/api/scanner/config --log-format json
```

Add a source in the UI → the **next scheduled run picks it up** automatically. The
command is identical regardless of source type — Docker Hub, GHCR, Harbor, ECR,
Kubernetes, EKS, ECS. (Endpoints/laptops are different: an agent on each device
posts to `POST /api/sync/endpoints`; they aren't pulled by a runner.)

## What each source needs on the runner

| Source | Runner needs | Secret (by reference) |
|---|---|---|
| `dockerhub` / `ghcr` / `harbor` | syft + network | registry PAT via env |
| `ecr` | syft + AWS CLI | IAM role / keys |
| `kubernetes` | syft + kubectl + cluster reach | kubeconfig / in-cluster SA |
| `eks` / `ecs` | syft + AWS CLI (+ kubectl for eks) | IAM role |

Because access differs, the common pattern is **multiple runners**, each scheduled
separately and scoped with `--source <name>` — e.g. a *registry runner* (only
registry PATs) and a *cluster runner* (kube/AWS access). All push to one platform.
See [`k8s-cronjob.yaml`](k8s-cronjob.yaml) for exactly that.

## Build the runner image

```bash
docker build -f image-scanner/deploy/runner.Dockerfile -t supplydrift-runner:latest .
```
kubectl and the AWS CLI are included by default (for Kubernetes / EKS / ECR
sources). For a slim registry-only image, build with
`--build-arg INSTALL_KUBECTL=false --build-arg INSTALL_AWSCLI=false`.

The Dockerfile pins **syft 1.44.0** and **grype 0.114.0** (per-arch SHA256
checksums, overridable via `--build-arg SYFT_VERSION=…` after updating the
checksum args), pre-bakes the grype vulnerability DB, and installs Python
dependencies with `pip --require-hashes` — bumping a dependency means
regenerating the hashed requirements file.

## Schedule it

### Kubernetes CronJob (recommended for k8s shops)
Use [`k8s-cronjob.yaml`](k8s-cronjob.yaml): separate `nodeSelector`, resource
requests/limits (note **ephemeral-storage** — syft needs disk for layers),
`concurrencyPolicy: Forbid`, secrets from k8s Secrets, read-only RBAC for the
cluster runner.

### systemd timer (dedicated worker VM)
```ini
# /etc/systemd/system/supplydrift-scan.service
[Service]
Type=oneshot
Environment=DOCKERHUB_USER=...  DOCKERHUB_TOKEN=...
ExecStart=/usr/bin/docker run --rm \
  -e DOCKERHUB_USER -e DOCKERHUB_TOKEN \
  supplydrift-runner:latest \
  --config-url https://platform.internal/api/scanner/config --log-format json
```
```ini
# /etc/systemd/system/supplydrift-scan.timer
[Timer]
OnCalendar=hourly
Persistent=true
[Install]
WantedBy=timers.target
```
`systemctl enable --now supplydrift-scan.timer`

### GitHub Actions (no infra to run)

Pin the action by commit SHA and install syft at a pinned, checksum-verified
version — a supply-chain scanner's own pipeline should not use the mutable-tag
and `curl | sh` patterns it flags:

```yaml
name: supplydrift-scan
on:
  schedule: [{cron: "0 * * * *"}]
  workflow_dispatch:
jobs:
  scan:
    runs-on: ubuntu-latest          # CI runner = separate compute
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683   # v4.2.2
      - name: Install syft (pinned + checksum-verified)
        run: |
          version=1.44.0
          sha=0e91737aee2b5baf1d255b959630194a302335d848ff97bb07921eb6205b5f5a
          curl -sSfL -o /tmp/syft.tgz "https://github.com/anchore/syft/releases/download/v${version}/syft_${version}_linux_amd64.tar.gz"
          echo "$sha  /tmp/syft.tgz" | sha256sum -c -
          sudo tar -xzf /tmp/syft.tgz -C /usr/local/bin syft
      - run: pip install pyyaml
      - run: python3 image-scanner/image_scan.py --config-url ${{ vars.PLATFORM_URL }}/api/scanner/config --log-format json
        env:
          DOCKERHUB_USER: ${{ secrets.DOCKERHUB_USER }}
          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}
```

### AWS (serverless, fully isolated from the app)
Run the runner image as an **ECS Scheduled Task** (EventBridge cron → Fargate).
Give the task an IAM **task role** with ECR/ECS read access; no static keys.

## Cadence & efficiency

- **Registries**: hourly–daily. Set `scan.pushed_within_days: 1` so each run only
  scans recently-pushed images (incremental — avoids re-pulling everything);
  `max_images_per_repo: 1` keeps it to the latest tag.
- **Clusters**: every 15–60 min (the running set changes often).
- **Idempotent**: re-scanning **upserts** by digest, so re-runs just refresh
  `last_seen` — safe to run as often as you like.
- **Concurrency**: `scanner.concurrency` = parallel syft runs; tune to runner CPU.
- **Rate limits**: authenticate registries (anonymous Docker Hub = 100 pulls/6h/IP).

## Observability & alerting

- `--log-format json` → one JSON line per event, for Loki/CloudWatch/Datadog.
- Every run ends with `done … pushed=N failed=M errors=K`, and the process exits
  **non-zero when there are errors** — wire that to your alerting (CronJob failure,
  CI red, systemd `OnFailure`).
- Each run also records a `scan_job` on the platform (visible under the connector).
