# Deploying and scheduling image scans

Run scanner workloads separately from the SupplyDrift API. Image discovery,
layer downloads, Syft cataloguing, and Grype matching are CPU-, disk-, memory-,
and network-intensive; the platform itself is a comparatively light HTTP and
database service.

SupplyDrift supports two runner models:

| Model | Command | Lifetime | Who starts a scan |
| --- | --- | --- | --- |
| Queue worker | `image_scan.py --serve --config-url ...` | Long-running | A user queues **Scan** or **Refresh** in the UI/API |
| Direct run | `image_scan.py --config-url ...` | One-shot | CronJob, systemd timer, CI schedule, EventBridge, or an operator |

Docker Compose uses an always-on queue worker. The platform does not currently
enqueue recurring image scans by itself, so use the direct model with an
external scheduler when periodic scanning is required. `--once` belongs to
queue-worker mode: it claims at most one already-queued job and does not create a
recurring scan.

## Authentication

An external runner needs a `runner`-scope API token for scanner-config fetches,
queue claims/completion, and sync uploads. An administrator creates it under
**Access -> API tokens**; the plaintext is shown once.

Set either:

```bash
export SUPPLYDRIFT_RUNNER_TOKEN='sdp_...'
# or mount a file and point the runner at it:
export SUPPLYDRIFT_RUNNER_TOKEN_FILE=/run/secrets/supplydrift-runner-token
```

The bundled Compose deployment is zero-touch: the platform creates the token
file and mounts the shared volume read-only into each runner. Do not copy that
Compose-managed token out of the volume. Runner tokens can obtain every
connector's decrypted scanner configuration; isolate them as privileged machine
credentials and revoke external tokens when they are no longer needed.

## Runner commands

An always-on worker claims image jobs queued by the platform:

```bash
python3 image-scanner/image_scan.py --serve \
  --config-url https://platform.example/api/scanner/config \
  --log-format json
```

A scheduled direct run fetches all enabled registry and service sources and
pushes each result immediately:

```bash
python3 image-scanner/image_scan.py \
  --config-url https://platform.example/api/scanner/config \
  --log-format json
```

Limit a direct run to one or more source names when the worker intentionally has
only that source's network access or credentials:

```bash
python3 image-scanner/image_scan.py \
  --config-url https://platform.example/api/scanner/config \
  --source prod-ecr --source prod-eks --log-format json
```

`--source` limits which connectors execute, but a direct unscoped
`--config-url` fetch still returns all enabled connector configuration and
secrets to that runner token. It is not a credential-disclosure boundary. Queue
workers add the claimed `connector_id` to their config fetch, although the token
itself remains globally authorized.

Queue workers are universal: an image worker can claim any image job and then
fetches configuration scoped to the claimed connector. Use the full runner image
for queue mode so a Kubernetes/EKS job is not claimed by a worker without
`kubectl` or AWS CLI.

Endpoints are different. The endpoint collector runs on each managed host and
posts to `/api/sync/endpoints`; the image runner does not pull endpoint data.

## Tooling and access by source

| Source | Runner requirements | Typical credential source |
| --- | --- | --- |
| Docker Hub / GHCR / Harbor | Syft, optional Grype, registry network | UI-managed secrets are encrypted by the platform and injected as `provider: static`; file/API-authored config may reference runner environment names |
| ECR | Syft, optional Grype, AWS CLI | IAM role/default chain, profile, or configured AWS identity |
| Kubernetes | Syft, optional Grype, `kubectl`, API-server reachability | Read-only kubeconfig or in-cluster ServiceAccount |
| EKS | Syft, optional Grype, AWS CLI, `kubectl` | IAM role/default chain plus generated kubeconfig |
| ECS | Syft, optional Grype, AWS CLI | IAM role/default chain |

Kubernetes and EKS also publish cluster/workload/image topology. ECS currently
publishes discovered running images with ECS discovery metadata, not ECS
workload topology assets.

## Build the reference runner image

Build from the repository root:

```bash
docker build -f image-scanner/deploy/runner.Dockerfile \
  -t supplydrift-image-runner:latest .
```

The current Dockerfile pins and checksum-verifies:

- Nono `0.67.1` (copied from a digest-pinned image);
- Syft `1.46.0`;
- Grype `0.115.0`;
- AWS CLI `2.35.21`; and
- kubectl `v1.36.2`.

It also preloads the Grype database, makes `/app` and `/opt/grype-db`
root-owned/read-only, and runs as UID `10001`. Rebuild the image regularly: the
Grype database never updates inside a running worker.

AWS CLI and kubectl are included by default. A direct, registry-only worker may
be made smaller with:

```bash
docker build -f image-scanner/deploy/runner.Dockerfile \
  --build-arg INSTALL_KUBECTL=false \
  --build-arg INSTALL_AWSCLI=false \
  -t supplydrift-registry-runner:latest .
```

Do not use that slim image for a universal queue worker.

The image sets `SUPPLYDRIFT_TOOL_SANDBOX=required` and
`SUPPLYDRIFT_SANDBOX_NETWORK=best-effort`. Each Syft/Grype invocation must pass
the Nono preflight and receives a fresh capability manifest. Best-effort affects
only the registry proxy for image Syft: if that proxy is unavailable, filesystem
and environment isolation stay active but pull egress becomes unrestricted and
a structured warning is emitted. Set `SUPPLYDRIFT_SANDBOX_NETWORK=require` when
that fallback is unacceptable. The precise boundary is documented in
[`../../supplydrift-sandbox/README.md`](../../supplydrift-sandbox/README.md).

## Kubernetes CronJob

[`k8s-cronjob.yaml`](k8s-cronjob.yaml) is a starting point for separate registry
and cluster direct scans. It includes non-root execution, dropped capabilities,
resource/ephemeral-storage budgets, non-overlap policy, read-only workload RBAC,
and a separate batch-node selector.

Before applying it:

1. Replace the example image with an immutable digest from your registry.
2. Change the platform URL and the `--source` name to match your deployment.
3. Create a UI-minted runner token as the referenced Kubernetes Secret.
4. Provision the referenced registry credentials out of band.
5. Review RBAC and network policies for the exact clusters and registries.

For example, write the token to a protected file without a trailing newline, then
create the Secret from that file so the secret value is not exposed in process
arguments:

```bash
kubectl -n supplydrift create secret generic supplydrift-runner-auth \
  --from-file=token=/secure/path/supplydrift-runner.token
```

The example manifest already reads that Secret with this entry in each runner:

```yaml
- name: SUPPLYDRIFT_RUNNER_TOKEN
  valueFrom:
    secretKeyRef:
      name: supplydrift-runner-auth
      key: token
```

For an in-cluster Kubernetes source, the included ServiceAccount/ClusterRole is
read-only. For EKS/ECR, prefer workload identity/IRSA and the default AWS
credential chain instead of static keys.

## systemd timer

Store the runner token and connector environment values in a root-owned file
such as `/etc/supplydrift/runner.env` with mode `0600`, then reference it without
putting secrets in the unit:

```ini
# /etc/systemd/system/supplydrift-image-scan.service
[Unit]
After=network-online.target docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/docker run --rm --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=20g \
  --security-opt no-new-privileges --cap-drop ALL \
  --env-file /etc/supplydrift/runner.env \
  supplydrift-image-runner:latest \
  --config-url https://platform.example/api/scanner/config --log-format json
```

```ini
# /etc/systemd/system/supplydrift-image-scan.timer
[Unit]
Requires=supplydrift-image-scan.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now supplydrift-image-scan.timer`. In a real
deployment, pin the runner image by digest and size the temporary filesystem for
the largest expected concurrent pulls.

## GitHub Actions

The most faithful CI deployment builds the reference image, so it includes the
same pinned Syft and Grype versions, immutable build-time Grype database
snapshot, and required sandbox as Compose:

```yaml
name: supplydrift-image-scan
on:
  schedule: [{cron: "0 * * * *"}]
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: Build scanner runner
        run: docker build -f image-scanner/deploy/runner.Dockerfile -t supplydrift-image-runner:ci .
      - name: Scan configured sources
        env:
          PLATFORM_URL: ${{ vars.PLATFORM_URL }}
          SUPPLYDRIFT_RUNNER_TOKEN: ${{ secrets.SUPPLYDRIFT_RUNNER_TOKEN }}
          DOCKERHUB_USER: ${{ secrets.DOCKERHUB_USER }}
          DOCKERHUB_PAT: ${{ secrets.DOCKERHUB_PAT }}
        run: |
          docker run --rm --read-only \
            --tmpfs /tmp:rw,nosuid,nodev,noexec,size=20g \
            --security-opt no-new-privileges --cap-drop ALL \
            -e SUPPLYDRIFT_RUNNER_TOKEN -e DOCKERHUB_USER -e DOCKERHUB_PAT \
            supplydrift-image-runner:ci \
            --config-url "${PLATFORM_URL}/api/scanner/config" --log-format json
```

Restrict repository/environment secrets and protect manual workflow execution in
accordance with your CI policy.

## AWS scheduled task

Run the reference image as an EventBridge-scheduled ECS/Fargate task. Assign a
least-privilege task role for ECR/ECS discovery, inject the platform runner token
from a secrets manager, use ephemeral storage sized for image layers, and keep
the task separate from the platform service. EKS scans additionally need cluster
API reachability and kubectl authentication.

## Cadence and efficiency

- Registries commonly run hourly to daily. `scan.pushed_within_days` limits
  discovery to recently pushed images, and `max_images_per_repo: 1` keeps the
  default latest-version scope.
- Cluster discovery commonly runs every 15-60 minutes because the running set
  changes more frequently.
- Re-scanning upserts image identity by digest/reference and refreshes the
  observation instead of creating a duplicate asset.
- `scanner.concurrency` controls parallel Syft runs. Tune it with CPU, memory,
  ephemeral storage, and registry limits together.
- Authenticate registry discovery/pulls and monitor provider rate-limit
  responses; limits vary by provider and account tier.

## Observability

- `--log-format json` produces one JSON object per progress or sandbox event on
  stderr.
- A run logs discovery, per-image outcomes, push counts, topology counts, total
  duration, and its final error count.
- Except for dry-run, direct mode exits non-zero for fatal discovery, SBOM, or
  push errors. Dry-run currently returns zero even when discovery logs errors.
  Grype-only failures are degraded warnings, so success does not guarantee CVE
  output. Queue mode reports fatal errors as `failed` and continues polling.
- Alert on scanner failures and on sandbox events with
  `filesystem_enforced: false` or
  `network_mode: "unrestricted-fallback"`.
- UI scan history represents queued `scan_runs`. A direct scheduled sync is not
  shown as a claimed queue run merely because it uploaded inventory.
