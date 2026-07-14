# k8s-cartographer

> Kubernetes cluster-wide dependency cartography — **SupplyDrift Vector 3**

Lockfile-based SCA never looks at what is *actually running* in your clusters.
`k8s-cartographer` treats the cluster as the source of truth: it enumerates every
workload, resolves the container image each one runs, and flags two classes of
phantom dependency that pipelines and SCA miss entirely:

- 🕳️ **Shadow deployments** — workloads applied directly to the cluster with
  interactive clients such as `kubectl apply` or `kubectl run`, with **no
  GitOps, Helm, or operator provenance**. These may bypass the normal delivery
  pipeline and its associated review and scanning controls.
- 📌 **Mutable / untrusted images** — containers running `:latest` (or any
  non-digest tag) or pulling from registries outside your approved allowlist.

It emits a [SupplyDrift platform](../../platform) sync payload and can POST it
straight to `/api/sync/kubernetes-workloads`.

> This component is bundled inside `image-scanner/` as the `k8s_cartographer`
> package. Run it standalone with `python3 k8s_scan.py ...` from the
> `image-scanner/` directory; its collector is also reused by the image
> scanner's `kubernetes` connector.

## Workloads covered

`Deployment`, `StatefulSet`, `DaemonSet`, `CronJob`, `Job`, `ReplicaSet`, and
bare `Pod`s — including their `init`, sidecar, and `ephemeral` containers. By
default only *root* workloads are inventoried (a `Deployment`, not the
ReplicaSets/Pods it churns); pass `--include-owned` for the full tree.

## Install

The scanner core is **standard-library only**. PyYAML is optional and only
needed for `--manifests` (scanning YAML manifest directories).

```bash
# Optional: only required for --manifests
pip install -r requirements.txt
```

For a **live** scan it shells out to `kubectl` (read-only `kubectl get`), so a
working kubeconfig is all you need. Offline JSON-dump scans need nothing beyond
Python; YAML manifest directories require PyYAML as described above.

## Usage

```bash
# Offline: a captured kubectl dump (no cluster required)
kubectl get deployments,statefulsets,daemonsets,cronjobs,jobs,replicasets,pods \
  --all-namespaces -o json --show-managed-fields > cluster-dump.json
python3 k8s_scan.py --from-json cluster-dump.json --cluster-name prod-eks-1

# Offline: a GitOps repo or `helm template` output
python3 k8s_scan.py --manifests ./gitops/

# Live cluster (uses kubectl + your current context)
python3 k8s_scan.py --context prod-eks-1 --provider aws --environment production

# Restrict trust to approved registries (globs supported)
python3 k8s_scan.py --from-json cluster-dump.json \
  --trusted-registry '123456789012.dkr.ecr.*' --trusted-registry 'ghcr.io'

# Emit the normalized payload and push it to the platform. Put a UI-minted
# ingest token in a mode-600 file first.
SUPPLYDRIFT_RUNNER_TOKEN_FILE=/secure/path/supplydrift-ingest.token \
  python3 k8s_scan.py --from-json cluster-dump.json \
  --format json --push http://127.0.0.1:8765

# CI gate: non-zero exit if anything is critical
python3 k8s_scan.py --context prod --fail-on critical
```

The captured dump includes full workload specs and managed fields. Those can
contain literal environment values, command arguments, and sensitive metadata;
store the dump with restrictive permissions, never commit it, and delete it
when the offline analysis is complete.

### Options

| Flag | Description |
|------|-------------|
| `--from-json FILE` | Offline `kubectl get ... -o json` dump |
| `--manifests DIR` | Directory of YAML/JSON manifests (needs PyYAML for YAML) |
| `--kubeconfig / --context / --namespace` | Live scan targeting |
| `--kubectl-bin PATH` | kubectl binary to invoke (default `kubectl`) |
| `--cluster-name` | Cluster name (auto-detected for live scans) |
| `--provider` | Cloud provider tag (`aws`, `gcp`, …) |
| `--environment` | Environment tag (`production`, …) |
| `--trusted-registry PATTERN` | Approved registry (repeatable, glob) |
| `--include-owned` | Inventory controller-owned children too |
| `--format {table,json}` | Output format (default `table`) |
| `-o, --output FILE` | Write output to a file |
| `--push URL` | POST the payload to a platform base URL |
| `--fail-on {critical,high,medium,low}` | Exit 1 at/above this severity |
| `--version` | Print the scanner version and exit |

`--push` sends an `Authorization: Bearer` header from
`SUPPLYDRIFT_RUNNER_TOKEN`, or from `SUPPLYDRIFT_RUNNER_TOKEN_FILE` (default
`/run/supplydrift/runner.token`). An `ingest`-scope API token is sufficient and
recommended for this standalone push; a `runner` token also works but adds
configuration and queue authority needed only by the bundled worker. Collection
and analysis need no platform token when output stays local.

## How shadow deployments are detected

For each root workload the scanner looks for evidence of a **sanctioned delivery
path** in the live object's metadata:

- **GitOps / Helm markers** — Argo CD (`argocd.argoproj.io/*`), Flux
  (`kustomize.toolkit.fluxcd.io/*`, `helm.toolkit.fluxcd.io/*`), Helm
  (`meta.helm.sh/*`, `app.kubernetes.io/managed-by: Helm`).
- **`managedFields` manager** — automation managers (`helm`,
  `argocd-application-controller`, `kustomize-controller`,
  `kube-controller-manager`, operators, …) vs. interactive clients
  (`kubectl-client-side-apply`, `kubectl-edit`, `kubectl-run`, `k9s`, …).

A workload with **no** sanctioned provenance is flagged `shadow_deployment`:

| Signal | Confidence → Severity |
|--------|----------------------|
| Interactive `kubectl` manager / bare Pod | high → `critical` |
| `kubectl` last-applied with no GitOps | medium → `high` |
| No provenance metadata at all | medium → `high` |

Every finding records the reasons, the `managedFields` managers, and the
service account in its evidence so a human can confirm the verdict.

> **Orphan images** (running containers with no source repo or CI pipeline) need
> cross-source correlation. This scanner supplies the runtime asset and
> image-to-workload edge, but the current platform does not automatically infer
> orphan status by joining repository, registry, and runtime inventories. A
> producer must submit explicit provenance relationships, or an operator must
> perform that correlation separately. CVE flagging for image contents is the
> image scanner's job (Vector 2).

Shadow detection is metadata-based evidence, not proof of how a workload was
created. Custom delivery controllers may be reported as shadows until they add a
recognized managed-by label/annotation or manager marker. Review the recorded
reasons and managers before remediation.

## Output → platform mapping

The normalized payload maps directly onto the platform data model:

- `k8s_cluster` asset (one per cluster)
- `k8s_workload` asset per workload **container** (matches the platform's
  `k8s_workload_assets` schema: namespace, kind, name, container, SA, image)
- `container_image` asset per unique image reference
- relationships: `workload —belongs_to→ cluster`, `image —runs_in→ workload`
- findings: `shadow_deployment`, `unpinned_image`, `untrusted_registry`

The relationship directions above are literal: workload `belongs_to` cluster,
and image `runs_in` workload. The standalone cartographer does not extract an
SBOM or create component/CVE records; the integrated `kubernetes`/`eks` image
pipeline publishes topology and then scans the same discovered images.

## Execution trust boundary

Live collection shells out to `kubectl` in the trusted runner process. The
workload `kubectl get` call strips `SUPPLYDRIFT_RUNNER_TOKEN` and
`SUPPLYDRIFT_SECRET_KEY` from its child environment while retaining `PATH`,
`HOME`, kubeconfig, and AWS values required by Kubernetes/EKS authentication.
Context listing and cluster-name autodetection currently inherit the parent
environment. Offline JSON/manifest parsing and all cartography heuristics also
run in the trusted Python process.

The shared Nono capability sandbox is intentionally limited to Syft and Grype;
it does not wrap `kubectl`, manifest parsing, or this analyzer. Run the
cartographer as a non-root user, use read-only Kubernetes RBAC and kubeconfig
mounts, treat cluster-returned metadata as untrusted output, and keep the runner
separate from the platform. See
[`../../supplydrift-sandbox/README.md`](../../supplydrift-sandbox/README.md) for
the exact parser boundary.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pytest pyyaml
python3 -m pytest -q
```

A labeled offline fixture lives at `tests/fixtures/cluster-dump.json` (a mix of
Helm/Argo/Flux-managed workloads and hand-applied shadow workloads).
