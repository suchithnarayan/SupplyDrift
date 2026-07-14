# Authentication

`image-scanner` keeps authentication as a dedicated component (`src/image_scanner/auth/`)
so the core scanner and connectors never deal with credentials directly. There
are three independent credential planes: the platform runner token, registry
pull credentials, and AWS credentials. They are deliberately not interchangeable.

## 1. Platform runner authentication

When platform authentication is enabled, config fetches, queue claims and
completion, and inventory uploads use a `runner`-scope API token:

```bash
export SUPPLYDRIFT_RUNNER_TOKEN='sdp_...'
python3 image_scan.py --serve \
  --config-url https://platform.example/api/scanner/config
```

The lookup order is `SUPPLYDRIFT_RUNNER_TOKEN`, then the file named by
`SUPPLYDRIFT_RUNNER_TOKEN_FILE`, then
`/run/supplydrift/runner.token`. Docker Compose generates and shares the default
file automatically. For an external runner, an administrator creates a runner
token under **Access -> API tokens** and stores it in the runtime's secret
manager. The value is shown once and remains valid until revoked.

A config-file run that only uploads inventory can put an `ingest`-scope token in
the same environment variable/file. It cannot use that token with `--config-url`
or `--serve`, because scanner-config and queue routes require runner capability.

A runner token can fetch any connector's decrypted scanner configuration. The
serve loop normally supplies the connector ID associated with its claimed job;
the response keeps all connector topology but reveals secrets only for that
connector and masks the others. This reduces routine secret exposure but does
not reduce the token's authority, because it can change or omit the scope. Treat
the token as a privileged machine secret.

## 2. Registry pull credentials — the `auth` block

Docker Hub, GHCR, and Harbor authenticate with a registry credential, declared in
each registry's `connection.auth`, discriminated by `provider`:

| provider | Meaning | Key fields |
|----------|---------|------------|
| `none` | Anonymous (public images) | – |
| `docker` | Reuse `~/.docker/config.json` + credential helpers | `config_path` (optional) |
| `env` | Credentials from environment variables | `username_env`, `password_env`, `token_env` |
| `static` | Inline credentials (**discouraged**) | `username`, `password`, `token` |

```yaml
registries:
  - name: ghcr-acme
    type: ghcr
    connection:
      owner: acme
      auth: { provider: env, username_env: GH_USER, token_env: GH_PAT }   # classic PAT, read:packages
```

Per-registry notes:
- **Docker Hub** — a Personal Access Token (PAT) or Org Access Token; the
  username is your Hub user / org name. Select `auth: { provider: docker }` to
  reuse an existing `docker login`; omitted auth is anonymous.
- **GHCR** — a **classic** PAT with the `read:packages` scope (fine-grained PATs
  are not supported by the Packages API).
- **Harbor** — a robot account; `username` is the full robot name
  (`robot$project+name`), `password` is its secret.

`provider: docker` resolves credentials the way the Docker CLI does: it reads
`config_path` if set, else `$DOCKER_CONFIG/config.json`, else
`~/.docker/config.json`, honoring both inline auths and credential helpers
(`credHelpers`/`credsStore`, invoked as `docker-credential-<helper>`; helper
names are allowlisted to safe characters).

These four providers are the supported registry-auth set. There is no
first-class GCR/Artifact Registry or ACR connector/auth flow; unsupported source
types or providers fail when the corresponding connector/auth resolver is
built, rather than through a single top-level config-schema rejection. The only
cloud-specific credential component is AWS (below).

## 3. AWS credentials — the `aws_auth` block

ECR, ECS, and EKS authenticate to AWS through one shared component
(`auth/aws.py`, `AwsSession`). Declare an `aws_auth` block with any one means;
combine `role_arn` with a base identity for cross-account access:

```yaml
aws_auth:
  profile: prod                       # a named ~/.aws profile
  access_key_id: AKIA...              # or static keys
  secret_access_key: ...
  session_token: ...                  # optional, for temporary keys
  role_arn: arn:aws:iam::123:role/X   # assume this role via STS
  external_id: ...                    # optional, paired with role_arn
  region: us-east-1                   # default region
  regions: [us-east-1, eu-west-1]     # regions services enumerate
```

Resolution follows the official AWS credential precedence:

- static `access_key_id`/`secret_access_key` → exported as env for child `aws`
  calls (and used as the base identity for `assume-role`);
- `role_arn` → `aws sts assume-role` (using the static keys or `profile` as the
  base), temporary credentials cached to expiry;
- `profile` (no `role_arn`) → passed as `--profile` so the CLI resolves it
  (including any `role_arn`/`source_profile` the profile declares);
- **omit the block entirely** → the AWS default credential chain (env vars,
  shared config, IRSA, ECS task role, EC2 instance profile). This is the right
  choice in CI and in-cluster.

ECR pull tokens are minted with `aws ecr get-login-password` through the same
session (username `AWS`, valid 12h, cached in memory).

## 4. How services pull — the registry auth index

Service connectors (Kubernetes, ECS, EKS) discover images but have no pull
credentials of their own. They resolve each pull through the **`RegistryAuthIndex`**,
built once from the configured `registries`:

1. If the discovered image's registry host matches a configured registry, **reuse
   that registry's credential** (Docker Hub PAT, GHCR PAT, Harbor robot, or an ECR
   token minted from that registry's `aws_auth`).
2. Otherwise, if the host is ECR and the service has its own `aws_auth`, mint a
   token from the service's `AwsSession`.
3. Otherwise the pull is anonymous. The sandboxed extractor has no ambient
   Docker-config fallback.

So a Kubernetes/EKS/ECS cluster running an ECR + GHCR + Harbor image will pull
each one using the matching registry's already-configured authentication — no
per-cluster credential duplication.

## 5. Sandbox and trusted-parent boundary

Credential discovery happens in the trusted Python parent. That parent reads
the selected environment variables, calls AWS CLI, reads an explicitly selected
Docker config, or invokes its allowlisted Docker credential helper. Docker config
and helper processes are never granted to the Syft child. Only the credential
resolved for the current image is copied into Syft's allowlisted environment.

When the Nono sandbox is active, each Syft/Grype invocation receives a fresh
filesystem, environment, network, and process capability manifest. The child
cannot read the platform runner token, AWS configuration, kubeconfig, Docker config, parent `/proc`
environment, application tree, or other targets. Exact supplied Syft token and
password values are redacted from captured stdout/stderr before returning to the
parent. This is targeted credential redaction, not general output DLP.

Grype gets the current temporary SBOM and, when present, read-only access to the
immutable local vulnerability database. It receives no registry credential and
its network is blocked.

### Sandboxed pull egress

Hosted runners try to proxy each Syft pull through a target-scoped domain
allowlist. Docker Hub additionally permits its token service and blob CDN;
GHCR additionally permits its package-blob host; Quay permits its CDN; ECR
permits only the regional Starport layer bucket associated with its registry
host. Other/private registries remain restricted to their configured host, so
an off-host storage redirect is denied while the proxy is active.

`SUPPLYDRIFT_TOOL_SANDBOX=required` requires the exact pinned Nono version and a
successful filesystem and blocked-network preflight. The Compose runner uses
this mode. Source-tree execution defaults to `auto`, which warns and runs the
tool locally with a minimal environment if the sandbox is unavailable; `off` is
an explicit development override.

When the filesystem sandbox is active but the domain proxy cannot start,
`SUPPLYDRIFT_SANDBOX_NETWORK=best-effort` retains filesystem/environment
isolation, permits unrestricted pull egress, and emits a structured
`unrestricted-fallback` event. Set it to `require` to fail the image scan closed.
Blocked-network jobs such as Grype never use this proxy fallback.

The Python runner, connector HTTP discovery, AWS CLI, `kubectl`, Docker
credential helpers, OSV queries, platform requests, and publishing remain
outside Nono and retain the access required for their jobs. The workload
`kubectl get` subprocess removes the runner-token and platform-key environment
variables while retaining kubeconfig and AWS variables so EKS exec
authentication works. Context listing and cluster-name autodetection currently
inherit the parent environment, so the stripping is not a universal `kubectl`
guarantee. The capability sandbox is a hostile-parser boundary for Syft/Grype,
not a container-wide firewall. See
[`../../supplydrift-sandbox/README.md`](../../supplydrift-sandbox/README.md).

## 6. Per-environment recipes

### Local development
- Platform: with auth enabled, set a UI-minted `SUPPLYDRIFT_RUNNER_TOKEN`; with
  auth disabled on a trusted loopback-only development instance, no token is
  needed.
- Public images: `auth: { provider: none }` (or omit). Copy
  [`../config.example.yaml`](../config.example.yaml) to a protected local config
  and adjust its sources.
- Anything `docker login`-ed: `auth: { provider: docker }`.
- AWS: `aws sso login --profile X` (or `aws configure`), then
  `aws_auth: { profile: X, regions: [...] }`.
- Kubernetes: point `connection.kubeconfig`/`contexts` at your clusters; configure
  the registries those images live in so the index can authenticate pulls.

### CI (GitHub Actions / GitLab)
- Platform: inject a `runner` token from the CI secret store; do not put it in
  the scanner YAML.
- AWS: federate via OIDC (`aws-actions/configure-aws-credentials`) and omit
  `aws_auth` (the ambient credentials resolve through the default chain), or set
  `aws_auth: { role_arn: ... }`.
- Registry PATs: store as CI secrets and reference with
  `auth: { provider: env, username_env: ..., password_env: ... }`.

### In-cluster (CronJob / Job)
- Platform: inject a UI-minted runner token from a Kubernetes Secret, or mount it
  as a file and set `SUPPLYDRIFT_RUNNER_TOKEN_FILE`.
- Kubernetes control plane: use the pod's ServiceAccount (the collector falls back
  to in-cluster config when no kubeconfig is set).
- AWS data plane: attach **IRSA** to the ServiceAccount and omit credential
  fields so the default chain picks up the role. Still declare the regions each
  ECR/EKS/ECS source should enumerate. A generic `kubernetes` source also needs a
  matching configured `ecr` registry entry (with region/account scope) before
  the registry-auth index can mint ECR pull credentials.

## 7. Security notes

- Never commit `provider: static` / inline AWS keys — they exist for quick local
  tests only. Prefer `env` (CI secrets) or roles (no long-lived secrets).
- Resolved pull secrets are passed to Syft through its allowlisted environment,
  never argv. The scanner does not write the resolved credential to disk; a
  user-supplied `provider: static` config is itself a secret-bearing file and
  must be protected accordingly. Minted AWS/ECR tokens remain in parent-process
  memory for the run.
- For no-pull validation, use `--dry-run --format targets` to confirm discovery
  and authentication wiring. Discovery can still call registry, Kubernetes, or
  AWS APIs; it is air-gapped only when those configured sources are reachable
  within the air gap.

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Platform `HTTP 401/403` | missing, invalid, or wrong-scope API token | set a valid `runner` token in `SUPPLYDRIFT_RUNNER_TOKEN` or its configured file |
| GHCR `HTTP 401/403` listing packages | missing/fine-grained PAT | use a **classic** PAT with `read:packages` |
| Docker Hub `login failed` | wrong PAT or username | check the configured `username`/`password` (or the env vars they reference); use `provider: docker` to reuse `docker login` |
| Harbor `HTTP 401` | wrong robot name/secret | use the full `robot$project+name` and its secret |
| syft `UNAUTHORIZED` on pull (service) | registry not configured | add the registry under `registries:` so the index can authenticate it |
| `'aws' not found` | AWS CLI not installed | install the AWS CLI (ECR/ECS/EKS need it) |
| EKS `get-token` errors | exec plugin lacks credentials | set `aws_auth` (or IRSA); EKS threads it into the kubeconfig |
| `required sandbox executable 'nono' was not found` | hosted runner lacks the pinned sandbox binary | use the reference runner image or install the exact version expected by `supplydrift-sandbox` |
| `registry-host network proxy is required but unavailable` | `SUPPLYDRIFT_SANDBOX_NETWORK=require` cannot be enforced on this host | fix Nono/host proxy support; use `best-effort` only if logged unrestricted pull egress is acceptable |
