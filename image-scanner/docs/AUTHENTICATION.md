# Authentication

`image-scanner` keeps authentication as a dedicated component (`src/image_scanner/auth/`)
so the core scanner and connectors never deal with credentials directly. There
are two credential kinds, both driven entirely by the config file.

## 1. Registry pull credentials — the `auth` block

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

These four providers are the complete set — GCP and Azure registry auth
(GCR/Artifact Registry, ACR) is **not supported** and is rejected at config
validation. The only cloud-specific auth is AWS (below).

## 2. AWS credentials — the `aws_auth` block

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

## 3. How services pull — the registry auth index

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

### Sandboxed pull egress

Hosted runners try to proxy each Syft pull through a target-scoped domain
allowlist. Docker Hub additionally permits its token service and blob CDN;
GHCR additionally permits its package-blob host; ECR permits only the regional
Starport layer bucket associated with its registry host. Private registries
remain restricted to their configured host, so an off-host storage redirect is
denied rather than silently retried with unrestricted egress. On kernels where
the domain proxy cannot be enforced,
`SUPPLYDRIFT_SANDBOX_NETWORK=best-effort` retains filesystem isolation, uses
unrestricted pull egress, and emits a structured `unrestricted-fallback` event.
Set it to `require` to fail closed.

## 4. Per-environment recipes

### Local development
- Public images: `auth: { provider: none }` (or omit). See `config.local.yaml`.
- Anything `docker login`-ed: `auth: { provider: docker }`.
- AWS: `aws sso login --profile X` (or `aws configure`), then
  `aws_auth: { profile: X, regions: [...] }`.
- Kubernetes: point `connection.kubeconfig`/`contexts` at your clusters; configure
  the registries those images live in so the index can authenticate pulls.

### CI (GitHub Actions / GitLab)
- AWS: federate via OIDC (`aws-actions/configure-aws-credentials`) and omit
  `aws_auth` (the ambient credentials resolve through the default chain), or set
  `aws_auth: { role_arn: ... }`.
- Registry PATs: store as CI secrets and reference with
  `auth: { provider: env, username_env: ..., password_env: ... }`.

### In-cluster (CronJob / Job)
- Kubernetes control plane: use the pod's ServiceAccount (the collector falls back
  to in-cluster config when no kubeconfig is set).
- AWS data plane: attach **IRSA** to the ServiceAccount and omit `aws_auth` — the
  default chain picks up the role; ECR pulls resolve automatically.

## 5. Security notes

- Never commit `provider: static` / inline AWS keys — they exist for quick local
  tests only. Prefer `env` (CI secrets) or roles (no long-lived secrets).
- Secrets are passed to the extractor via env vars (never argv) and never written
  to disk. Minted tokens live only in process memory for the run.
- For offline/air-gapped validation, use `--dry-run --format targets` to confirm
  discovery and auth wiring without pulling images.

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| GHCR `HTTP 401/403` listing packages | missing/fine-grained PAT | use a **classic** PAT with `read:packages` |
| Docker Hub `login failed` | wrong PAT or username | check the configured `username`/`password` (or the env vars they reference); use `provider: docker` to reuse `docker login` |
| Harbor `HTTP 401` | wrong robot name/secret | use the full `robot$project+name` and its secret |
| syft `UNAUTHORIZED` on pull (service) | registry not configured | add the registry under `registries:` so the index can authenticate it |
| `'aws' not found` | AWS CLI not installed | install the AWS CLI (ECR/ECS/EKS need it) |
| EKS `get-token` errors | exec plugin lacks credentials | set `aws_auth` (or IRSA); EKS threads it into the kubeconfig |
