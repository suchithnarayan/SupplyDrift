# Security Policy

## Scope

This repository (product name **SupplyDrift**) contains security tooling with
five components, all in scope:

- **`platform/`** — the FastAPI service + React UI: authentication/authorization,
  session and API-token handling, credential storage/encryption, and the ingest
  and scanner-config APIs, scan queue, and malware-analysis processing.
- **`github-shadow-deps/`** — the repository scanner: untrusted-repo handling,
  path containment, subprocess/argument construction, and the AI-egress sanitizer.
- **`image-scanner/`** — the container/Kubernetes SBOM scanner: registry and
  cluster connectors, credential handling, and subprocess calls to
  syft/grype/kubectl.
- **`endpoint-dep-inventory/`** — the endpoint SBOM collector that runs on
  developer machines: command injection via configuration, privilege issues,
  payload tampering, server-side request issues in the upload path, and
  information disclosure beyond the documented inventory fields.
- **`supplydrift-sandbox/`** — the shared Syft/Grype execution boundary:
  capability-manifest construction, environment and filesystem isolation,
  network-policy enforcement, credential redaction, preflight canaries, and
  child-process cleanup.

Exploitable issues in any component — authentication/authorization bypass,
injection (SQL/command/argument), SSRF, path traversal, secret exposure, or RCE
from an untrusted scan target — are in scope.

## Reporting a Vulnerability

Please do **not** open a public issue for security reports.

- Use GitHub's **private vulnerability reporting** on this repository
  (Security tab → "Report a vulnerability"). This is the only supported
  private channel; do not include secrets in the report.

Include reproduction steps, the affected component and version/commit, and your
environment (OS, Python/Node, Bash, Syft/Grype/Nono versions as applicable).

## What to Expect

- Acknowledgement within 5 business days.
- A fix or mitigation plan communicated before any public disclosure.
- Credit in the changelog if you would like it.

This project does not currently run a bug bounty program.

## Hardening Guidance for Deployers

The collector's own security posture (config/token file permissions, HTTPS,
token scoping, `SBOM_STRICT_CONFIG_PERMS`) is documented in
[`endpoint-dep-inventory/README.md`](endpoint-dep-inventory/README.md#security-and-privacy).
Remember that config files are Bash-sourced and must be writable only by
trusted administrators.

### Protect the credential-encryption key

`SUPPLYDRIFT_SECRET_KEY` is the Fernet key that encrypts stored source
credentials at rest. Generate it with the one-liner documented in
`.env.example`, keep it **out of the database and backups**, and treat its
loss as unrecoverable (stored credentials cannot be decrypted without it) and
its leak as a credential-exposure event (rotate the connector credentials).

### Runner tokens are highly privileged (trust model)

Scan runners are trusted components. A `runner`-scoped token can fetch decrypted
connector credentials from `GET /api/scanner/config` — this is how a runner
authenticates to the registries and clusters it scans. Bundled runners pass the
job's `connector_id`; the response still includes every enabled connector's
topology, reveals secrets for the claimed connector, and masks the others. This
is runner behavior, not an authorization boundary: the token can change or omit
the scope to request another connector or an unscoped response. A compromised
runner process or leaked runner token can therefore expose all stored source
credentials.

Treat runner tokens as top-level secrets: keep them on runner hosts only, rotate
them when a runner is decommissioned, prefer the bundled zero-touch token shared
over an internal read-only volume, and do not expose runner-facing APIs to
untrusted networks. Bundled runners include their `runner_id` when completing a
job, and the platform rejects a mismatched ID; completion without `runner_id`
remains accepted for legacy clients. Cancellation is a logical state change and
does not terminate an already-running scanner process. Per-connector token
authorization and mandatory completion identity remain future hardening work.

### Understand the sandbox boundary

The hardened Compose repository and image runners require pinned Nono and run a
preflight before accepting work. A fresh capability manifest, isolated home,
cache and temporary directory, minimal environment, process reaper, and output
credential redaction are applied to each Syft or Grype child. The runner images
keep application code and the prebuilt Grype database read-only.

This boundary is deliberately narrower than the whole scanner. The long-lived
runner parent, Git clone, repository-native Python scanners, registry and cloud
discovery, `kubectl`, AWS CLI, and the endpoint collector's direct Syft/Grype
invocations run outside Nono. Treat those stages and their credentials as trusted
deployment components. Custom Kubernetes or VM deployments must reproduce the
Compose hardening explicitly; installing the Python library alone does not do so.

`SUPPLYDRIFT_TOOL_SANDBOX=required` is the production/Compose fail-closed mode.
`auto` may warn and execute locally without isolation, while `off` deliberately
disables it. Blocked-network jobs never fall back. Image Syft can use a logged
unrestricted-egress fallback only when
`SUPPLYDRIFT_SANDBOX_NETWORK=best-effort`; set it to `require` where proxy
enforcement is mandatory. Monitor structured `supplydrift_tool_sandbox` events
and alert on `filesystem_enforced: false` or
`network_mode: "unrestricted-fallback"`. Rebuild runner images through a
reviewed process to refresh their immutable Grype database and pinned tools.

See [`supplydrift-sandbox/README.md`](supplydrift-sandbox/README.md) and the
[architecture sandbox section](docs/architecture.md#per-invocation-parser-sandbox)
for the complete capability and trust model.

### Do not disable authentication on a public interface

`SUPPLYDRIFT_AUTH=disabled` turns the entire API into an unauthenticated admin
surface (for trusted local/dev use only). `run.py` refuses to start in that mode
on a non-loopback `--host` unless `SUPPLYDRIFT_I_UNDERSTAND_AUTH_DISABLED=1` is
set, and — as a last-line rail covering direct `uvicorn server:api` starts — the
API middleware additionally refuses requests from public (non-loopback,
non-private) peer addresses in this mode unless the same override is set.
Private-range peers stay allowed so the bundled compose runners keep working in
dev. Keep auth enabled and bind `127.0.0.1` (front with a TLS proxy) for anything
reachable by others.
