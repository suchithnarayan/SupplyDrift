# Security Policy

## Scope

This repository (product name **SupplyDrift**) contains security tooling with
four components, all in scope:

- **`platform/`** — the FastAPI service + React UI: authentication/authorization,
  session and API-token handling, credential storage/encryption, and the ingest
  and scanner-config APIs.
- **`github-shadow-deps/`** — the repository scanner: untrusted-repo handling,
  path containment, subprocess/argument construction, and the AI-egress sanitizer.
- **`image-scanner/`** — the container/Kubernetes SBOM scanner: registry and
  cluster connectors, credential handling, and subprocess calls to
  syft/grype/kubectl.
- **`endpoint-dep-inventory/`** — the endpoint SBOM collector that runs on
  developer machines: command injection via configuration, privilege issues,
  payload tampering, server-side request issues in the upload path, and
  information disclosure beyond the documented inventory fields.

Exploitable issues in any component — authentication/authorization bypass,
injection (SQL/command/argument), SSRF, path traversal, secret exposure, or RCE
from an untrusted scan target — are in scope.

## Reporting a Vulnerability

Please do **not** open a public issue for security reports.

- Use GitHub's **private vulnerability reporting** on this repository
  (Security tab → "Report a vulnerability"). This is the only supported
  private channel; do not include secrets in the report.

Include reproduction steps, the affected component and version/commit, and your
environment (OS, Python/Node, bash, syft/grype versions as applicable).

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
authenticates to the registries/clusters it scans. Runners scope each request to
the connector of the job they just claimed (`?connector_id=…`), so a runner
*process* compromised while scanning an untrusted target only holds the secret it
is actively using, not every connector's. The token itself, however, remains
authorized for all connectors (it can request any `connector_id`), so a **leaked
runner token still exposes all stored source credentials.** Treat runner tokens as
top-level secrets: keep them on the runner hosts only, rotate them if a runner is
decommissioned, prefer the bundled zero-touch token (shared over an internal
volume) over long-lived external ones, and never expose the platform's
runner-facing API to untrusted networks. Run-completion is bound to the claiming
runner. (Per-connector *token* authorization — a token limited to specific
connectors — would close the leaked-token blast radius and is a good future
enhancement.)

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
