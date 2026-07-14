# supplydrift-sandbox

`supplydrift-sandbox` is SupplyDrift's internal least-privilege executor for
third-party cataloguers. It places each Syft or Grype invocation behind a fresh
[Nono](https://github.com/nolabs-ai/nono) capability manifest, gives it only the
inputs and network access needed for that invocation, and cleans up its complete
process tree afterward.

It is used by:

- `image-scanner` for registry-backed Syft and offline Grype; and
- `github-shadow-deps` for repository Syft and offline Grype.

This package is not a general command sandbox and has no standalone CLI. The
executor rejects tool names other than `syft` and `grype` and accepts only their
explicitly allowlisted environment variables.

## Trust boundary

The long-lived Python runner is the trusted parent. It claims jobs, decrypts or
resolves source credentials, performs discovery, starts trusted helper tools,
normalizes results, and publishes to the platform. Only the hostile-parser stage
is placed inside Nono.

| Runs inside a fresh Nono boundary | Runs in the trusted parent/outside Nono |
| --- | --- |
| Image Syft | Platform queue/config/sync requests |
| Repository Syft | Git clone and native repository scanners |
| Image/repository Grype | Registry discovery APIs and Docker credential helpers |
| | AWS CLI and `kubectl`/Kubernetes collection |
| | OSV malware queries and result normalization |
| | Endpoint collector and malware worker |

Nono is therefore a per-tool parser boundary, not a whole-runner container
sandbox or an outbound firewall for the trusted parent. Deployments should also
use the hardened runner container controls: non-root execution, read-only
application filesystems, dropped capabilities, `no-new-privileges`, ephemeral
temporary storage, resource limits, and separation from the platform service.

## Invocation lifecycle

For each `SandboxExecutor.run(...)` call, the executor:

1. validates the requested tool, executable, environment keys, filesystem
   grants, network policy, target host, and positive timeout;
2. verifies sandbox readiness once per parent process;
3. creates a private temporary job root and fresh home, temp, cache, config, and
   state directories;
4. writes a mode-`0600` capability manifest outside the child-visible work area;
5. starts a trusted per-invocation reaper, which launches Nono and the tool in a
   new process session;
6. captures stdout/stderr and redacts the exact supplied Syft token/password
   values, including JSON-escaped forms;
7. kills and reaps the process tree on completion or timeout; and
8. deletes the temporary job root.

The readiness check requires the exact `nono 0.67.1` runtime, runs
`nono setup --check-only`, and proves both filesystem and blocked-network
enforcement with canaries. The filesystem canary verifies allowed reads/writes,
denied unrelated reads and writes, read-only inputs, absence of selected runner
and cloud environment variables, and denial of the parent environment through
`/proc`. The network canary proves that a blocked child cannot create a TCP
socket.

In `required` mode, a failed preflight prevents serve-mode runners from polling
for jobs and makes any direct invocation fail. Readiness is cached for the parent
process; capabilities and workspaces are still rebuilt for every tool call.

## Filesystem and environment capabilities

A sandboxed tool receives only:

- the resolved executable and its required dynamic libraries;
- selected CA certificates, name-resolution files, identity files, timezone
  data, and random/null devices required by the executable;
- an invocation-private writable work directory;
- explicit read-only inputs such as a repository or temporary SBOM;
- explicit read/write output paths, when requested;
- for Grype only, the configured immutable database beneath `/opt/grype-db`;
- fresh `HOME`, `TMPDIR`, and XDG cache/config/state directories; and
- a small base environment plus the tool-specific keys below.

| Tool | Accepted additional environment |
| --- | --- |
| Syft | `SYFT_CHECK_FOR_APP_UPDATE`, registry authority/username/token/password, and insecure-HTTP setting |
| Grype | `GRYPE_CHECK_FOR_APP_UPDATE`, `GRYPE_DB_AUTO_UPDATE`, and `GRYPE_DB_CACHE_DIR` |

The executor starts from this allowlist instead of inheriting the parent
environment. Runner tokens, the platform encryption key, AWS variables,
`KUBECONFIG`, `DOCKER_CONFIG`, proxy variables, and the parent `HOME` are not
passed through. Image Syft receives only the pull credential already resolved
for its current registry. Repository Syft and every Grype invocation receive no
publisher, registry, Kubernetes, or cloud credential.

Grant validation rejects the filesystem root and overlapping protected paths.
Read grants cannot expose `/run/supplydrift`, the reference runner's AWS,
kubeconfig, or Docker-config directories, or `/proc`. Write grants additionally
cannot overlap application/system paths, the immutable Grype DB, `/sys`, or the
protected credential paths. Only Grype can receive a read grant within the
configured Grype database root.

The reference runner images keep `/app` and `/opt/grype-db` root-owned and
non-writable. Current consumers do not grant application source to a child.

## Network policies

Current scanner consumers use these policies:

| Invocation | Policy | Credential |
| --- | --- | --- |
| Repository Syft | `blocked` | None |
| Repository Grype | `blocked` | Read-only local DB only |
| Image Syft | `proxy` | Current image's registry credential only |
| Image Grype | `blocked` | Read-only local DB only |

The proxy validates a plain registry host and allows only that target plus known
auxiliary hosts required by major registries:

- Docker Hub: registry, token service, and blob CDN;
- GHCR: registry and package-blob host;
- Quay: registry and CDN;
- ECR: registry and that region's Starport layer bucket; and
- other/private registries: the configured registry host only.

This allowlist is hostname-based. If a private registry redirects layers to an
unlisted host, the proxied pull fails rather than silently broadening its active
allowlist.

`SUPPLYDRIFT_SANDBOX_NETWORK` controls what happens when the proxy cannot be
started:

| Value | Behavior |
| --- | --- |
| `require` | Fail the image-Syft invocation closed |
| `best-effort` | Keep filesystem/environment isolation, switch that invocation to unrestricted egress, and log `unrestricted-fallback` |

Blocked-network invocations never use the proxy fallback while enforcement is
active. If the entire tool sandbox is unavailable in `auto`/`off` mode, however,
the local-development fallback has neither filesystem nor network enforcement;
it retains only the minimal child environment, fresh workspace, output
redaction, timeout, and reaper.

## Sandbox modes

`SUPPLYDRIFT_TOOL_SANDBOX` accepts:

| Value | Behavior |
| --- | --- |
| `required` | Require Nono `0.67.1` and every preflight canary; fail on any problem |
| `auto` | Use the sandbox when available; otherwise warn and execute locally with the reduced fallback controls |
| `off` | Explicitly disable Nono and emit a warning; intended only for local development |

The shared executor defaults to `auto`. Both hardened Compose scanner images set
`required`; they set network mode to `best-effort` for portability. Environments
that cannot accept logged unrestricted registry egress should override the
network mode to `require`.

Every readiness and invocation decision emits a structured log record with
`event: "supplydrift_tool_sandbox"`. Production monitoring should alert on
`filesystem_enforced: false` and
`network_mode: "unrestricted-fallback"`.

## Process cleanup

Every tool call has its own trusted reaper outside the Nono boundary. On Linux it
acts as a child subreaper, creates a new process session, enforces the requested
timeout, kills the process group, adopts and kills detached descendants, and
returns an error if cleanup does not finish. Per-invocation reapers prevent one
concurrent scan from killing another scan's children.

Detached-descendant adoption depends on Linux `/proc` and `PR_SET_CHILD_SUBREAPER`.
The reference runner images are Linux-based; other operating systems do not get
the same descendant-cleanup guarantee.

## Output redaction limitations

Before output returns to the parent, the executor replaces exact values supplied
as `SYFT_REGISTRY_AUTH_TOKEN` or `SYFT_REGISTRY_AUTH_PASSWORD`, including their
JSON-escaped representations. It does not redact arbitrary inventory content,
usernames, unrelated parent secrets, encoded/hashed/fragmented derivatives, or
secrets a tool discovers in an explicitly granted input. Treat scanner output
and logs as sensitive operational data.

## Internal API example

Repository entry points add `supplydrift-sandbox/src` to their import path. The
core integration is intentionally small:

```python
from supplydrift_sandbox import NetworkPolicy, SandboxExecutor

executor = SandboxExecutor()
completed = executor.run(
    "grype",
    ["grype", "sbom:/tmp/input.cdx.json", "-o", "json", "-q"],
    read_paths=["/tmp/input.cdx.json", "/opt/grype-db"],
    environment={
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_DB_CACHE_DIR": "/opt/grype-db",
    },
    network_policy=NetworkPolicy.BLOCKED,
    timeout_seconds=600,
)
```

Callers must pass argv as a sequence; the executor does not invoke a shell. It
resolves the executable before building the manifest and rejects malformed
registry hosts or unexpected environment variables.

## Development

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e supplydrift-sandbox pytest
python3 -m pytest -q supplydrift-sandbox/tests
```

The test suite covers exact grants, secret-environment exclusion, output
redaction, required-mode failure, version and canary checks, proxy fallback,
registry allowlists, protected paths, detached descendants, and concurrent
reapers. Tests that assert Linux process semantics are skipped on other
operating systems.

The broader architecture and deployment limitations are documented in
[`../docs/architecture.md`](../docs/architecture.md) and
[`../SECURITY.md`](../SECURITY.md).
