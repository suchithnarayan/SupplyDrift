# SBOM Endpoint Inventory Collector

A production-oriented endpoint collector for building a package and dependency inventory across developer laptops and workstations.

The collector runs [Syft](https://github.com/anchore/syft), normalizes the useful fields from `syft-json`, removes noisy data such as CPEs and file metadata, batches the result, and uploads it to an inventory server. The intended operational use case is compromised-package response: when a malicious package or version is identified, the inventory backend can quickly answer which endpoints have local evidence of it.

## SupplyDrift Platform

This collector integrates with the SupplyDrift platform — the platform's
`POST /api/sync/endpoints` accepts the collector's native package and
vulnerability batches, including gzip request bodies. With the platform's
default authentication enabled, every upload must carry a UI-minted `ingest`
token (a `runner` token also has ingest capability). Each device's scan becomes
an `endpoint` asset with its packages as components, visible on the platform's
**Endpoints** screen and searchable in the SBOM Analyzer for
compromised-package response.

**Vulnerabilities.** When `SBOM_ENABLE_VULN_SCAN=true` (default) and `grype` is installed, the collector runs grype on the syft SBOM and uploads a **separate, tiny vulnerability batch** — just package name, version, purl, and the CVE id/severity/fix. The platform turns each into a CVE **finding** linked to the package, so device vulnerabilities show up on the global **Vulnerabilities** screen and the endpoint asset's **Vulnerabilities** tab without bloating the (already large) SBOM upload. Both streams map to the same endpoint asset.

Create an `ingest` token under **Access → API tokens**, store it in a protected
file, and point the collector at the platform:

```bash
SBOM_SERVER_URL="https://supplydrift.example/api/sync/endpoints" \
SBOM_AUTH_TOKEN_FILE="/etc/sbom-inventory/token" \
./collect-sbom-inventory.sh
```

For the repository's local Compose stack, put that ingest token in the root
`.env` as `ENDPOINT_SCANNER_TOKEN`; `scripts/local-compose.sh endpoint` copies
it into a temporary token file for the collector. Direct collector invocations
use `SBOM_AUTH_TOKEN` or, preferably, `SBOM_AUTH_TOKEN_FILE`—the collector does
not read `ENDPOINT_SCANNER_TOKEN` itself.

[`sbom-inventory.supplydrift.env.example`](./sbom-inventory.supplydrift.env.example)
is a checked-in template, not a runnable token-bearing config: its repository
file mode is intentionally too open for the collector's strict permission
checks. Copy it and create the token file in a private directory before editing
either file:

```bash
install -d -m 700 "$HOME/.config/supplydrift"
install -m 600 sbom-inventory.supplydrift.env.example \
  "$HOME/.config/supplydrift/endpoint.env"
install -m 600 /dev/null "$HOME/.config/supplydrift/endpoint.token"
```

Write the real UI-minted `ingest` token to `endpoint.token`, then edit the copied
config so `SBOM_AUTH_TOKEN_FILE` points to that file. Keep the template's
`SBOM_ALLOW_INSECURE=true` only for its loopback HTTP URL; use HTTPS and set it
to `false` for every remote or production platform. Run the protected copy with
`./collect-sbom-inventory.sh --config "$HOME/.config/supplydrift/endpoint.env"`.
Deploy the final protected config and token per device using the launchd/systemd
guidance in [docs/operations.md](docs/operations.md).

## Contents

- [SupplyDrift Platform](#supplydrift-platform)
- [What This Collects](#what-this-collects)
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [How The Collector Works](#how-the-collector-works)
- [Configuration](#configuration)
- [Scan Scope](#scan-scope)
- [Frequent-Run Optimization](#frequent-run-optimization)
- [Uploaded Payload](#uploaded-payload)
- [Testing Against The Dummy Server](#testing-against-the-dummy-server)
- [Production Rollout](#production-rollout)
- [Validation](#validation)
- [Troubleshooting](#troubleshooting)
- [Security And Privacy](#security-and-privacy)
- [Known Limitations](#known-limitations)
- [License](#license)

## What This Collects

The collector reports package inventory evidence discovered by Syft from local filesystem scans.

It includes:

- package name, version, ecosystem/type, language, and PURL
- license values reported by Syft
- dependency kind and scope where Syft provides enough evidence
- per-package occurrence data so repeated packages across projects are not flattened into one ambiguous record
- manifest or lockfile locations
- dependency edges reported by Syft
- endpoint identity and scan metadata
- optionally (default on, requires `grype`): known CVEs for the discovered
  packages, uploaded as separate small vulnerability batches

It does not upload source code, file contents, shell history, environment variables, raw Syft JSON, file digests, Syft file listings, or CPEs.

SupplyDrift currently stores the package/component and vulnerability portions
of this payload. It does not yet persist the collector's `dependency_edges[]` or
the complete per-occurrence detail; receivers implementing the complete generic
contract may do so.

## Repository Layout

```text
.
|-- collect-sbom-inventory.sh                # Endpoint collector (a single bash script)
|-- sbom-dummy-server.py                     # Local receiver for upload/backpressure tests
|-- sbom-inventory.env.example               # Flat KEY=VALUE production config template
|-- sbom-inventory.supplydrift.env.example   # SupplyDrift platform config template
|-- docs/                                    # Payload contract, operations, scan-scope deep dives
|-- tests/collector-smoke.sh                 # Local smoke test
`-- test-manifests/                          # Syft fixture manifests by ecosystem
```

Fixture coverage:

- Python: `requirements.txt`, `pyproject.toml`
- Node: npm, Yarn, Bun fixture folders
- Go: `go.mod`, `go.sum`
- GitHub Actions workflows

## Requirements

Supported platforms: Linux and macOS, `bash` 3.2+ (the script targets the stock
macOS bash and avoids bash-4+ features).

Collector requirements:

- `bash`
- `syft` — install from the official [Anchore project](https://github.com/anchore/syft)
- `jq`
- `curl`
- `gzip`
- `grype` — optional but recommended; vulnerability scanning is **on by default**
  (`SBOM_ENABLE_VULN_SCAN=true`) and is skipped with a warning when grype is
  absent. Install from the official [Anchore project](https://github.com/anchore/grype).
- standard Linux/macOS tools: `awk`, `date`, `df`, `du`, `find`, `hostname`, `mktemp`, `uname`

Development and validation requirements:

- `python3` for the dummy receiver
- `shellcheck` for static shell analysis

There is no package to install: the collector is the single script
`collect-sbom-inventory.sh`. Copy it (plus a config file and token file) onto
each endpoint via your endpoint-management/MDM tooling, make it executable, and
schedule it — see [docs/operations.md](docs/operations.md).

## Quick Start

### Local CLI scan (this host → one JSON file)

Scan the configured roots and write a **single consolidated JSON** (packages +
grype CVEs) to a file — no server, no batching, no upload:

```bash
SBOM_SCAN_ROOTS="$HOME/projects" ./collect-sbom-inventory.sh --output result.json
# Flattened, human-friendly report instead of the upload payload:
SBOM_SCAN_ROOTS="$HOME/projects" ./collect-sbom-inventory.sh --output report.json --report
# add an OSV malicious-package (MAL-*) check (adds a "malware" array):
SBOM_SCAN_ROOTS="$HOME/projects" ./collect-sbom-inventory.sh --output out.json --malware
```

`result.json` is `{scan_id, scanned_at, endpoint, scanner, packages:[…],
vulnerabilities:[…], malware:[…]}`; `--report` emits `{target, asset_type:
"endpoint", summary: {components, vulnerabilities, malware}, components,
vulnerabilities:[{id,severity,package,version,fix}], malware}`. Requires
`syft`, `jq`, and (for CVEs) `grype` on PATH. The change gate never applies in
`--output` mode — it always produces a complete inventory. The full upload mode
below is the deployable setup. `--malware` submits each package's PURL, or
fallback ecosystem/name/version coordinates, to OSV's `/v1/querybatch` service;
network failures are soft and do not prevent the base inventory from completing.

Run the built-in smoke test:

```bash
./tests/collector-smoke.sh
```

Run a local fixture dry run:

```bash
SBOM_DRY_RUN=true \
SBOM_SCAN_ROOTS="$PWD/test-manifests" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR=/tmp/sbom-inventory-test \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh
```

Expected fixture result with Syft `1.44.0`:

- 4 batches
- 13 packages
- 2 dependency edges
- no CPEs
- `payload_schema_version` present
- stable `endpoint.id` present
- package `occurrences` present

Note: current Syft support may not catalog the Bun lockfile fixture. The collector records scan status, but package discovery depends on Syft cataloger support.

Dry runs never persist change-gate state, so repeated dry runs always perform
a full scan. Progress is printed to stderr (spinner on a terminal, timestamped
lines when piped); add `--verbose` for command lines or `--quiet` for silence.

## How The Collector Works

1. Reads environment variables and an optional Bash-style config file.
2. Creates or reuses a stable endpoint ID.
3. Acquires a local lock so concurrent runs do not race.
4. Applies startup jitter and endpoint preflight gates.
5. Runs the change gate per root: a cheap mtime sweep decides whether a full
   Syft scan is needed at all (see [Frequent-Run Optimization](#frequent-run-optimization)).
6. Runs Syft against each root that changed (or is due a forced full scan).
7. Normalizes `syft-json` into a compact inventory payload with `jq`.
8. Splits packages into bounded batches.
9. Uploads batches to the server, gzip-compressed by default; if every root was
   unchanged, uploads one tiny heartbeat payload instead.
10. Queues failed uploads locally with size limits.
11. Writes run status to `$SBOM_STATE_DIR/last-run.json`.

Configuration precedence:

```text
built-in defaults < config file < environment variables < CLI flags
```

The config file supplies the fleet baseline; exported `SBOM_*` environment
variables always override it (so `SBOM_SCAN_ROOTS=$HOME ./collect-sbom-inventory.sh
--config prod.env` scans `$HOME`). CLI flags win over everything; `--dry-run`
always prevents uploads.

All human-readable output goes to stderr with `[HH:MM:SS]` timestamps; stdout
is reserved for dry-run batch JSON. Interactive terminals get an in-place
status line with a spinner and elapsed time during long syft/grype scans and
change sweeps; non-TTY runs (cron, systemd, pipes) get a plain
`still running: ...` heartbeat line every 60 seconds instead. Every run ends
with a summary block mirroring `last-run.json`. Use `--quiet` for errors and
warnings only, or `--verbose` for command lines, batch byte counts, and
per-attempt HTTP codes (`SBOM_LOG_LEVEL=quiet|info|verbose` is the env
equivalent; CLI flags win).

## Configuration

Run with an explicit config file:

```bash
./collect-sbom-inventory.sh --config ./sbom-inventory.env.example
```

Or point to a config file through the environment:

```bash
SBOM_CONFIG_FILE=/etc/sbom-inventory/config.env ./collect-sbom-inventory.sh
```

Config files are plain KEY=VALUE Bash-sourced files — keep them declarative
(no logic).

### CLI Flags

| Flag | Effect |
| --- | --- |
| `--config FILE` | Load a KEY=VALUE config file (fleet baseline; env vars override it). |
| `--dry-run` | Print batch JSON to stdout instead of uploading. Always wins over `SBOM_DRY_RUN`. |
| `--full` | Force a full scan + grype + upload for every root, overriding the change gate. |
| `--quiet` | Errors and warnings only on stderr. |
| `--verbose` | Adds syft/grype/sweep command lines, batch byte counts, and per-attempt HTTP codes. |
| `--output FILE` | Local CLI mode: write one consolidated JSON (packages + CVEs), no server, no gate. |
| `--report` | With `--output`: write a flattened human-friendly report instead of the upload payload. |
| `--malware` | With `--output`: submit package coordinates to OSV, add malicious-package (`MAL-*`) matches, and soft-fail lookup network errors. |
| `-h`, `--help` | Usage text with every variable. |

### Core Variables

| Variable | Default | Description |
| --- | --- | --- |
| `SBOM_SERVER_URL` | none | Inventory server endpoint. Required in upload mode; not needed with `--dry-run` or `--output`. |
| `SBOM_AUTH_TOKEN` | none | Bearer token for uploads. Required in upload mode; use an `ingest`-scope token for SupplyDrift. |
| `SBOM_AUTH_TOKEN_FILE` | empty | File containing bearer token. Preferred for managed deployments. |
| `SBOM_CONFIG_FILE` | empty | Optional Bash-style config file. |
| `SBOM_DRY_RUN` | `false` | Print batch JSON instead of uploading. |
| `SBOM_SCAN_ROOTS` | `/home` (Linux), `/Users` (macOS) | Colon-separated roots to scan. Set `/` for full-filesystem coverage including OS packages. |
| `SBOM_EXCLUDE_PATHS` | empty | Colon-separated Syft exclude patterns. Empty applies tiered built-in defaults per scan root. |
| `SBOM_USE_DEFAULT_EXCLUDES` | `true` | Apply tiered built-in excludes when `SBOM_EXCLUDE_PATHS` is empty: full OS list for `/`, cache tier for home roots, VCS/bytecode tier for every root. |
| `SBOM_SOURCE_NAME` | empty | Logical source label sent in `source.name`. |
| `SBOM_SCAN_POLICY_VERSION` | `homes-v1` | Policy label sent with every payload. Use `fullfs-v1` when scanning `/`. |

### State And Identity

| Variable | Default | Description |
| --- | --- | --- |
| `SBOM_STATE_DIR` | `$HOME/.sbom-inventory` | Local collector state directory. |
| `SBOM_ENDPOINT_ID_FILE` | `$SBOM_STATE_DIR/endpoint-id` | Stable endpoint ID file. |
| `SBOM_QUEUE_DIR` | `$SBOM_STATE_DIR/queue` | Failed upload queue. |
| `SBOM_RAW_DIR` | `$SBOM_STATE_DIR/raw` | Optional raw Syft JSON directory. |
| `SBOM_LOCK_DIR` | `$SBOM_STATE_DIR/run.lock` | Portable lock directory. |

### Upload And Queue Controls

| Variable | Default | Description |
| --- | --- | --- |
| `SBOM_BATCH_SIZE` | `500` | Package records per batch. |
| `SBOM_MAX_BATCH_BYTES` | `2097152` | Warn when generated batch JSON exceeds this size. |
| `SBOM_COMPRESS_UPLOAD` | `true` | Send gzip-compressed request bodies. |
| `SBOM_TIMEOUT_SECONDS` | `30` | Per-upload curl timeout. |
| `SBOM_UPLOAD_RETRIES` | `2` | Retry attempts before queueing. |
| `SBOM_RETRY_DELAY_SECONDS` | `5` | Delay between upload retries. |
| `SBOM_MAX_RETRY_AFTER_SECONDS` | `300` | Maximum honored `Retry-After` delay. |
| `SBOM_QUEUE_RETRY_LIMIT` | `25` | Queued payloads retried per run. |
| `SBOM_MAX_QUEUE_FILES` | `10000` | Queue file cap. |
| `SBOM_MAX_QUEUE_BYTES` | `1073741824` | Queue byte cap. |
| `SBOM_FAIL_ON_UPLOAD_ERROR` | `false` | Exit non-zero when upload failures occurred. |

### Vulnerability Scanning

| Variable | Default | Description |
| --- | --- | --- |
| `SBOM_ENABLE_VULN_SCAN` | `true` | Run grype on each scanned root's SBOM and upload minimal vulnerability batches. Automatically disabled (with a warning) when grype is not installed. |
| `SBOM_GRYPE_BIN` | `grype` | grype binary to invoke. |
| `SBOM_VULN_BATCH_SIZE` | `1000` | Vulnerability records per upload batch. |
| `SBOM_GRYPE_DB_AUTO_UPDATE` | `true` | Let grype auto-update its vulnerability DB; set `false` on air-gapped fleets that pre-distribute the DB. |

### Resource Controls

| Variable | Default | Description |
| --- | --- | --- |
| `SBOM_SYFT_PARALLELISM` | `2` | Syft cataloger worker count. |
| `SBOM_DISABLE_FILE_CATALOGERS` | `true` | Ask Syft to skip file catalogers where supported. |
| `SBOM_NICE` | `10` | Run Syft with lower CPU priority when `nice` exists. |
| `SBOM_ENABLE_IONICE` | `true` | Use idle I/O priority on Linux when `ionice` exists. |
| `SBOM_ENABLE_TASKPOLICY` | `true` | macOS: run scanners at background QoS via `taskpolicy -b` (throttled CPU/IO while the user is active). |
| `SBOM_START_JITTER_SECONDS` | `0` | Random startup delay before scanning. |
| `SBOM_SKIP_ON_BATTERY` | `false` | Skip scans when the endpoint appears to be on battery. |
| `SBOM_MAX_LOAD_1M` | empty | Skip scans above this one-minute load average. |
| `SBOM_MIN_FREE_MB` | `256` | Minimum free MB required for the state directory. |
| `SBOM_MAX_RUN_SECONDS` | `0` | Per-root Syft timeout. `0` disables timeout. |
| `SBOM_SKIP_REMOTE_MOUNTS` | `true` | Dynamically skip remote and pseudo mounts under any scan root on Linux (e.g. NFS homes under `/home`). The configured root itself always scans. |
| `SBOM_SKIP_FILESYSTEM_TYPES` | see script | Comma-separated filesystem type patterns to skip. |

### Change Gate And Adaptive Parallelism

| Variable | Default | Description |
| --- | --- | --- |
| `SBOM_CHANGE_GATE` | `true` | Skip Syft for a root when the mtime sweep finds no dependency-relevant changes. `false` restores always-scan behavior. |
| `SBOM_FULL_SCAN_INTERVAL_HOURS` | `168` | Force a full scan (Syft + grype + upload) at least this often per root. This is the coverage guarantee. |
| `SBOM_HEARTBEAT_ON_UNCHANGED` | `true` | Upload one tiny `payload_type: "heartbeat"` JSON when every root is unchanged. |
| `SBOM_GATE_MANIFEST_NAMES` | see script | Colon-separated manifest/lockfile name globs the sweep watches. |
| `SBOM_GATE_DEP_DIR_NAMES` | `node_modules:site-packages:dist-packages:.venv:venv:vendor` | Dependency directory names the sweep watches for install/removal. |
| `SBOM_GATE_EXTRA_PATHS` | empty | Colon-separated extra absolute paths checked for changes (files or small dirs). |
| `SBOM_ADAPTIVE_PARALLELISM` | `true` | Raise Syft parallelism toward half the CPU cores when on AC power with low load. |
| `SBOM_MAX_PARALLELISM` | `8` | Upper bound for adaptive parallelism. |

The `--full` CLI flag forces a full scan for every root in that run, overriding
the gate.

### Debug And Security

| Variable | Default | Description |
| --- | --- | --- |
| `SBOM_LOG_LEVEL` | `info` | Output verbosity: `quiet`, `info`, or `verbose`. CLI `--quiet`/`--verbose` win. |
| `SBOM_KEEP_RAW` | `false` | Store raw Syft JSON locally for debugging. |
| `SBOM_STRICT_CONFIG_PERMS` | `true` | Refuse (not just warn) if a token-bearing config or the token file is group/other readable or writable; unreadable perms are treated as unsafe (fail closed). Set `false` to warn instead. |
| `SBOM_ALLOW_UNSAFE_CONFIG` | `false` | Bypass the refusal to source a group/world-writable or foreign-owned config, or one whose **parent directory** is group/world-writable or foreign-owned (the config is dot-sourced as shell, so parent-dir write is a TOCTOU code-exec vector). |
| `SBOM_ALLOW_INSECURE` | `false` | Allow uploading to a plaintext `http://` server URL (token + inventory sent in the clear). |

## Scan Scope

The default scan scope is **user home directories** — `/home` on Linux,
`/Users` on macOS — where developer dependency evidence lives. For full
coverage including OS packages (dpkg/rpm/apk, Homebrew), `/opt`, and
`/usr/local`, opt into full-filesystem scans:

```bash
SBOM_SCAN_ROOTS="/"
SBOM_SCAN_POLICY_VERSION="fullfs-v1"
```

When `SBOM_EXCLUDE_PATHS` is empty, the collector applies **tiered built-in
excludes** per scan root: the full OS-aware list for `/`, a home-cache tier for
home roots, and a universal tier (`.git`, `__pycache__`, ...) everywhere.
Dependency-bearing paths (`node_modules`, virtualenvs, `site-packages`,
`vendor`, `~/.m2`, ...) are deliberately **never** excluded by default.

The full tier table, the per-group exclusion rationale, the
deliberately-not-excluded list, and guidance for writing custom exclude
patterns are in [docs/scan-scope.md](docs/scan-scope.md).

## Frequent-Run Optimization

The collector is designed to run frequently (hourly or a few times a day) at
near-zero cost on unchanged machines. Three mechanisms make that possible:

1. **The change gate.** Before scanning a root, a cheap `find`-based mtime
   sweep checks manifests/lockfiles (`SBOM_GATE_MANIFEST_NAMES`), dependency
   directories (`SBOM_GATE_DEP_DIR_NAMES`), OS package databases (dpkg/rpm/apk,
   Homebrew, macOS pkg receipts), and any `SBOM_GATE_EXTRA_PATHS` for changes
   since the last successful scan. No hits → no Syft, no grype, no upload for
   that root. The sweep reads only directory metadata and uses POSIX find
   primaries (identical on BSD/macOS and GNU find), typically finishing in
   seconds where a Syft scan takes minutes.
2. **The package-set digest.** When a sweep hit triggers a scan but the
   normalized package set comes out identical (e.g. a manifest was touched but
   not materially changed), the collector skips grype and the re-upload for
   that root. The digest is stored only after a fully successful pipeline.
3. **Marker safety.** The new marker is created *before* the sweep and scan and
   promoted only after Syft succeeds, so changes landing mid-scan are
   re-detected on the next run. A failed root discards its marker — nothing is
   ever silently skipped after a failure.

**Coverage guarantee.** mtime sweeps can miss timestamp-preserving changes
(`tar -p`, `rsync -t`, `touch -r`, an attacker hiding a package) and deleted
projects. The bound on that exposure is `SBOM_FULL_SCAN_INTERVAL_HOURS`
(default 168 = weekly): every root gets an unconditional full Syft + grype +
upload at least that often, and `--full` forces one on demand.
Security-sensitive fleets should lower the interval rather than disable the
gate. Servers must only mark packages removed based on full scans (heartbeats
and unchanged runs carry no inventory).

**Heartbeats.** When every root is unchanged, the collector uploads a single
small JSON with `payload_type: "heartbeat"` referencing the last full scan per
root. A receiver can use this as an endpoint-liveness signal. Heartbeats are
best-effort: never queued, and a failed heartbeat does not fail the run. The
current SupplyDrift adapter accepts the request but does not persist heartbeat
liveness or update the endpoint asset from it.

`SBOM_CHANGE_GATE=false` restores the previous always-scan behavior exactly.
The gate state lives in `$SBOM_STATE_DIR/roots/<hash>/` as plain files; deleting
that directory forces a full scan on the next run.

## Uploaded Payload

The collector uploads normalized JSON batches, not raw Syft JSON. Three payload
kinds share one endpoint URL, dispatched on `payload_type`: **SBOM batches**
(no `payload_type`, `SBOM_BATCH_SIZE` packages each), **vulnerability batches**
(`payload_type: "vulnerabilities"`, minimal `{name, version, purl, id,
severity, fix}` records), and **heartbeats** (`payload_type: "heartbeat"` when
every root is unchanged).

Full payload examples, per-field tables, generic receiver recommendations, and
the exact subset currently stored by SupplyDrift are in
[docs/payload-contract.md](docs/payload-contract.md).

## Testing Against The Dummy Server

`sbom-dummy-server.py` is a **test-only** receiver (no real authentication;
binds `127.0.0.1` by default and refuses a non-loopback `--host` without
`--i-know-this-is-insecure`). Start it and run the collector against it:

```bash
./sbom-dummy-server.py --port 8080 --out-dir ./received-sbom-batches --token test-token
```

```bash
SBOM_SERVER_URL=http://127.0.0.1:8080/batches \
SBOM_AUTH_TOKEN=test-token \
SBOM_SCAN_ROOTS="$PWD/test-manifests" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR=/tmp/sbom-upload-test \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh
```

Payload inspection recipes and backpressure/oversize simulations (429 +
`Retry-After`, 413 caps) are in [docs/operations.md](docs/operations.md#testing-against-the-dummy-server).

## Production Rollout

Deploy the script, a protected config file, and a token file through endpoint
management (MDM), start with a dry-run pilot, then roll out by cohorts with
jitter. Recommended systemd service/timer units, launchd guidance, enterprise
tuning defaults, and fleet monitoring are in
[docs/operations.md](docs/operations.md).

## Validation

Run static checks:

```bash
bash -n collect-sbom-inventory.sh
bash -n sbom-inventory.env.example
bash -n sbom-inventory.supplydrift.env.example
shellcheck collect-sbom-inventory.sh
shellcheck tests/collector-smoke.sh
python3 -m py_compile sbom-dummy-server.py
```

Run the smoke test:

```bash
./tests/collector-smoke.sh
```

The repository CI (`.github/workflows/endpoint-collector-ci.yml`) runs these
same checks on Ubuntu and macOS with Syft pinned to `1.44.0`.

Check last-run status (every run also prints a summary block mirroring it):

```bash
jq . "$HOME/.sbom-inventory/last-run.json"
```

The full field reference for `last-run.json` is in
[docs/operations.md](docs/operations.md#monitoring-last-runjson). Watch a live
run with full detail:

```bash
./collect-sbom-inventory.sh --verbose --dry-run
```

## Troubleshooting

- **`syft` not found** — the collector exits early; install syft and ensure it
  is on the PATH of the scheduled job (systemd/launchd PATHs are minimal).
- **`grype not found (...); vulnerability scanning disabled`** — informational:
  the SBOM upload proceeds without CVE batches. Install grype or set
  `SBOM_ENABLE_VULN_SCAN=false` to silence it.
- **`refusing to source config ...` / permission refusals** — the config or
  token file (or its parent directory) is group/world-writable, foreign-owned,
  or too open. Fix with `chmod 600` on the file and a root-owned parent
  directory; see [Security And Privacy](#security-and-privacy). Bypass knobs
  (`SBOM_STRICT_CONFIG_PERMS=false`, `SBOM_ALLOW_UNSAFE_CONFIG=true`) exist for
  lab use only.
- **`plaintext http:// refused`** — production uploads require HTTPS; set
  `SBOM_ALLOW_INSECURE=true` only for local testing against the dummy server.
- **`another run appears to be active`** — a stale lock after a crash: remove
  `$SBOM_STATE_DIR/run.lock` if no collector process is running.
- **Queue keeps growing** — the server is rejecting or unreachable; check
  `last-run.json` (`upload_failures`, `queue.files`, `queue.bytes`). Queued
  payloads are retried on later runs and capped by `SBOM_MAX_QUEUE_FILES` /
  `SBOM_MAX_QUEUE_BYTES`.
- **Every run rescans everything** — the change gate persists no state in
  dry-run mode (expected), and deleting `$SBOM_STATE_DIR/roots/` forces full
  scans.

## Security And Privacy

The current production mode sends full detail:

- stable endpoint ID
- hostname
- username
- OS, kernel, architecture
- source root
- package names, versions, PURLs, and licenses
- manifest and dependency evidence paths

Protect config and token files:

```bash
chmod 600 /etc/sbom-inventory/config.env
chmod 600 /etc/sbom-inventory/token
```

Recommended security posture:

- use HTTPS for all production uploads
- prefer token files over inline config tokens
- issue separate `ingest` tokens per device or deployment when independent
  revocation and audit are useful; tokens are capability-scoped and the
  platform does not bind one to a claimed endpoint identity
- rotate tokens periodically
- keep `SBOM_STRICT_CONFIG_PERMS=true` (the default) so unsafe config/token perms are refused
- store the config in a root-owned, non-group/world-writable directory (its parent dir is checked too)
- restrict write access to the collector, config, token, state, and queue directories

Optional analysis can also make outbound requests. `--malware` sends package
PURLs or fallback coordinates to OSV. When vulnerability scanning is enabled,
Grype's database auto-update is on by default and may download a newer database;
set `SBOM_GRYPE_DB_AUTO_UPDATE=false` only when a current database is distributed
through another trusted channel, such as on an air-gapped fleet.

The host collector is **not** executed through `supplydrift-sandbox`/`nono`.
Syft and Grype run directly as the collector's operating-system identity and
can read every configured scan root that identity can access. `nice`, `ionice`,
`taskpolicy`, timeouts, and battery/load gates limit resource impact; they are
not security isolation. Run the scheduled service with the least privilege
that still covers the intended roots, and protect the collector script,
scanner binaries, `PATH`, config, token, state, queue, and temporary storage
from untrusted modification or disclosure.

Report vulnerabilities privately — see the repository
[security policy](../SECURITY.md).

## Known Limitations

- Dependency kind is best-effort and depends on Syft cataloger evidence.
- Unlike the containerized image and repository runners, this host collector does not sandbox Syft or Grype; their effective read access is the scheduled service account's read access.
- Some ecosystems expose direct/transitive context better than others.
- The Bash normalizer processes the Syft JSON document with `jq`; very large endpoints may require a future streaming helper.
- The collector scans local filesystems only. It does not inspect remote registries unless relevant files exist on disk.
- Config files are Bash-sourced and must be treated as trusted local files. Keep them declarative KEY=VALUE; exported `SBOM_*` environment variables override them.
- The change gate is mtime-based: timestamp-preserving changes (`tar -p`, `rsync -t`, `touch -r`) and whole-project deletions are not detected between full scans. `SBOM_FULL_SCAN_INTERVAL_HOURS` bounds that exposure; lower it (or use `--full`) rather than disabling the gate.
- The default excludes skip container layer storage and snap/flatpak runtime contents on host scans: container coverage is expected to come from image scanning (the SupplyDrift image scanner), and snap/flatpak app presence still surfaces via OS package databases. Set `SBOM_EXCLUDE_PATHS` explicitly to re-include any of these.
- Downloaded-but-not-installed artifacts (cargo registry, the full Go module cache `~/go/pkg/mod`, pnpm store, conda `pkgs/`) do not appear in inventory by default — they were noise for compromised-package response; usage evidence remains in lockfiles (`go.mod`/`go.sum`, `Cargo.lock`), installed binaries, and project trees.
- Mounted external/foreign volumes (`/mnt`, `/media`, USB drives, WSL's Windows drive) are not inventoried by default. List a mount explicitly in `SBOM_SCAN_ROOTS` to scan it.
- The default homes scope (`/home`/`/Users`) does not inventory OS-level packages (dpkg/rpm/apk, Homebrew), `/opt`, or `/usr/local`, and the change gate's OS package-database checks are inactive for it. Set `SBOM_SCAN_ROOTS="/"` (with `SBOM_SCAN_POLICY_VERSION="fullfs-v1"`) for full coverage.
- The macOS aggressive defaults skip `~/Library/Containers`, `Group Containers`, and `Application Support`, which can hold app-embedded manifests; re-include them if app-bundle inventory matters more than scan cost.
- Multi-line `SBOM_*` environment variable values lose everything after the first line when re-applied over a config file (values are paths, numbers, and booleans in practice).
- CPEs are intentionally omitted from endpoint payloads. Use PURL as the primary inventory key and do any CPE mapping server-side.

## License

Apache License 2.0 — see the repository [LICENSE](../LICENSE). Version history
for this component is in [CHANGELOG.md](CHANGELOG.md).
