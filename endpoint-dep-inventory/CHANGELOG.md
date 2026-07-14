# Changelog

All notable changes to the SBOM Endpoint Inventory Collector are documented
here. The format follows [Keep a Changelog](https://keepachangelog.com/) and
the project adheres to semantic-ish versioning of `COLLECTOR_VERSION`.

## [0.4.0] - 2026-06-11

Initial open-source release.

### Security
- Config source-safety now also validates the config file's **parent directory**
  (refuses group/world-writable — sticky dirs like `/tmp` excepted — or
  foreign-owned directories) to close a TOCTOU parent-dir swap that could execute
  code as the collector (often root). The config path is canonicalized once and
  that exact resolved path is sourced; a symlinked config is refused when its
  target directory is writable.
- Permission checks now **fail closed**: if a mode/owner cannot be determined it is
  treated as unsafe rather than skipped.
- `SBOM_STRICT_CONFIG_PERMS` now defaults to `true`, so an unsafe token-bearing
  config or token file is refused (not just warned). Set
  `SBOM_STRICT_CONFIG_PERMS=false` to restore warn-only behavior.
- `SBOM_AUTH_TOKEN_FILE` is now permission-checked (refused when group/world
  readable/writable under strict mode).
- `sbom-dummy-server.py` (test receiver) refuses to bind a non-loopback host unless
  `--i-know-this-is-insecure` is passed, and now caps both the compressed request
  size (`--max-bytes`, default 64 MiB) and the **decompressed** size
  (`--max-decompressed-bytes`, default 256 MiB via bounded incremental gunzip) so a
  small gzip bomb cannot exhaust memory.

### Collection
- Syft-based package inventory with `jq` normalization: PURLs, licenses,
  best-effort dependency kind/scope, per-occurrence evidence paths, and
  dependency edges; CPEs and file metadata stripped.
- Optional grype vulnerability scanning on the same SBOM, uploaded as
  separate small `payload_type: "vulnerabilities"` batches.
- Local CLI mode: `--output FILE` writes one consolidated JSON (no server);
  `--report` emits a flattened human-friendly report.

### Scan scope and performance
- Default scope: user home directories (`/home` on Linux, `/Users` on macOS);
  `SBOM_SCAN_ROOTS="/"` opts into full-filesystem coverage.
- Tiered built-in excludes resolved per scan root: full OS-aware list for
  `/`, per-user cache tier for `/home`//`/Users` and home roots, and a
  universal VCS/bytecode tier for every root. Evidence-bearing paths
  (`/etc`, `/opt`, `/usr/local`, `/usr/lib`, `/var/lib/dpkg`, `~/.m2`,
  `~/.nvm`, editor extensions) are guarded by tests.
- Remote/pseudo mounts (NFS, 9p/drvfs, squashfs, ...) skipped under any scan
  root; foreign volumes (`/mnt`, `/media`) excluded by default.
- Change gate: a cheap mtime sweep (manifests, dependency dirs, OS package
  databases) skips the Syft scan entirely when nothing dependency-relevant
  changed; a forced full scan every `SBOM_FULL_SCAN_INTERVAL_HOURS`
  (default 168h) is the coverage guarantee; `--full` overrides.
- Package-set digest gate skips grype + re-upload when the inventory is
  unchanged despite file churn.
- Heartbeat payloads (`payload_type: "heartbeat"`) keep endpoint liveness
  visible on unchanged runs without re-shipping the inventory.
- Adaptive Syft parallelism on idle AC-powered machines; `ionice` (Linux)
  and `taskpolicy -b` (macOS) keep scans in the background.

### Upload pipeline
- Bounded JSON batches, gzip uploads, retry with `Retry-After` support,
  429 backpressure handling, and a size-capped on-disk retry queue.
- Configuration precedence: defaults < config file < environment < CLI flags.

### Observability
- Timestamped stderr progress with `--quiet`/`--verbose`/`SBOM_LOG_LEVEL`,
  TTY spinner with elapsed time, batch `X/Y` upload labels, end-of-run
  summary, and a machine-readable `last-run.json` (gate results, sweep
  timing, queue depth, effective parallelism, heartbeat status).
