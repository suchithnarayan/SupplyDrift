# Operations: Rollout, Tuning & Monitoring

Fleet-scale guidance for running the collector in production. For configuration
reference and quick-start usage see the [README](../README.md).

## Production rollout

Recommended rollout:

1. Install `syft`, `jq`, `curl`, `gzip` (and `grype` for the default
   vulnerability scan) plus this collector through endpoint management.
2. Deploy a protected config file and token file (restrictive permissions —
   see [Security And Privacy](../README.md#security-and-privacy)).
3. Start in dry-run on a small pilot group.
4. Enable uploads for a pilot group and monitor server ingestion.
5. Roll out by cohorts with jitter enabled.
6. Tune resource gates, queue caps, and excludes from measured results.

### Linux: systemd

Suggested service:

```ini
[Unit]
Description=SBOM endpoint inventory collector

[Service]
Type=oneshot
Environment=SBOM_CONFIG_FILE=/etc/sbom-inventory/config.env
ExecStart=/opt/sbom-inventory/collect-sbom-inventory.sh
Nice=10
IOSchedulingClass=idle
```

Suggested timer — frequent runs (the change gate makes unchanged runs nearly
free):

```ini
[Timer]
OnCalendar=hourly
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

Or the classic once-daily off-hours schedule:

```ini
[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
```

### macOS: launchd

- hourly or a few times a day with the change gate enabled, or once daily
  off-hours for conservative fleets
- use `SBOM_START_JITTER_SECONDS=900` for frequent runs (14400 for once-daily)
- keep `SBOM_SKIP_ON_BATTERY=true` unless inventory freshness requirements override it
- deploy config and token files with restrictive permissions through MDM

## Performance and endpoint impact

Recommended enterprise defaults for frequent runs:

```bash
SBOM_SYFT_PARALLELISM=2
SBOM_ADAPTIVE_PARALLELISM=true
SBOM_MAX_PARALLELISM=8
SBOM_NICE=10
SBOM_ENABLE_IONICE=true
SBOM_ENABLE_TASKPOLICY=true
SBOM_START_JITTER_SECONDS=900
SBOM_SKIP_ON_BATTERY=true
SBOM_MIN_FREE_MB=1024
SBOM_MAX_RUN_SECONDS=7200
SBOM_CHANGE_GATE=true
SBOM_FULL_SCAN_INTERVAL_HOURS=168
```

Fleet guidance:

- With the change gate enabled, hourly or 4-hourly runs are viable: unchanged
  runs cost a metadata sweep plus one tiny heartbeat upload.
- Use a shorter jitter (e.g. 900s) for frequent runs; keep the long 14400s
  jitter only for once-daily full-fleet schedules.
- Adaptive parallelism only raises Syft workers when the machine is on AC
  power and under low load; the configured `SBOM_SYFT_PARALLELISM` remains the
  floor and `SBOM_MAX_PARALLELISM` the ceiling.
- Keep remote and pseudo mount skipping enabled for `/` scans (`squashfs` snap
  mounts and other pseudo filesystems are skipped by default).
- The default excludes are also a user-protection measure: macOS cloud-storage
  placeholders are never traversed, so scans cannot trigger file hydration
  (surprise downloads); on macOS the scanners run at background QoS
  (`taskpolicy -b`), mirroring `ionice` on Linux.
- Tune excludes from measured data, not from assumptions — see
  [scan-scope.md](scan-scope.md).
- `SBOM_MAX_RUN_SECONDS` also bounds the sweep; a timed-out sweep is treated
  as "changed" (fail toward coverage).

## Monitoring: `last-run.json`

Every run writes `$SBOM_STATE_DIR/last-run.json` (and prints a summary block
mirroring it on stderr). Useful fields:

- `status`: `success`, `partial-failure`, or `skipped`
- `skip_reason`: why a preflight gate skipped the scan
- `total_packages`, `total_vulnerabilities`
- `total_batches`, `batches_uploaded`, `batches_queued`, `batches_dropped`
- `upload_failures`, `scan_failures`
- `gate.enabled`, `gate.sweep_seconds`, and per-root `gate.results[]`
  (`{result, root, reason}` where result is `full-forced`, `full-changed`,
  `unchanged`, `unchanged-content`, or `disabled`)
- `roots_scanned`, `roots_unchanged`
- `grype_skipped`: roots whose digest matched, so grype + upload were skipped
- `last_full_scan_at`: oldest last-full timestamp across roots
- `heartbeat`: `sent`, `printed`, `failed`, `skipped-backpressure`,
  `disabled`, or `not-applicable`
- `effective_parallelism`: the syft worker count actually used this run
- `queue.files`, `queue.bytes`

Fleet monitoring should watch gate results, sweep duration, scan duration,
failures, queue depth, and skip reasons across endpoints.

## Testing against the dummy server

`sbom-dummy-server.py` is a **test-only** receiver — it has no real authentication
and writes every POST body to disk. It therefore binds `127.0.0.1` by default and
refuses a non-loopback `--host` unless you pass `--i-know-this-is-insecure`. It also
caps the compressed request body (`--max-bytes`, default 64 MiB) and the decompressed
size (`--max-decompressed-bytes`, default 256 MiB) so a gzip bomb cannot exhaust
memory; both return HTTP 413 when exceeded. Do not deploy it as a real ingestion
endpoint.

Start a local receiver and run the collector against it (see the
[README quick start](../README.md#quick-start) for the basic loop). Then:

Inspect received payloads:

```bash
jq -s '{
  received_batches: length,
  total_packages: (map(.packages | length) | add),
  total_dependency_edges: (map(.dependency_edges | length) | add),
  has_cpes: ([.[] .packages[] | has("cpes")] | any),
  has_occurrences: all(.[]; all(.packages[]; has("occurrences")))
}' received-sbom-batches/batch-*.json
```

Run the collector a second time without changing anything to see the change
gate in action — the run takes seconds and the receiver gets one heartbeat:

```bash
# same command as before; then inspect:
jq 'select(.payload_type == "heartbeat") | {status, last_full_scan}' received-sbom-batches/batch-*.json
```

Add `--verbose` to any run to see the exact syft/grype/sweep command lines and
per-attempt HTTP codes.

Simulate server backpressure (the collector honors `Retry-After`, stops on
sustained 429, and queues the remainder):

```bash
./sbom-dummy-server.py --port 8080 --token test-token --status 429 --retry-after 5
```

Simulate oversized request rejection:

```bash
./sbom-dummy-server.py --port 8080 --token test-token --max-bytes 1000
```
