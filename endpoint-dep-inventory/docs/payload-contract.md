# Uploaded Payload & Server Contract

What the collector sends, and what a receiving server must do with it. For
configuration and day-to-day usage see the [README](../README.md).

The SupplyDrift platform accepts this wire format on
`POST /api/sync/endpoints`, but currently implements a **storage subset** of
the complete receiver contract described below. Do not interpret the generic
receiver recommendations as guarantees provided by the current platform.

The collector uploads normalized JSON batches, not raw Syft JSON. Three payload
kinds share one endpoint URL — dispatch on `payload_type`:

| Kind | `payload_type` | When |
| --- | --- | --- |
| SBOM batch | *(absent)* | Every scanned root, `SBOM_BATCH_SIZE` packages per batch. |
| Vulnerability batch | `"vulnerabilities"` | When `SBOM_ENABLE_VULN_SCAN=true` and `grype` is installed. |
| Heartbeat | `"heartbeat"` | When the change gate finds every root unchanged. |

## SBOM batch

Top-level shape:

```json
{
  "scan_id": "uuid",
  "payload_schema_version": "1",
  "collector_version": "0.4.0",
  "scan_policy_version": "fullfs-v1",
  "scanned_at": "2026-05-30T00:00:00Z",
  "collector": {
    "started_at": "2026-05-30T00:00:00Z",
    "resource_limits": {
      "syft_parallelism": 2
    }
  },
  "endpoint": {
    "id": "stable-endpoint-id",
    "hostname": "developer-laptop",
    "username": "alice",
    "os": "Darwin",
    "kernel": "25.0.0",
    "arch": "arm64"
  },
  "scanner": {
    "name": "syft",
    "version": "1.44.0",
    "schema_version": "16.1.3"
  },
  "source": {
    "name": "developer-endpoint",
    "root": "/",
    "type": "directory",
    "status": "success"
  },
  "package_count": 1100,
  "dependency_edge_count": 2,
  "packages": [],
  "dependency_edges": [],
  "batch_id": "uuid-sourcehash-1",
  "batch_index": 1,
  "batch_count": 3,
  "batch_package_count": 500,
  "batch_byte_count": 100000
}
```

`package_count` / `dependency_edge_count` describe the whole scan of that root;
`batch_*` fields describe this slice of it (here: batch 1 of 3, holding 500 of
the 1100 packages).

Package fields:

| Field | Description |
| --- | --- |
| `key` | PURL when available, otherwise `type:name:version`. |
| `name`, `version`, `type`, `language` | Package identity fields from Syft. |
| `purl` | Package URL. Preferred lookup key. |
| `licenses` | Unique license values reported by Syft. |
| `found_by` | Syft catalogers that found the package. |
| `metadata_types` | Syft metadata types seen across occurrences. |
| `dependency_kind` | Primary best-effort kind: `root`, `direct`, `transitive`, or `unknown`. |
| `dependency_kinds` | All kinds seen across occurrences. |
| `dependency_scope` | Primary scope: `runtime`, `dev`, `optional`, `peer`, or `unknown`. |
| `dependency_scopes` | All scopes seen across occurrences. |
| `dependency_evidence` | Evidence source such as `manifest-declared`, `lockfile-graph`, or `cataloger-only`. |
| `dependency_kind_note` | Currently always `best-effort`. |
| `locations` | Unique evidence paths. |
| `occurrences` | Per-occurrence project/source context. |
| `occurrence_count` | Number of grouped occurrences. |

Occurrence fields:

```json
{
  "artifact_id": "syft-artifact-id",
  "source_root": "/",
  "manifest_path": "/Users/alice/project/package-lock.json",
  "locations": ["/Users/alice/project/package-lock.json"],
  "dependency_kind": "direct",
  "dependency_scope": "runtime",
  "dependency_evidence": "manifest-declared",
  "found_by": "javascript-lock-cataloger",
  "metadata_type": "javascript-npm-package-lock-entry"
}
```

Dependency edge fields:

```json
{
  "from_key": "pkg:npm/lodash@4.17.21",
  "to_key": "pkg:npm/example-app@0.1.0",
  "relationship_type": "dependency-of",
  "source_root": "/"
}
```

## Vulnerability batches

When `SBOM_ENABLE_VULN_SCAN=true` (the default) and `grype` is installed, each
scanned root also produces small vulnerability batches (`SBOM_VULN_BATCH_SIZE`
records per batch, default 1000). Records are intentionally minimal:

```json
{
  "scan_id": "uuid",
  "payload_schema_version": "1",
  "payload_type": "vulnerabilities",
  "collector_version": "0.4.0",
  "endpoint": { "id": "stable-endpoint-id" },
  "scanner": { "name": "grype", "version": "0.114.0" },
  "source": { "root": "/", "type": "directory", "status": "success" },
  "vulnerability_count": 87,
  "vulnerabilities": [
    {
      "name": "lodash",
      "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20",
      "id": "CVE-2021-23337",
      "severity": "High",
      "fix": "4.17.21"
    }
  ],
  "batch_id": "uuid-vuln-sourcehash-1",
  "batch_index": 1,
  "batch_count": 1
}
```

## Heartbeat payload

When the change gate finds every root unchanged, one heartbeat is uploaded
instead of re-shipping the identical inventory:

```json
{
  "scan_id": "uuid",
  "payload_schema_version": "1",
  "payload_type": "heartbeat",
  "collector_version": "0.4.0",
  "scanned_at": "2026-06-10T02:00:00Z",
  "collector": { "started_at": "2026-06-10T02:00:00Z", "resource_limits": { "syft_parallelism": 2 } },
  "endpoint": { "id": "stable-endpoint-id", "hostname": "developer-laptop", "username": "alice" },
  "status": "unchanged",
  "last_full_scan": { "scan_id": "uuid-of-last-full-scan", "finished_at": "2026-06-08T02:11:42Z" },
  "roots": [
    { "root": "/", "status": "unchanged", "last_full_scan_id": "uuid", "last_full_finished_at": "2026-06-08T02:11:42Z" }
  ]
}
```

The top-level `last_full_scan` is the **oldest** across roots — a conservative
staleness signal. Heartbeats are best-effort: never queued, never retried
across runs, and a failed heartbeat does not fail the run.

## Current SupplyDrift compatibility

With authentication enabled (the default), use a bearer token with `ingest`
capability: either an `ingest`-scope token or a `runner`-scope token. The
platform currently handles the payload kinds as follows:

| Payload | Current behavior |
| --- | --- |
| SBOM batch | Upserts one endpoint asset, package components, and endpoint-to-component usage evidence. Basic endpoint/scanner/source/batch metadata is retained. `dependency_edges[]` and the complete `occurrences[]` detail are not persisted. |
| Vulnerability batch | Upserts the affected package components and CVE findings, including severity and an available fix version. |
| Heartbeat | Accepts the request, but does not persist endpoint liveness, update the endpoint asset, or retain `last_full_scan`/per-root heartbeat state. |

Additional limitations of the current adapter:

- It does not record or enforce the recommended
  `endpoint.id + scan_id + batch_id` idempotency key. Stable asset/component
  upserts make repeated content largely convergent, but there is no durable
  per-batch acceptance record.
- Ingestion is additive. It does not reconcile a completed full scan against a
  prior snapshot, mark missing packages removed, or maintain separate current
  inventory and observation history.
- Consequently, SupplyDrift can answer which endpoint/package and endpoint/CVE
  evidence has been ingested, but it does not yet implement the dependency
  graph, liveness, removal, or snapshot semantics required of a complete fleet
  inventory receiver.

## Full receiver contract

Endpoint:

```text
POST $SBOM_SERVER_URL
Authorization: Bearer <token>
Content-Type: application/json
Content-Encoding: gzip   # when SBOM_COMPRESS_UPLOAD=true
```

All three payload kinds POST to the same URL — dispatch on `payload_type`.

A receiver implementing the full contract should:

- accept gzip request bodies
- return `2xx` only after accepting the batch for ingestion
- dedupe SBOM and vulnerability batches idempotently on
  `endpoint.id + scan_id + batch_id`
- handle heartbeats separately because they have no `batch_id`: either accept
  repeats or dedupe them on `endpoint.id + scan_id + payload_type`
- return `401` or `403` for authentication failures
- return `413` when the batch is too large
- return `429` with `Retry-After` when overloaded
- return `5xx` for transient server failures

Recommended indexes:

- `purl`
- `type`, `name`, `version`
- `endpoint.id`
- `source.root`
- `locations`
- `last_seen_at`
- `dependency_kind`
- `scan_policy_version`

Full inventory semantics:

- Treat each accepted batch as evidence for a scan.
- Do not mark packages removed unless the endpoint completed a full scan successfully.
- Store current inventory separately from historical observations.
- Track ingestion lag, stale endpoints, rejected batches, queue backlog, and scan failure rates.

Full heartbeat semantics:

- Unchanged runs POST a single small JSON with `payload_type: "heartbeat"`,
  `status: "unchanged"`, the endpoint block, and a `last_full_scan`
  `{scan_id, finished_at}` reference (plus per-root detail under `roots[]`).
- Heartbeats are liveness signals only: they must never mutate inventory.
- Staleness alerting should key off `max(last accepted batch, last heartbeat)`;
  inventory-freshness guarantees come from the collector's
  `SBOM_FULL_SCAN_INTERVAL_HOURS` forced full scans.
- Servers that do not understand heartbeats may ignore them (any response is
  acceptable; the collector never queues or retries them across runs).
