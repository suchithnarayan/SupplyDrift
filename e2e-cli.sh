#!/usr/bin/env bash
#
# End-to-end CLI test for SupplyDrift.
#
#   Phase A — run each scanner's LOCAL CLI against a live target and assert the
#             JSON output (default payload + --report) is well-formed.
#   Phase B — round-trip: start a throwaway platform, ingest the image + repo
#             payloads via /api/ingest, push the endpoint scan via the collector's
#             connected mode, then query the platform to confirm the data landed.
#
# Needs: syft, grype, jq, curl, python3, network (pulls alpine:3.18). Reuses the
# .ci-venv from ci.sh if present, else builds one.
#
#   bash e2e-cli.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 2
VENV="$ROOT/.ci-venv"
PORT=8799
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sd-e2e.XXXXXX")"
DB="$WORK/platform.db"
PLATFORM_PID=""
FAIL=0
declare -a RESULTS

c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
hdr() { printf '\n%s\n' "$(c '1;36' "━━ $1 ━━")"; }
ok()   { RESULTS+=("$(c '1;32' PASS)  $1"); printf '  %s %s\n' "$(c '1;32' ✓)" "$1"; }
bad()  { RESULTS+=("$(c '1;31' FAIL)  $1"); printf '  %s %s\n' "$(c '1;31' ✗)" "$1"; FAIL=1; }
assert() { local m="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$m"; else bad "$m"; fi; }

cleanup() { [ -n "$PLATFORM_PID" ] && kill "$PLATFORM_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

# ── tools + venv ────────────────────────────────────────────────────────────
hdr "preflight"
for t in syft grype jq curl python3; do command -v "$t" >/dev/null || { echo "missing required tool: $t"; exit 2; }; done
if [ ! -x "$VENV/bin/python3" ]; then
  python3 -m venv "$VENV" || { echo "failed to create virtual environment: $VENV"; exit 2; }
fi
"$VENV/bin/python3" -m pip install -q -U pip \
  || { echo "failed to update pip in virtual environment: $VENV"; exit 2; }
"$VENV/bin/python3" -m pip install -q -r platform/requirements.txt \
  || { echo "failed to install platform runtime requirements"; exit 2; }
"$VENV/bin/python3" -m pip install -q -r github-shadow-deps/requirements.txt \
  || { echo "failed to install github scanner runtime requirements"; exit 2; }
PY="$VENV/bin/python3"
echo "  venv: $VENV"

# small fixtures (deterministic, exercise syft components + grype CVEs + phantom-deps)
REPO="$WORK/repo"; mkdir -p "$REPO/.github/workflows"
printf 'jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v3\n      - run: curl https://get.example.com | bash\n' > "$REPO/.github/workflows/ci.yml"
# lodash 4.17.15 = fixable CVEs ; firefly-utilities-helper 99.9.1 = a real OSV MAL-* malicious package
printf '{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.15","firefly-utilities-helper":"99.9.1"}}\n' > "$REPO/package.json"
printf '{"name":"app","version":"1.0.0","lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.15"},"firefly-utilities-helper":{"version":"99.9.1"}}}\n' > "$REPO/package-lock.json"
HOSTDIR="$WORK/host"; mkdir -p "$HOSTDIR"; cp "$REPO/package.json" "$REPO/package-lock.json" "$HOSTDIR/"

# ════════════════════════════ PHASE A — local CLI ══════════════════════════
hdr "A1 · image-scanner local CLI (alpine:3.18)"
"$PY" image-scanner/image_scan.py alpine:3.18 -o "$WORK/image.json" -q 2>"$WORK/image.err" \
  && ok "image: scan -> payload" || bad "image: scan -> payload ($(tail -1 "$WORK/image.err"))"
"$PY" image-scanner/image_scan.py alpine:3.18 -o "$WORK/image-report.json" --report -q 2>/dev/null \
  && ok "image: scan -> --report" || bad "image: scan -> --report"
assert "image: payload is a container_image with components" \
  jq -e '.[0].assets[0].asset_type=="container_image" and (.[0].components|length)>0' "$WORK/image.json"
assert "image: payload has CVE findings" \
  jq -e '([.[0].findings[]|select(.finding_type=="cve")]|length)>0' "$WORK/image.json"
# NB: alpine CVEs are mostly "won't-fix" (no upgrade in grype), so we only require
# vulns here; fix-capture is asserted on the github target below (lodash is fixable).
assert "image: report has vulnerabilities" \
  jq -e '(.[0].vulnerabilities|length)>0' "$WORK/image-report.json"

hdr "A2 · github local CLI (local repo path)"
"$PY" github-shadow-deps/gbom_sync.py "$REPO" -o "$WORK/repo.json" -q 2>"$WORK/repo.err" \
  && ok "github: scan -> payload" || bad "github: scan -> payload ($(tail -1 "$WORK/repo.err"))"
"$PY" github-shadow-deps/gbom_sync.py "$REPO" -o "$WORK/repo-report.json" --report -q 2>/dev/null \
  && ok "github: scan -> --report" || bad "github: scan -> --report"
assert "github: payload is a repository with components" \
  jq -e '.[0].assets[0].asset_type=="repository" and (.[0].components|length)>0' "$WORK/repo.json"
assert "github: components include a syft (npm) package" \
  jq -e '[.[0].components[]|select(.ecosystem=="npm")]|length>0' "$WORK/repo.json"
assert "github: report has phantom-dep issues + CVEs WITH a fix recommendation" \
  jq -e '(.[0].issues|length)>0 and (.[0].vulnerabilities|length)>0 and ([.[0].vulnerabilities[]|select(.fix!="")]|length)>0' "$WORK/repo-report.json"

hdr "A3 · endpoint local CLI (--output over a dir)"
SBOM_SCAN_ROOTS="$HOSTDIR" SBOM_STATE_DIR="$WORK/epstate" SBOM_START_JITTER_SECONDS=0 SBOM_SKIP_ON_BATTERY=false \
  bash endpoint-dep-inventory/collect-sbom-inventory.sh --output "$WORK/endpoint.json" >/dev/null 2>"$WORK/ep.err" \
  && ok "endpoint: scan -> --output" || bad "endpoint: scan -> --output ($(tail -1 "$WORK/ep.err"))"
SBOM_SCAN_ROOTS="$HOSTDIR" SBOM_STATE_DIR="$WORK/epstate" SBOM_START_JITTER_SECONDS=0 SBOM_SKIP_ON_BATTERY=false \
  bash endpoint-dep-inventory/collect-sbom-inventory.sh --output "$WORK/endpoint-report.json" --report >/dev/null 2>&1 \
  && ok "endpoint: scan -> --report" || bad "endpoint: scan -> --report"
assert "endpoint: inventory has packages + vulnerabilities" \
  jq -e '(.packages|length)>0 and (.vulnerabilities|length)>0' "$WORK/endpoint.json"
assert "endpoint: report has components + vulnerabilities" \
  jq -e '(.components|length)>0 and (.summary.components>0)' "$WORK/endpoint-report.json"

hdr "A4 · --malware (OSV malicious-package check) — flags firefly-utilities-helper@99.9.1"
"$PY" github-shadow-deps/gbom_sync.py "$REPO" -o "$WORK/repo-mal.json" --report --malware -q 2>/dev/null \
  && ok "github: scan -> --malware" || bad "github: scan -> --malware"
assert "github: --malware flagged the MAL-* package" \
  jq -e '(.[0].malware|length)>0 and (.[0].malware[]|select(.package=="firefly-utilities-helper"))' "$WORK/repo-mal.json"
SBOM_SCAN_ROOTS="$HOSTDIR" SBOM_ENABLE_VULN_SCAN=false SBOM_STATE_DIR="$WORK/epstate" SBOM_START_JITTER_SECONDS=0 SBOM_SKIP_ON_BATTERY=false \
  bash endpoint-dep-inventory/collect-sbom-inventory.sh --output "$WORK/endpoint-mal.json" --malware >/dev/null 2>&1 \
  && ok "endpoint: scan -> --malware" || bad "endpoint: scan -> --malware"
assert "endpoint: --malware flagged the MAL-* package" \
  jq -e '(.malware|length)>0 and (.malware[]|select(.package=="firefly-utilities-helper"))' "$WORK/endpoint-mal.json"

# ════════════════════════ PHASE B — platform round-trip ════════════════════
hdr "B · throwaway platform round-trip"
# Auth disabled for the e2e (it exercises the data round-trip, not login).
( cd "$ROOT/platform" && exec env SUPPLYDRIFT_DB="$DB" SUPPLYDRIFT_AUTH=disabled "$PY" run.py --host 127.0.0.1 --port "$PORT" --db "$DB" ) \
  >"$WORK/platform.log" 2>&1 &
PLATFORM_PID=$!
BASE="http://127.0.0.1:$PORT"
for _ in $(seq 1 30); do curl -sf "$BASE/api/summary" >/dev/null 2>&1 && break; sleep 1; done
assert "platform: up" curl -sf "$BASE/api/summary"

ingest_payload() {
  local label="$1" source="$2" staged="$WORK/ingest-$1.json" code
  local extract_err="$WORK/ingest-$1.err"

  if ! jq -ce '
    if type == "array" and length > 0 and (.[0] | type == "object")
    then .[0]
    else error("expected a non-empty JSON array whose first item is an object")
    end
  ' "$source" >"$staged" 2>"$extract_err"; then
    bad "platform: ingest $label payload (missing or invalid scanner output: $(tail -1 "$extract_err"))"
    return 1
  fi

  if ! code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/api/ingest" \
    -H 'Content-Type: application/json' --data-binary "@$staged"); then
    bad "platform: ingest $label payload (request failed)"
    return 1
  fi

  if [ "$code" = 201 ]; then
    ok "platform: ingest $label payload (201)"
    return 0
  fi
  bad "platform: ingest $label payload ($code)"
  return 1
}

# image + repo payloads are the normalized {assets, components, component_usages, findings} shape -> /api/ingest
ingest_payload "image" "$WORK/image.json"
ingest_payload "repo" "$WORK/repo.json"
# endpoint: connected mode (the collector's real upload path) -> /api/sync/endpoints
SBOM_SERVER_URL="$BASE/api/sync/endpoints" SBOM_ALLOW_INSECURE=true SBOM_AUTH_TOKEN="ignored" SBOM_COMPRESS_UPLOAD=true \
  SBOM_SCAN_ROOTS="$HOSTDIR" SBOM_STATE_DIR="$WORK/epstate2" SBOM_START_JITTER_SECONDS=0 SBOM_SKIP_ON_BATTERY=false \
  bash endpoint-dep-inventory/collect-sbom-inventory.sh >/dev/null 2>"$WORK/epsync.err" \
  && ok "platform: endpoint connected sync (collector -> /api/sync/endpoints)" \
  || bad "platform: endpoint connected sync ($(tail -1 "$WORK/epsync.err"))"

assert "platform: image asset present with components" \
  bash -c "curl -s '$BASE/api/assets?asset_type=container_image' | jq -e '.[0].component_count>0'"
assert "platform: repo asset present with components" \
  bash -c "curl -s '$BASE/api/assets?asset_type=repository' | jq -e '.[0].component_count>0'"
assert "platform: endpoint asset present with components + vulnerabilities" \
  bash -c "curl -s '$BASE/api/assets?asset_type=endpoint' | jq -e '.[0].component_count>0 and .[0].finding_count>0'"
assert "platform: vulnerabilities visible with a fix recommendation" \
  bash -c "curl -s '$BASE/api/vulnerabilities?limit=200' | jq -e '(.items|length)>0 and ([.items[]|select(.fix_recommendation!=\"\")]|length)>0'"

hdr "C · UI-driven scan queue (enqueue → runner claims → completes)"
CID=$(curl -s -X POST "$BASE/api/connectors" -H 'Content-Type: application/json' \
  -d '{"name":"E2E DockerHub","source_type":"dockerhub","connection":{"namespaces":["acme"]}}' | jq -r '.id')
RUN=$(curl -s -X POST "$BASE/api/connectors/$CID/scan" | jq -r '.id')
assert "queue: Scan button enqueues a job for the connector" \
  bash -c "curl -s '$BASE/api/connectors/$CID/scan/latest' | jq -e '.status==\"queued\" and .job_type==\"image\"'"
assert "queue: image runner claims the job (atomic)" \
  bash -c "curl -s -X POST '$BASE/api/scan/runs/claim' -H 'Content-Type: application/json' -d '{\"job_type\":\"image\",\"runner_id\":\"e2e-runner\"}' | jq -e '.id==\"$RUN\" and .status==\"running\"'"
assert "queue: a second claim gets nothing (job already taken)" \
  bash -c "curl -s -X POST '$BASE/api/scan/runs/claim' -H 'Content-Type: application/json' -d '{\"job_type\":\"image\",\"runner_id\":\"e2e-2\"}' | jq -e '.==null'"
curl -s -X POST "$BASE/api/scan/runs/$RUN/complete" -H 'Content-Type: application/json' \
  -d '{"status":"succeeded","summary":{"scanned_ok":2,"total_components":42}}' >/dev/null
assert "queue: runner reports completion -> succeeded with summary" \
  bash -c "curl -s '$BASE/api/connectors/$CID/scan/latest' | jq -e '.status==\"succeeded\" and .summary.scanned_ok==2'"

hdr "D · malware analysis (enable → enqueue → runner claims → match → alert)"
curl -s -X PUT "$BASE/api/settings/malware" -H 'Content-Type: application/json' -d '{"malware_enabled":true}' >/dev/null
assert "malware: enabling turns on the master switch (platform alerts default on)" \
  bash -c "curl -s '$BASE/api/settings/malware' | jq -e '.malware_enabled==true and .platform_alerts_enabled==true'"
curl -s -X POST "$BASE/api/ingest" -H 'Content-Type: application/json' -d '{
  "scan_metadata":{"started_at":"2026-06-11T09:00:00+00:00"},
  "assets":[{"ref":"img","asset_type":"container_image","provider":"docker_hub","external_id":"img:evil@sha256:aa","display_name":"evil-img","details":{"repository":"evil-img"}}],
  "components":[{"ref":"pkg:npm/evil@6.6.6","name":"evil","version":"6.6.6","ecosystem":"npm","package_manager":"npm","purl":"pkg:npm/evil@6.6.6"}],
  "component_usages":[{"asset_ref":"img","component_ref":"pkg:npm/evil@6.6.6","source":"image_scan"}],"findings":[]}' >/dev/null
MRUN=$(curl -s -X POST "$BASE/api/malware/scan" | jq -r '.id')
assert "malware: Run analysis enqueues a malware job" \
  bash -c "curl -s '$BASE/api/scan/runs?job_type=malware&limit=1' | jq -e '.items[0].status==\"queued\" and .items[0].job_type==\"malware\"'"
assert "malware: the malware runner claims the job" \
  bash -c "curl -s -X POST '$BASE/api/scan/runs/claim' -H 'Content-Type: application/json' -d '{\"job_type\":\"malware\",\"runner_id\":\"e2e-mw\"}' | jq -e '.id==\"$MRUN\"'"
curl -s -X POST "$BASE/api/malware/match" -H 'Content-Type: application/json' -d '{
  "scanned_at":"2026-06-11T10:00:00+00:00",
  "specs":[{"advisory_id":"MAL-E2E","package_name":"evil","ecosystem":"npm","versions":["6.6.6"],"all_versions":false,"advisory_url":"https://osv.dev/MAL-E2E","sources":["e2e"]}]}' >/dev/null
assert "malware: match creates an in-app alert for the malicious package" \
  bash -c "curl -s '$BASE/api/alerts' | jq -e '[.[]|select(.advisory_id==\"MAL-E2E\" and .package==\"evil\")]|length==1'"
assert "malware: summary reflects the active alert" \
  bash -c "curl -s '$BASE/api/summary' | jq -e '.malware.active>=1'"
curl -s -X POST "$BASE/api/scan/runs/$MRUN/complete" -H 'Content-Type: application/json' -d '{"status":"succeeded","summary":{"new":1,"active_total":1}}' >/dev/null

# ── summary ─────────────────────────────────────────────────────────────────
printf '\n%s\n' "$(c '1;37' '═════════════ E2E CLI SUMMARY ═════════════')"
for r in "${RESULTS[@]}"; do printf '  %s\n' "$r"; done
printf '%s\n' "$(c '1;37' '═══════════════════════════════════════════')"
if [ "$FAIL" -eq 0 ]; then printf '%s\n' "$(c '1;32' 'E2E CLI: ALL PASS ✓')"; else printf '%s\n' "$(c '1;31' 'E2E CLI: FAILURES ✗')"; fi
exit "$FAIL"
