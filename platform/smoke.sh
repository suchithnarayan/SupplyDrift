#!/usr/bin/env bash
# Smoke test for the SupplyDrift platform API: boots a throwaway instance with
# demo data and exercises ingestion, the config plane, graph, and findings.
set -euo pipefail

PORT="${PORT:-8765}"
DB="$(mktemp -t supplydrift-smoke-XXXX.db)"
BASE="http://127.0.0.1:${PORT}"

cd "$(dirname "$0")"
python3 run.py --load-demo --db "$DB" --port "$PORT" >/tmp/supplydrift-smoke.log 2>&1 &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null || true; rm -f "$DB"' EXIT
sleep 4

say() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

say "summary (asset types)"
curl -fsS "$BASE/api/summary" | python3 -c "import sys,json;print(json.load(sys.stdin)['assets']['by_type'])"

say "ingest an endpoint (developer laptop)"
curl -fsS -XPOST "$BASE/api/sync/endpoints" -d '{
  "asset":{"asset_type":"endpoint","provider":"jamf","external_id":"endpoint:LT-7",
    "display_name":"LT-7","details":{"hostname":"lt-7","os_name":"Windows","employee_name":"Sam","department":"SRE"}},
  "cyclonedx":{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"application","name":"git","version":"2.40"}]}}' >/dev/null
curl -fsS "$BASE/api/assets?asset_type=endpoint" | python3 -c "import sys,json;print([a['endpoint_hostname'] for a in json.load(sys.stdin)])"

say "configure a source from the 'UI' then read the scanner config"
curl -fsS -XPOST "$BASE/api/connectors" -d '{
  "name":"ghcr-acme","source_type":"ghcr",
  "connection":{"owner":"acme","auth":{"provider":"env","token_env":"GH_PAT"}},
  "scan":{"repositories":["acme/*"]}}' >/dev/null
curl -fsS "$BASE/api/scanner/config" | python3 -c "import sys,json;d=json.load(sys.stdin);print('registries',[r['type'] for r in d['registries']])"

say "dependency graph"
curl -fsS "$BASE/api/graph" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d['nodes']),'nodes',len(d['edges']),'edges')"

say "OK"
