#!/usr/bin/env bash
# regression.sh — fixture regression suite.
#
# Runs fixture scans, focused tests, optional AI smoke checks, and secret-leak
# audits for generated outputs.
#
# Exits non-zero on any failure. Designed to be CI-friendly.
#
# Usage:
#   ./scripts/regression.sh                # offline only
#   GITHUB_INVENTORY_AI_KEY=... ./scripts/regression.sh     # offline + AI
set -euo pipefail

PY="${PYTHON:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Private mktemp dir by default (world-writable /tmp + a fixed name would allow
# symlink preplacement); pass OUT_DIR=... for a stable location.
OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/binv-regression.XXXXXX")}"
SCAN_TARGET="${SCAN_TARGET:-tests/fixtures}"
mkdir -p "$OUT_DIR"
echo "Output dir: $OUT_DIR"
echo "Scan target: $SCAN_TARGET"

step() { echo; echo "=== $* ==="; }

# ---------- Offline regression (always runs) ----------

step "Fixture scan: JSON"
$PY scan.py scan "$SCAN_TARGET" --format json -o "$OUT_DIR/baseline.json" --fail-on never

step "Fixture scan: SARIF"
$PY scan.py scan "$SCAN_TARGET" --format sarif -o "$OUT_DIR/baseline.sarif" --fail-on never

step "Fixture scan: table (smoke)"
$PY scan.py scan "$SCAN_TARGET" --format table --fail-on never > "$OUT_DIR/baseline-table.txt"
echo "(table written to $OUT_DIR/baseline-table.txt)"

step "Validate JSON parses"
$PY -c "import json,sys; json.load(open('$OUT_DIR/baseline.json'))"

step "Validate SARIF basic shape"
$PY -c "
import json
d = json.load(open('$OUT_DIR/baseline.json'))
s = json.load(open('$OUT_DIR/baseline.sarif'))
assert s['version'] == '2.1.0'
assert s['runs'] and 'tool' in s['runs'][0]
assert 'driver' in s['runs'][0]['tool']
print(f'  JSON findings: {len(d[\"findings\"])}')
print(f'  SARIF results: {len(s[\"runs\"][0][\"results\"])}')
"

step "Sample-repos smoke (offline)"
# Any real-world repos cloned under sample-repos/ (gitignored) are smoke-scanned.
for repo in sample-repos/*/; do
    repo=${repo%/}
    if [ -d "$repo" ]; then
        out="$OUT_DIR/$(basename "$repo")-summary.json"
        $PY scan.py scan "$repo" --format json -o "$out" --fail-on never
        $PY -c "
import json
d = json.load(open('$out'))
s = d['summary']
print(f\"  $repo: {s['total_findings']} findings, {s['files_scanned']} files, {s['scan_duration_ms']:.0f}ms\")
"
    else
        echo "  (skipping $repo — not present)"
    fi
done

step "Pytest"
if command -v pytest >/dev/null 2>&1; then
    pytest -q tests/test_sanitizer.py tests/test_ai_analyzer.py tests/test_enrichment.py tests/test_engine.py
else
    echo "  pytest not on PATH — install via 'pip install pytest' to run the full suite"
fi

# ---------- Secret-leak audit ----------

step "Secret leak audit on offline outputs"
LEAKED=0
for f in "$OUT_DIR"/baseline.json "$OUT_DIR"/baseline.sarif "$OUT_DIR"/baseline-table.txt \
         "$OUT_DIR"/*-summary.json; do
    [ -f "$f" ] || continue
    if grep -E "AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|BEGIN [A-Z ]*PRIVATE KEY" "$f" >/dev/null 2>&1; then
        echo "  LEAK: $f"
        LEAKED=1
    fi
done
if [ "$LEAKED" -eq 0 ]; then
    echo "  no secret patterns found in any output file"
else
    echo "  SECRETS LEAKED — failing"
    exit 1
fi

# ---------- AI regression (only if key + SDK present) ----------

if [ -n "${GITHUB_INVENTORY_AI_KEY:-}${ANTHROPIC_API_KEY:-}" ]; then
    if $PY -c "import anthropic" 2>/dev/null; then
        step "AI mode on fixtures (--ai-max-files 5 to bound cost)"
        $PY scan.py scan "$SCAN_TARGET" --ai --ai-max-files 5 \
            --format json -o "$OUT_DIR/ai.json" --fail-on never
        $PY -c "
import json
d = json.load(open('$OUT_DIR/ai.json'))
ai = [f for f in d['findings'] if f.get('analysis_source') == 'ai-assisted']
print(f'  AI-assisted findings: {len(ai)} / {len(d[\"findings\"])} total')
"

        step "AI + enrich"
        $PY scan.py scan "$SCAN_TARGET" --ai --enrich --ai-max-files 5 \
            --format json -o "$OUT_DIR/enriched.json" --fail-on never
        $PY -c "
import json
d = json.load(open('$OUT_DIR/enriched.json'))
enr = [f for f in d['findings'] if f.get('enrichment')]
print(f'  enriched findings: {len(enr)}')
"

        step "Secret leak audit on AI outputs"
        for f in "$OUT_DIR"/ai.json "$OUT_DIR"/enriched.json; do
            [ -f "$f" ] || continue
            if grep -E "AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|BEGIN [A-Z ]*PRIVATE KEY" "$f" >/dev/null 2>&1; then
                echo "  LEAK: $f"
                exit 1
            fi
        done
        echo "  no secrets in AI outputs"
    else
        step "AI mode SKIPPED (current runtime AI SDK not installed)"
        echo "  install with: pip install -r requirements-ai.txt"
    fi
else
    step "AI mode SKIPPED (no GITHUB_INVENTORY_AI_KEY / ANTHROPIC_API_KEY)"
fi

step "Done"
echo "All outputs under $OUT_DIR"
