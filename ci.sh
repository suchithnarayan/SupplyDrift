#!/usr/bin/env bash
#
# CI runner for the entire SupplyDrift project — runs every check the way a CI
# pipeline would: a fresh Python venv, all three pytest suites, ruff lint, the
# frontend typecheck+build, and the endpoint collector's shell checks.
#
#   bash ci.sh            # run everything (reuses .ci-venv if present)
#   bash ci.sh --fresh    # wipe the venv + frontend node_modules/dist first
#
# Exits non-zero if any *blocking* stage fails. Lint/shellcheck/smoke are
# advisory (reported, never block). Stages needing a missing tool are SKIPPED.
set -uo pipefail   # NOT -e: run all stages, then summarize.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 2
VENV="$ROOT/.ci-venv"
FAIL=0
declare -a RESULTS

c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
hdr()  { printf '\n%s\n' "$(c '1;36' "━━ $1 ━━")"; }
shdr() { printf '\n%s\n' "$(c '1;33' "━━ $1 (advisory) ━━")"; }

run()  { local l="$1"; shift; hdr  "$l"; if "$@"; then RESULTS+=("$(c '1;32' PASS)  $l"); else RESULTS+=("$(c '1;31' FAIL)  $l"); FAIL=1; fi; }
soft() { local l="$1"; shift; shdr "$l"; if "$@"; then RESULTS+=("$(c '1;32' PASS)  $l"); else RESULTS+=("$(c '1;33' WARN)  $l (non-blocking)"); fi; }
skip() { RESULTS+=("$(c '1;90' SKIP)  $1 — $2"); printf '\n%s\n' "$(c '1;90' "━━ $1 — SKIPPED: $2 ━━")"; }

if [ "${1:-}" = "--fresh" ]; then
  hdr "fresh: removing .ci-venv + frontend node_modules/dist"
  rm -rf "$VENV" platform/frontend/node_modules platform/frontend/dist
fi

# ── Tool inventory ──────────────────────────────────────────────────────────
hdr "tool inventory"
for t in python3 node npm git syft grype jq shellcheck; do
  if command -v "$t" >/dev/null 2>&1; then printf '  %-11s %s\n' "$t" "$(c '1;32' present)"
  else printf '  %-11s %s\n' "$t" "$(c '1;33' MISSING)"; fi
done

# ── Python: one venv covering all three suites ──────────────────────────────
setup_python() {
  [ -d "$VENV" ] || python3 -m venv "$VENV"
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
  python -m pip install -q -U pip
  # platform = fastapi/uvicorn/httpx ; github reqs = click/rich/pyyaml + pytest/ruff/coverage
  python -m pip install -q -r platform/requirements.txt
  python -m pip install -q -r github-shadow-deps/requirements.txt -r github-shadow-deps/requirements-dev.txt
  python --version
}
run "python: venv + dependencies" setup_python
# Re-activate for the rest of the script (the function ran in the same shell).
# shellcheck disable=SC1091
[ -d "$VENV" ] && source "$VENV/bin/activate" || true

run "platform: pytest"       bash -c "cd '$ROOT/platform'            && python -m pytest"
run "image-scanner: pytest"  bash -c "cd '$ROOT/image-scanner'       && python -m pytest"
run "github: pytest"         bash -c "cd '$ROOT/github-shadow-deps'  && python -m pytest"

if command -v ruff >/dev/null 2>&1; then
  soft "github: ruff lint"   bash -c "cd '$ROOT/github-shadow-deps'  && ruff check ."
else
  skip "github: ruff lint" "ruff not installed"
fi

# ── Frontend: typecheck (tsc --noEmit) + production build (vite) ─────────────
# Subshell body `( … )` so the `cd` does not leak into later stages.
build_frontend() (
  cd "$ROOT/platform/frontend" || return 1
  if [ -f package-lock.json ]; then npm ci; else npm install; fi
  npm run build   # = tsc --noEmit && vite build
)
if command -v npm >/dev/null 2>&1; then run "frontend: tsc + vite build" build_frontend
else skip "frontend: tsc + vite build" "npm not installed"; fi

# ── Endpoint collector (bash) ───────────────────────────────────────────────
ENDPOINT_SH="$ROOT/endpoint-dep-inventory/collect-sbom-inventory.sh"
LOCAL_COMPOSE_SH="$ROOT/scripts/local-compose.sh"
E2E_SH="$ROOT/e2e-cli.sh"
run "endpoint: bash -n syntax" bash -n "$ENDPOINT_SH"
run "local compose helper: bash -n syntax" bash -n "$LOCAL_COMPOSE_SH"
run "local compose helper: executable" test -x "$LOCAL_COMPOSE_SH"
run "e2e cli: bash -n syntax" bash -n "$E2E_SH"

if command -v shellcheck >/dev/null 2>&1; then
  soft "endpoint: shellcheck" shellcheck -S warning "$ENDPOINT_SH"
  soft "local compose helper: shellcheck" shellcheck -S warning "$LOCAL_COMPOSE_SH"
  soft "e2e cli: shellcheck" shellcheck -S warning "$E2E_SH"
else
  skip "shellcheck" "shellcheck not installed (apt-get install shellcheck)"
fi

if command -v jq >/dev/null 2>&1 && command -v syft >/dev/null 2>&1; then
  soft "endpoint: collector smoke" bash -c "cd '$ROOT/endpoint-dep-inventory' && ./tests/collector-smoke.sh"
else
  skip "endpoint: collector smoke" "needs jq + syft (apt-get install jq)"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
printf '\n%s\n' "$(c '1;37' '═════════════════ CI SUMMARY ═════════════════')"
for r in "${RESULTS[@]}"; do printf '  %s\n' "$r"; done
printf '%s\n' "$(c '1;37' '══════════════════════════════════════════════')"
if [ "$FAIL" -eq 0 ]; then printf '%s\n' "$(c '1;32' 'ALL BLOCKING STAGES PASSED ✓')"; else printf '%s\n' "$(c '1;31' 'CI FAILED ✗')"; fi
exit "$FAIL"
