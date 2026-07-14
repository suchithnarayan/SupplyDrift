#!/usr/bin/env bash

set -eo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sbom-smoke-state.XXXXXX")
GATE_STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sbom-smoke-gate.XXXXXX")
OUTPUT_JSON=$(mktemp "${TMPDIR:-/tmp}/sbom-smoke-output.XXXXXX")
STDERR_LOG=$(mktemp "${TMPDIR:-/tmp}/sbom-smoke-stderr.XXXXXX")
PRECEDENCE_CONFIG="$STATE_DIR/precedence.env"

cleanup() {
  rm -rf "$STATE_DIR" "$GATE_STATE_DIR" "$OUTPUT_JSON" "$STDERR_LOG" "$PRECEDENCE_CONFIG"
}
trap cleanup EXIT INT TERM

# Mirrors make_hash in the collector so tests can address per-root gate state.
hash16() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{print substr($1, 1, 16)}'
  else
    printf '%s' "$1" | shasum -a 256 | awk '{print substr($1, 1, 16)}'
  fi
}

# Fabricates "a successful full scan just happened" state: marker newer than
# every fixture file, a dummy digest, and a fresh last-full timestamp.
seed_gate_state() {
  sgs_dir="$1/roots/$(hash16 "$2")"
  mkdir -p "$sgs_dir"
  touch "$sgs_dir/marker"
  printf 'dummy-digest 1\n' > "$sgs_dir/pkg-state"
  date +%s > "$sgs_dir/last-full-epoch"
  printf 'seeded-scan-id\n' > "$sgs_dir/last-full-id"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$sgs_dir/last-full-at"
  printf '%s\n' "$2" > "$sgs_dir/root-path"
}

cd "$ROOT_DIR"

bash -n collect-sbom-inventory.sh
bash -n sbom-inventory.env.example
python3 -m py_compile sbom-dummy-server.py

# This asserts the PACKAGE inventory (batch count / package count / structure),
# so vuln scanning is disabled to keep stdout deterministic regardless of whether
# grype is installed. (Pre-existing quirk: in --dry-run with grype enabled, vuln
# batches are printed but the package batches are not — see collect-sbom-inventory.sh.)
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=false \
SBOM_SCAN_ROOTS="$ROOT_DIR/test-manifests" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh > "$OUTPUT_JSON" 2> "$STDERR_LOG"

# Non-TTY stderr must be plain line-based logs with no in-place status updates.
if grep -q "$(printf '\r')" "$STDERR_LOG"; then
  echo "expected no carriage returns in non-TTY stderr" >&2
  exit 1
fi

jq -e -s '
  length == 4
  and (map(.packages | length) | add) == 13
  and (all(.[]; .payload_schema_version == "1"))
  and (all(.[]; (.endpoint.id // "") != ""))
  and (all(.[]; all(.packages[]?; has("occurrences"))))
  and (([.[] .packages[]? | has("cpes")] | any) == false)
' "$OUTPUT_JSON" >/dev/null

jq -e '
  .status == "success"
  and .total_packages == 13
  and .total_batches == 4
  and .gate.enabled == true
  and .gate.results[0].result == "full-forced"
  and .gate.results[0].reason == "first-run"
  and .roots_scanned == 1
' "$STATE_DIR/last-run.json" >/dev/null

# Vulnerability-enabled dry-run must emit package batches and exactly one
# vulnerability batch. This catches shell-variable leakage between the Grype
# and package batching stages without depending on the live Grype database.
FAKE_GRYPE="$STATE_DIR/fake-grype"
cat > "$FAKE_GRYPE" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "version" ]; then
  printf '%s\n' '{"version":"smoke"}'
  exit 0
fi
cat <<'JSON'
{"matches":[{"artifact":{"name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"},"vulnerability":{"id":"CVE-SMOKE-0001","severity":"High","fix":{"versions":["4.17.22"]}}}]}
JSON
EOF
chmod 700 "$FAKE_GRYPE"
VULN_STATE_DIR="$STATE_DIR/vulnerability-enabled"
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=true \
SBOM_GRYPE_BIN="$FAKE_GRYPE" \
SBOM_SCAN_ROOTS="$ROOT_DIR/test-manifests" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$VULN_STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh > "$OUTPUT_JSON" 2> "$STDERR_LOG"

jq -e -s '
  ([.[] | select(.payload_type == "vulnerabilities")] | length) == 1
  and ([.[] | select(.payload_type == "vulnerabilities") | .vulnerabilities[]] | length) == 1
  and ([.[] | .packages[]?] | length) == 13
  and ([.[] | select(has("packages"))] | length) == 4
' "$OUTPUT_JSON" >/dev/null
jq -e '
  .status == "success"
  and .total_packages == 13
  and .total_vulnerabilities == 1
  and .total_batches == 5
  and .grype_skipped == 0
' "$VULN_STATE_DIR/last-run.json" >/dev/null

if SBOM_DRY_RUN=true \
  SBOM_SCAN_ROOTS="$ROOT_DIR/test-manifests" \
  SBOM_EXCLUDE_PATHS="/tmp/**" \
  SBOM_STATE_DIR="$STATE_DIR-invalid" \
  ./collect-sbom-inventory.sh >/dev/null 2>&1; then
  echo "expected invalid absolute exclude to fail" >&2
  exit 1
fi

# Config source-safety: a group/world-writable config is dot-sourced as shell, so
# it must be refused (unless explicitly bypassed). 0600 configs are exercised by the
# precedence test below.
UNSAFE_CONFIG="$STATE_DIR/unsafe.env"
printf 'SBOM_SCAN_ROOTS=%s\n' "$ROOT_DIR/test-manifests" > "$UNSAFE_CONFIG"
chmod 666 "$UNSAFE_CONFIG"
if SBOM_DRY_RUN=true ./collect-sbom-inventory.sh --config "$UNSAFE_CONFIG" >/dev/null 2>&1; then
  rm -f "$UNSAFE_CONFIG"
  echo "expected world-writable config to be refused" >&2
  exit 1
fi
# Bypass flag allows it through (no longer refused at the source-safety gate).
if ! SBOM_DRY_RUN=true SBOM_ALLOW_UNSAFE_CONFIG=true SBOM_START_JITTER_SECONDS=0 \
  SBOM_SKIP_ON_BATTERY=false SBOM_STATE_DIR="$STATE_DIR-bypass" \
  ./collect-sbom-inventory.sh --config "$UNSAFE_CONFIG" >/dev/null 2>&1; then
  rm -f "$UNSAFE_CONFIG"
  echo "expected SBOM_ALLOW_UNSAFE_CONFIG=true to bypass the refusal" >&2
  exit 1
fi
rm -rf "$UNSAFE_CONFIG" "$STATE_DIR-bypass"

run_gated() {
  SBOM_DRY_RUN=true \
  SBOM_ENABLE_VULN_SCAN=false \
  SBOM_SCAN_ROOTS="$ROOT_DIR/test-manifests" \
  SBOM_BATCH_SIZE=4 \
  SBOM_STATE_DIR="$GATE_STATE_DIR" \
  SBOM_START_JITTER_SECONDS=0 \
  SBOM_SKIP_ON_BATTERY=false \
  ./collect-sbom-inventory.sh "$@"
}

# Gate: seeded unchanged state -> no scan, one heartbeat doc on stdout.
seed_gate_state "$GATE_STATE_DIR" "$ROOT_DIR/test-manifests"
run_gated > "$OUTPUT_JSON"

jq -e -s '
  length == 1
  and .[0].payload_type == "heartbeat"
  and .[0].status == "unchanged"
  and .[0].roots[0].status == "unchanged"
  and .[0].last_full_scan.scan_id == "seeded-scan-id"
' "$OUTPUT_JSON" >/dev/null

jq -e '
  .total_batches == 0
  and .roots_unchanged == 1
  and .roots_scanned == 0
  and .heartbeat == "printed"
  and .gate.results[0].result == "unchanged"
' "$GATE_STATE_DIR/last-run.json" >/dev/null

# Gate: touching a watched manifest re-triggers a full scan.
touch "$ROOT_DIR/test-manifests/node-npm/package.json"
run_gated > "$OUTPUT_JSON"

jq -e -s 'length == 4' "$OUTPUT_JSON" >/dev/null
jq -e '
  .gate.results[0].result == "full-changed"
  and .roots_scanned == 1
' "$GATE_STATE_DIR/last-run.json" >/dev/null

# Gate: --full overrides a seeded unchanged state.
seed_gate_state "$GATE_STATE_DIR" "$ROOT_DIR/test-manifests"
run_gated --full > "$OUTPUT_JSON"

jq -e -s 'length == 4' "$OUTPUT_JSON" >/dev/null
jq -e '.gate.results[0].result == "full-forced" and .gate.results[0].reason == "cli-full"' \
  "$GATE_STATE_DIR/last-run.json" >/dev/null

# Gate disabled restores legacy always-scan behavior even with unchanged state.
seed_gate_state "$GATE_STATE_DIR" "$ROOT_DIR/test-manifests"
SBOM_CHANGE_GATE=false \
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=false \
SBOM_SCAN_ROOTS="$ROOT_DIR/test-manifests" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$GATE_STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh > "$OUTPUT_JSON"

jq -e -s 'length == 4' "$OUTPUT_JSON" >/dev/null
jq -e '.gate.enabled == false' "$GATE_STATE_DIR/last-run.json" >/dev/null

# Heartbeat disabled: unchanged run emits nothing on stdout.
seed_gate_state "$GATE_STATE_DIR" "$ROOT_DIR/test-manifests"
SBOM_HEARTBEAT_ON_UNCHANGED=false \
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=false \
SBOM_SCAN_ROOTS="$ROOT_DIR/test-manifests" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$GATE_STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh > "$OUTPUT_JSON"

jq -e -s 'length == 0' "$OUTPUT_JSON" >/dev/null
jq -e '.heartbeat == "disabled" and .roots_unchanged == 1' "$GATE_STATE_DIR/last-run.json" >/dev/null

# Parallelism: fixed value is reported in the payload resource limits.
rm -rf "$GATE_STATE_DIR/roots"
SBOM_ADAPTIVE_PARALLELISM=false \
SBOM_SYFT_PARALLELISM=3 \
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=false \
SBOM_SCAN_ROOTS="$ROOT_DIR/test-manifests" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$GATE_STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh > "$OUTPUT_JSON"

jq -e -s '.[0].collector.resource_limits.syft_parallelism == 3' "$OUTPUT_JSON" >/dev/null
jq -e '.effective_parallelism == 3' "$GATE_STATE_DIR/last-run.json" >/dev/null

# --quiet keeps stdout JSON intact and suppresses progress + summary on stderr.
rm -rf "$GATE_STATE_DIR/roots"
run_gated --quiet > "$OUTPUT_JSON" 2> "$STDERR_LOG"
jq -e -s 'length == 4' "$OUTPUT_JSON" >/dev/null
if grep -Eq 'scanning:|run summary' "$STDERR_LOG"; then
  echo "expected --quiet stderr to contain no progress or summary lines" >&2
  exit 1
fi

# --verbose adds command lines on stderr.
rm -rf "$GATE_STATE_DIR/roots"
run_gated --verbose > "$OUTPUT_JSON" 2> "$STDERR_LOG"
if ! grep -q 'syft command:' "$STDERR_LOG"; then
  echo "expected --verbose stderr to include the syft command line" >&2
  exit 1
fi
# Fixture roots get the universal default tier (VCS internals, __pycache__),
# but never the root-anchored system excludes.
if ! grep 'syft command:' "$STDERR_LOG" | grep -Fq -- '--exclude **/.git/**'; then
  echo "expected universal default excludes for a non-/ scan root" >&2
  exit 1
fi
if grep 'syft command:' "$STDERR_LOG" | grep -Fq './proc/**'; then
  echo "expected no root-anchored excludes for a non-/ scan root" >&2
  exit 1
fi

# Precedence: environment variables override config file values.
printf 'SBOM_SCAN_ROOTS=/nonexistent-from-config\n' > "$PRECEDENCE_CONFIG"
rm -rf "$GATE_STATE_DIR/roots"
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=false \
SBOM_SCAN_ROOTS="$ROOT_DIR/test-manifests" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$GATE_STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh --config "$PRECEDENCE_CONFIG" > "$OUTPUT_JSON" 2> "$STDERR_LOG"
jq -e -s 'length == 4' "$OUTPUT_JSON" >/dev/null

# Without the env var, the config value is used (missing root -> skipped).
rm -rf "$GATE_STATE_DIR/roots"
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=false \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$GATE_STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh --config "$PRECEDENCE_CONFIG" > "$OUTPUT_JSON" 2> "$STDERR_LOG"
if ! grep -q 'skipping missing scan root: /nonexistent-from-config' "$STDERR_LOG"; then
  echo "expected config-supplied scan root to be used when env is unset" >&2
  exit 1
fi

# Default-excludes content: extract the function and check the OS list.
DEFAULTS_FN=$(mktemp "${TMPDIR:-/tmp}/sbom-smoke-defaults.XXXXXX")
sed -n '/^default_exclude_paths_for_os()/,/^}/p' collect-sbom-inventory.sh > "$DEFAULTS_FN"
# shellcheck disable=SC1090
DEFAULT_EXCLUDES=$(. "$DEFAULTS_FN"; default_exclude_paths_for_os)
rm -f "$DEFAULTS_FN"
case "$DEFAULT_EXCLUDES" in
  '**/.git/**'*) ;;
  *)
    echo "expected default excludes to start with **/.git/**" >&2
    exit 1
    ;;
esac
case "$DEFAULT_EXCLUDES" in
  *'**/__pycache__/**'*) ;;
  *)
    echo "expected default excludes to cover __pycache__" >&2
    exit 1
    ;;
esac
case "$DEFAULT_EXCLUDES" in
  *"/var/lib/dpkg"*|*"/System/Volumes/Data/**"*)
    echo "default excludes must never cover /var/lib/dpkg or the macOS data volume" >&2
    exit 1
    ;;
esac
if [ "$(uname -s)" = "Linux" ]; then
  case "$DEFAULT_EXCLUDES" in
    *"./var/lib/docker/**"*) ;;
    *)
      echo "expected Linux default excludes to cover container storage" >&2
      exit 1
      ;;
  esac
  case "$DEFAULT_EXCLUDES" in
    *"./snap/**"*) ;;
    *)
      echo "expected Linux default excludes to cover snap" >&2
      exit 1
      ;;
  esac
  case "$DEFAULT_EXCLUDES" in
    *"./home/*/.cargo/registry/**"*) ;;
    *)
      echo "expected Linux default excludes to cover the cargo registry cache" >&2
      exit 1
      ;;
  esac
  case "$DEFAULT_EXCLUDES" in
    *"./home/*/go/pkg/mod/**"*) ;;
    *)
      echo "expected Linux default excludes to cover the Go module cache" >&2
      exit 1
      ;;
  esac
  case "$DEFAULT_EXCLUDES" in
    *"./var/lib/apt/lists/**"*) ;;
    *)
      echo "expected Linux default excludes to cover apt lists" >&2
      exit 1
      ;;
  esac
  case "$DEFAULT_EXCLUDES" in
    *"./mnt/**"*) ;;
    *)
      echo "expected Linux default excludes to cover foreign mounts" >&2
      exit 1
      ;;
  esac
  case "$DEFAULT_EXCLUDES" in
    *"./boot/**"*) ;;
    *)
      echo "expected Linux default excludes to cover /boot" >&2
      exit 1
      ;;
  esac
fi

# Evidence-bearing paths must never appear in the defaults.
case "$DEFAULT_EXCLUDES" in
  *"./etc/**"*|*":./opt/**"*|*"./usr/local/**"*|*"./usr/lib/**"*)
    echo "default excludes must never cover /etc, /opt, /usr/local, or /usr/lib" >&2
    exit 1
    ;;
esac

# Functional .git exclusion via the DEFAULT universal tier (no explicit
# SBOM_EXCLUDE_PATHS): a manifest planted inside .git must be ignored by both
# syft and the change-gate sweep.
GIT_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/sbom-smoke-gitroot.XXXXXX")
cp -r "$ROOT_DIR/test-manifests/." "$GIT_ROOT/"
mkdir "$GIT_ROOT/.git"
cp "$ROOT_DIR/test-manifests/node-npm/package.json" "$GIT_ROOT/.git/package.json"

rm -rf "$GATE_STATE_DIR/roots"
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=false \
SBOM_SCAN_ROOTS="$GIT_ROOT" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$GATE_STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh > "$OUTPUT_JSON"

jq -e -s '
  length == 4
  and ([.[].packages[]] | length) == 13
' "$OUTPUT_JSON" >/dev/null

# Gate prune: a touch inside .git must not trip the sweep; a real manifest must.
seed_gate_state "$GATE_STATE_DIR" "$GIT_ROOT"
touch "$GIT_ROOT/.git/package.json"
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=false \
SBOM_SCAN_ROOTS="$GIT_ROOT" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$GATE_STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh > "$OUTPUT_JSON"
jq -e '.gate.results[0].result == "unchanged"' "$GATE_STATE_DIR/last-run.json" >/dev/null

touch "$GIT_ROOT/go/go.mod"
SBOM_DRY_RUN=true \
SBOM_ENABLE_VULN_SCAN=false \
SBOM_SCAN_ROOTS="$GIT_ROOT" \
SBOM_BATCH_SIZE=4 \
SBOM_STATE_DIR="$GATE_STATE_DIR" \
SBOM_START_JITTER_SECONDS=0 \
SBOM_SKIP_ON_BATTERY=false \
./collect-sbom-inventory.sh > "$OUTPUT_JSON"
jq -e '.gate.results[0].result == "full-changed"' "$GATE_STATE_DIR/last-run.json" >/dev/null

rm -rf "$GIT_ROOT"

# Tier selection: extract the resolver functions and check each root class.
TIER_FN=$(mktemp "${TMPDIR:-/tmp}/sbom-smoke-tiers.XXXXXX")
for tier_fn_name in is_true default_universal_excludes default_home_excludes default_homes_parent_excludes default_exclude_paths_for_os effective_excludes_for_root; do
  sed -n "/^${tier_fn_name}()/,/^}/p" collect-sbom-inventory.sh >> "$TIER_FN"
done

tier_for() {
  # The sourced functions consume these variables.
  # shellcheck disable=SC1090,SC2034
  (. "$TIER_FN"; SBOM_EXCLUDE_PATHS=${2:-}; SBOM_USE_DEFAULT_EXCLUDES=true; effective_excludes_for_root "$1")
}

TIER_HOME=$(tier_for /home/alice)
case "$TIER_HOME" in
  *"./go/pkg/mod/**"*) ;;
  *) echo "expected home tier for /home/alice" >&2; exit 1 ;;
esac
case "$TIER_HOME" in
  *"./proc/**"*) echo "home root must not get root-anchored system excludes" >&2; exit 1 ;;
esac

TIER_PROJ=$(tier_for /home/alice/proj)
case "$TIER_PROJ" in
  *"./go/pkg/mod/**"*) echo "project root must not get the home tier" >&2; exit 1 ;;
esac
case "$TIER_PROJ" in
  *'**/.git/**'*) ;;
  *) echo "expected universal tier for a project root" >&2; exit 1 ;;
esac

TIER_EXPLICIT=$(tier_for /home/alice './custom/**')
if [ "$TIER_EXPLICIT" != "./custom/**" ]; then
  echo "explicit SBOM_EXCLUDE_PATHS must be used verbatim" >&2
  exit 1
fi

# The /home and /Users parents get the home tier applied per user (./*/...).
TIER_HOMES_PARENT=$(tier_for /home)
case "$TIER_HOMES_PARENT" in
  *"./*/go/pkg/mod/**"*) ;;
  *) echo "expected per-user home tier for /home" >&2; exit 1 ;;
esac
case "$TIER_HOMES_PARENT" in
  *'**/.git/**'*) ;;
  *) echo "expected universal tier for /home" >&2; exit 1 ;;
esac
rm -f "$TIER_FN"

# The default scan root is OS-aware (/home on Linux, /Users on macOS).
ROOT_FN=$(mktemp "${TMPDIR:-/tmp}/sbom-smoke-rootfn.XXXXXX")
sed -n '/^is_true()/,/^}/p' collect-sbom-inventory.sh > "$ROOT_FN"
sed -n '/^set_defaults()/,/^}/p' collect-sbom-inventory.sh >> "$ROOT_FN"
DEFAULT_ROOT=$(
  # shellcheck disable=SC1090
  . "$ROOT_FN"
  unset SBOM_SCAN_ROOTS
  set_defaults
  printf '%s' "$SBOM_SCAN_ROOTS"
)
rm -f "$ROOT_FN"
case "$(uname -s)" in
  Linux)
    if [ "$DEFAULT_ROOT" != "/home" ]; then
      echo "expected default scan root /home on Linux, got: $DEFAULT_ROOT" >&2
      exit 1
    fi
    ;;
  Darwin)
    if [ "$DEFAULT_ROOT" != "/Users" ]; then
      echo "expected default scan root /Users on macOS, got: $DEFAULT_ROOT" >&2
      exit 1
    fi
    ;;
esac

printf 'collector smoke test passed\n'
