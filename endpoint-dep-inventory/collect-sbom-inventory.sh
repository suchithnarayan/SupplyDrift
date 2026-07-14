#!/usr/bin/env bash
# shellcheck disable=SC2317

set -eo pipefail

COLLECTOR_VERSION="0.4.0"
PAYLOAD_SCHEMA_VERSION="1"
DEFAULT_SCAN_POLICY_VERSION="homes-v1"
CLI_DRY_RUN=false
CLI_REPORT=false
CLI_MALWARE=false
SBOM_OUTPUT_FILE=${SBOM_OUTPUT_FILE:-}
# Canonicalized config path validated by enforce_config_source_safety and sourced
# by load_config; reset here so a value cannot be smuggled in via the environment.
SBOM_RESOLVED_CONFIG_FILE=""
SERVER_BACKPRESSURE=false
STOP_UPLOADS=false
UPLOAD_FAILURES=0
BATCHES_UPLOADED=0
BATCHES_QUEUED=0
BATCHES_DROPPED=0
SCAN_FAILURES=0
TOTAL_PACKAGES=0
TOTAL_VULNERABILITIES=0
TOTAL_BATCHES=0
GRYPE_VERSION="unknown"
RUN_STATUS="success"
SKIP_REASON=""
CLI_FORCE_FULL=false
ROOTS_SCANNED=0
ROOTS_UNCHANGED=0
ROOTS_TOTAL=0
GATE_SWEEP_SECONDS=0
GRYPE_SKIPPED=0
GATE_RESULTS=""
HEARTBEAT_ROOTS=""
HEARTBEAT_STATUS="not-applicable"
EFFECTIVE_PARALLELISM=""
LAST_FULL_SCAN_AT=""
SR_GRYPE_OK=true
SR_FINAL_RESULT=""
GATE_TAB=$(printf '\t')
LOG_LEVEL=1
CLI_LOG_LEVEL=""
STDERR_IS_TTY=false
STATUS_ACTIVE=false
STATUS_LAST_LEN=0
STATUS_SPIN_IDX=0
STATUS_NEXT_HEARTBEAT=0
SCRIPT_START_EPOCH=$(date +%s)
ACTIVE_CHILD_PID=""

if [ -t 2 ]; then
  STDERR_IS_TTY=true
fi

usage() {
  cat <<'EOF'
Usage: collect-sbom-inventory.sh [--config FILE] [--dry-run] [--full]
                                 [--quiet|--verbose] [--output FILE [--report]]

Runs Syft (+grype), extracts a compact package inventory from syft-json, and
uploads batched JSON payloads to an inventory server.

Output:
  --quiet                    Errors and warnings only.
  --verbose                  Adds command lines, byte counts, and HTTP codes.
  SBOM_LOG_LEVEL             quiet|info|verbose. Default: info. CLI flags win.

  Progress goes to stderr. Interactive terminals get an in-place status line
  with a spinner and elapsed time during long scans and sweeps; non-TTY runs
  (cron, systemd, pipes) get plain timestamped heartbeat lines every 60s.

Local CLI mode:
  --output FILE              Write ONE consolidated JSON (packages + vulnerabilities)
                             for this endpoint to FILE and do not upload. No server needed.
  --report                   With --output: emit a flattened {target, components,
                             vulnerabilities} report instead of the upload payload.
  --malware                  With --output: also check scanned packages against OSV's
                             malicious-package (MAL-*) feed and add a "malware" array.

Required unless --dry-run or --output is used:
  SBOM_SERVER_URL            Server endpoint that accepts inventory batch POSTs.
  SBOM_AUTH_TOKEN            Bearer token for SBOM_SERVER_URL.
  SBOM_AUTH_TOKEN_FILE       Optional file containing the bearer token.

Core configuration:
  SBOM_SCAN_ROOTS            Colon-separated scan roots. Default: /home (Linux)
                             or /Users (macOS). Set "/" for full-filesystem
                             coverage including OS packages.
  SBOM_EXCLUDE_PATHS         Colon-separated Syft exclude patterns starting ./, */, or **/.
                             Empty applies tiered built-in defaults per scan root.
  SBOM_USE_DEFAULT_EXCLUDES  Apply tiered built-in excludes when SBOM_EXCLUDE_PATHS is
                             empty: full OS list for "/", cache tier for home roots,
                             VCS/bytecode tier for any root. Default: true.
  SBOM_BATCH_SIZE            Packages per upload batch. Default: 500.
  SBOM_MAX_BATCH_BYTES       Warn when a batch exceeds this size. Default: 2097152.
  SBOM_CONFIG_FILE           Optional shell-style config file.
  SBOM_DRY_RUN               true/false. Print batches instead of uploading.

Production controls:
  SBOM_STATE_DIR             Local collector state. Default: ~/.sbom-inventory.
  SBOM_ENDPOINT_ID_FILE      Stable endpoint ID file. Default: $SBOM_STATE_DIR/endpoint-id.
  SBOM_LOCK_DIR              Portable run lock. Default: $SBOM_STATE_DIR/run.lock.
  SBOM_SYFT_PARALLELISM      Syft worker count. Default: 2.
  SBOM_START_JITTER_SECONDS  Random startup delay. Default: 0.
  SBOM_SKIP_ON_BATTERY       true/false. Default: false.
  SBOM_MAX_LOAD_1M           Skip when 1m load is above this value. Default: empty.
  SBOM_ENABLE_TASKPOLICY     macOS: run scanners at background QoS via taskpolicy -b.
                             Default: true.
  SBOM_MIN_FREE_MB           Minimum free MB for state dir. Default: 256.
  SBOM_MAX_RUN_SECONDS       Kill a Syft root scan after this many seconds. Default: 0.

Vulnerability scanning:
  SBOM_ENABLE_VULN_SCAN      Run grype on the SBOM and upload vulns. Default: true.
  SBOM_GRYPE_BIN             grype binary. Default: grype.
  SBOM_VULN_BATCH_SIZE       Vulnerabilities per upload batch. Default: 1000.
  SBOM_GRYPE_DB_AUTO_UPDATE  Let grype auto-update its DB. Default: true.

Change gate (frequent-run optimization):
  --full                     Force a full scan + upload for every root this run.
  SBOM_CHANGE_GATE           Skip syft for a root when a cheap mtime sweep finds no
                             dependency-relevant changes since the last scan. Default: true.
  SBOM_FULL_SCAN_INTERVAL_HOURS  Force a full scan at least this often. Default: 168.
  SBOM_HEARTBEAT_ON_UNCHANGED    Upload one tiny heartbeat payload when every root
                             is unchanged so the server sees liveness. Default: true.
  SBOM_GATE_MANIFEST_NAMES   Colon-separated manifest/lockfile name globs the sweep watches.
  SBOM_GATE_DEP_DIR_NAMES    Colon-separated dependency directory names the sweep watches.
  SBOM_GATE_EXTRA_PATHS      Colon-separated extra absolute paths the sweep watches.

Adaptive parallelism:
  SBOM_ADAPTIVE_PARALLELISM  Raise syft parallelism toward half the CPU cores when the
                             machine is on AC power with low load. Default: true.
  SBOM_MAX_PARALLELISM       Upper bound for adaptive parallelism. Default: 8.

Upload and queue controls:
  SBOM_COMPRESS_UPLOAD       gzip uploads. Default: true.
  SBOM_TIMEOUT_SECONDS       curl timeout in seconds. Default: 30.
  SBOM_UPLOAD_RETRIES        Upload retry attempts before queueing. Default: 2.
  SBOM_RETRY_DELAY_SECONDS   Delay between upload retries. Default: 5.
  SBOM_QUEUE_DIR             Failed upload queue. Default: $SBOM_STATE_DIR/queue.
  SBOM_MAX_QUEUE_FILES       Queue file cap. Default: 10000.
  SBOM_MAX_QUEUE_BYTES       Queue byte cap. Default: 1073741824.
  SBOM_QUEUE_RETRY_LIMIT     Queued payloads retried per run. Default: 25.

Config and token safety:
  The config file is dot-sourced as shell, so write access to it OR its parent
  directory is arbitrary code execution as the collector (often root).
  SBOM_STRICT_CONFIG_PERMS   Refuse (not just warn) a token-bearing config or token
                             file that is group/other readable or writable, and treat
                             unreadable perms as unsafe. Default: true.
  SBOM_ALLOW_UNSAFE_CONFIG   Bypass the refusal to source a group/world-writable or
                             foreign-owned config (or one in such a directory).
                             Default: false.

Precedence:
  built-in defaults < config file < environment variables < CLI flags
EOF
}

ts() {
  date '+[%H:%M:%S] '
}

clear_status_line() {
  if [ "$STATUS_ACTIVE" = true ]; then
    printf '\r%*s\r' "$STATUS_LAST_LEN" '' >&2
    STATUS_ACTIVE=false
  fi
}

emit() {
  clear_status_line
  printf '%s%s\n' "$(ts)" "$*" >&2
}

log() {
  [ "$LOG_LEVEL" -ge 1 ] || return 0
  emit "$*"
}

vlog() {
  [ "$LOG_LEVEL" -ge 2 ] || return 0
  emit "$*"
}

warn() {
  emit "warning: $*"
}

die() {
  emit "error: $*"
  exit 1
}

fmt_elapsed() {
  fe_total=$1
  if [ "$fe_total" -lt 60 ]; then
    printf '%ds' "$fe_total"
  elif [ "$fe_total" -lt 3600 ]; then
    printf '%dm%02ds' $((fe_total / 60)) $((fe_total % 60))
  else
    printf '%dh%02dm' $((fe_total / 3600)) $(((fe_total % 3600) / 60))
  fi
}

init_logging() {
  case "${SBOM_LOG_LEVEL:-info}" in
    quiet) LOG_LEVEL=0 ;;
    info) LOG_LEVEL=1 ;;
    verbose) LOG_LEVEL=2 ;;
    *) die "SBOM_LOG_LEVEL must be quiet, info, or verbose: $SBOM_LOG_LEVEL" ;;
  esac
  if [ -n "$CLI_LOG_LEVEL" ]; then
    LOG_LEVEL=$CLI_LOG_LEVEL
  fi
}

is_true() {
  case "${1:-}" in
    true|TRUE|yes|YES|1) return 0 ;;
    *) return 1 ;;
  esac
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

normalize_root() {
  case "$1" in
    "") return 1 ;;
    "/") printf '/\n' ;;
    */) printf '%s\n' "${1%/}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

make_id() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
  elif [ -r /proc/sys/kernel/random/uuid ]; then
    tr '[:upper:]' '[:lower:]' < /proc/sys/kernel/random/uuid
  elif command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
  else
    printf '%s-%s-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$" "$(hostname 2>/dev/null || uname -n)"
  fi
}

make_hash() {
  value=$1
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$value" | sha256sum | awk '{print substr($1, 1, 16)}'
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "$value" | shasum -a 256 | awk '{print substr($1, 1, 16)}'
  else
    printf '%s' "$value" | cksum | awk '{print $1}'
  fi
}

make_stdin_hash() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print substr($1, 1, 16)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print substr($1, 1, 16)}'
  else
    cksum | awk '{print $1}'
  fi
}

# Packages are sorted by key in the normalized payload, so this digest is
# deterministic for an identical installed package set.
compute_package_digest() {
  jq -r '.packages[] | .key + "@" + .version' "$1" | make_stdin_hash
}

with_colon_values() {
  values=$1
  callback=$2

  [ -n "$values" ] || return 0

  noglob_was_set=false
  case $- in
    *f*) noglob_was_set=true ;;
    *) set -f ;;
  esac

  old_ifs=$IFS
  IFS=:
  for item in $values; do
    IFS=$old_ifs
    if [ -n "$item" ]; then
      if [ "$noglob_was_set" = false ]; then
        set +f
      fi
      "$callback" "$item"
      if [ "$noglob_was_set" = false ]; then
        set -f
      fi
    fi
    IFS=:
  done
  IFS=$old_ifs

  if [ "$noglob_was_set" = false ]; then
    set +f
  fi
}

validate_positive_int() {
  name=$1
  value=$2
  case "$value" in
    ''|*[!0-9]*) die "$name must be a positive integer" ;;
  esac
  [ "$value" -gt 0 ] || die "$name must be greater than zero"
}

validate_nonnegative_int() {
  name=$1
  value=$2
  case "$value" in
    ''|*[!0-9]*) die "$name must be a non-negative integer" ;;
  esac
}

validate_exclude_pattern() {
  exclude_pattern=$1
  case "$exclude_pattern" in
    ./*|\*/*|\*\*/*) ;;
    *)
      die "SBOM_EXCLUDE_PATHS pattern must start with ./, */, or **/: $exclude_pattern"
      ;;
  esac
}

validate_exclude_paths() {
  with_colon_values "${SBOM_EXCLUDE_PATHS:-}" validate_exclude_pattern
}

validate_gate_extra_path() {
  case "$1" in
    /*) ;;
    *) die "SBOM_GATE_EXTRA_PATHS entries must be absolute paths: $1" ;;
  esac
}

append_one_syft_exclude() {
  syft_args+=(--exclude "$1")
}

append_syft_excludes() {
  with_colon_values "${EFFECTIVE_EXCLUDE_PATHS:-}" append_one_syft_exclude
}

fs_type_skipped() {
  fs_type=$1
  old_ifs=$IFS
  IFS=,
  for pattern in $SBOM_SKIP_FILESYSTEM_TYPES; do
    IFS=$old_ifs
    # Filesystem skip entries may use shell globs, e.g. fuse.*.
    # shellcheck disable=SC2254
    case "$fs_type" in
      $pattern) IFS=$old_ifs; return 0 ;;
    esac
    IFS=,
  done
  IFS=$old_ifs
  return 1
}

mount_path_to_exclude() {
  mount_path=$1
  case "$mount_path" in
    "/"|"") return 0 ;;
    /*) printf '.%s/**\n' "$mount_path" ;;
    *) return 0 ;;
  esac
}

# Iterate skipped-fstype mounts that sit under the scan root. WSM_ROOT is
# exposed for callbacks. The scan root itself is never reported, even when it
# is a skipped mount (e.g. an NFS /home) — the configured root always scans.
with_skipped_mounts() {
  WSM_ROOT=$1
  wsm_callback=$2

  is_true "$SBOM_SKIP_REMOTE_MOUNTS" || return 0
  [ -r /proc/mounts ] || return 0

  while read -r _device mount_path fs_type _rest; do
    if fs_type_skipped "$fs_type"; then
      case "$mount_path" in
        "$WSM_ROOT") ;;
        /*)
          if [ "$WSM_ROOT" = "/" ]; then
            "$wsm_callback" "$mount_path"
          else
            case "$mount_path" in
              "$WSM_ROOT"/*) "$wsm_callback" "$mount_path" ;;
            esac
          fi
          ;;
      esac
    fi
  done < /proc/mounts
}

append_one_mount_exclude() {
  if [ "$WSM_ROOT" = "/" ]; then
    exclude_pattern=$(mount_path_to_exclude "$1" || true)
  else
    # Syft excludes are root-relative: /home/nfs under root /home -> ./nfs/**
    exclude_pattern=".${1#"$WSM_ROOT"}/**"
  fi
  if [ -n "$exclude_pattern" ]; then
    syft_args+=(--exclude "$exclude_pattern")
  fi
}

append_dynamic_mount_excludes() {
  with_skipped_mounts "$1" append_one_mount_exclude
}

config_has_token() {
  [ -n "${SBOM_CONFIG_FILE:-}" ] || return 1
  grep -Eq '^[[:space:]]*SBOM_AUTH_TOKEN(_FILE)?=' "$SBOM_CONFIG_FILE"
}

# Print the 10-char ls-style mode string (e.g. -rw-r--r--) for a path.
# Returns non-zero when the mode cannot be determined so callers can FAIL CLOSED
# (treat "unknown perms" as unsafe) rather than proceeding blind.
perm_mode_string() {
  # ls -ld is used only for the portable mode string; the path is quoted.
  # shellcheck disable=SC2012
  pms_mode=$(ls -ld "$1" 2>/dev/null | awk 'NR==1{print $1}')
  case "$pms_mode" in
    ??????????*) printf '%s\n' "$pms_mode" ;;
    *) return 1 ;;
  esac
}

# Print the owner name for a path (field 3 of ls -ld). Returns non-zero when it
# cannot be determined so callers FAIL CLOSED rather than trusting an empty owner.
perm_owner() {
  # ls -ld is used only for the portable owner field; the path is quoted.
  # shellcheck disable=SC2012
  po_owner=$(ls -ld "$1" 2>/dev/null | awk 'NR==1{print $3}')
  [ -n "$po_owner" ] || return 1
  printf '%s\n' "$po_owner"
}

# True when a mode string grants write to group (char 6) or other (char 9).
mode_group_or_world_writable() {
  [ "$(printf '%s' "$1" | cut -c6)" != "-" ] || [ "$(printf '%s' "$1" | cut -c9)" != "-" ]
}

# True when a DIRECTORY mode string lets someone other than the file owner swap a
# file inside it. The sticky bit (char 10 = t/T) restricts rename/delete to each
# file's owner or root, so a sticky directory is safe against the config-swap TOCTOU
# regardless of its group/other write bits (this is why /tmp, drwxrwxrwt, is fine).
# Without sticky, any group-write (char 6) or other-write (char 9) bit is unsafe.
dir_swap_unsafe() {
  case "$(printf '%s' "$1" | cut -c10)" in
    t|T) return 1 ;;
  esac
  if [ "$(printf '%s' "$1" | cut -c6)" != "-" ]; then
    return 0
  fi
  if [ "$(printf '%s' "$1" | cut -c9)" != "-" ]; then
    return 0
  fi
  return 1
}

# True when a mode string grants read or write to group/other (chars 5,6,8,9).
mode_group_or_world_accessible() {
  [ "$(printf '%s' "$1" | cut -c5-6)$(printf '%s' "$1" | cut -c8-9)" != "----" ]
}

check_config_permissions() {
  [ -n "${SBOM_CONFIG_FILE:-}" ] || return 0
  [ -f "$SBOM_CONFIG_FILE" ] || return 0
  config_has_token || return 0

  # Fail CLOSED: if we cannot read the mode, treat perms as unknown/unsafe.
  if ! ccp_perms=$(perm_mode_string "$SBOM_CONFIG_FILE"); then
    message="cannot determine permissions of token-bearing config: $SBOM_CONFIG_FILE"
  elif mode_group_or_world_accessible "$ccp_perms"; then
    message="config file contains token settings and is readable or writable by group/other: $SBOM_CONFIG_FILE"
  else
    return 0
  fi
  if is_true "$SBOM_STRICT_CONFIG_PERMS"; then
    die "$message"
  else
    warn "$message"
  fi
}

# The config file is dot-sourced as shell (so values may use $HOME, ${VAR}, etc).
# That means anyone who can WRITE the file OR its parent directory can run arbitrary
# code as the collector (often root): with parent-dir write an attacker can swap the
# file between the permission check and the source (TOCTOU). So we canonicalize the
# path ONCE, validate that both the file and its parent directory are not group/world-
# writable and are owned by the invoking user or root, refuse a symlink whose target
# directory is writable, and then source exactly that resolved path without re-resolving.
# Any permission we cannot read is treated as unsafe (fail closed). Set
# SBOM_ALLOW_UNSAFE_CONFIG=true to bypass (a deliberately shared, otherwise-protected
# config). The resolved path is published in SBOM_RESOLVED_CONFIG_FILE for load_config.
enforce_config_source_safety() {
  SBOM_RESOLVED_CONFIG_FILE=${SBOM_CONFIG_FILE:-}
  [ -n "${SBOM_CONFIG_FILE:-}" ] || return 0
  [ -f "$SBOM_CONFIG_FILE" ] || return 0

  # Canonicalize the parent directory once (resolves any symlinks in the dir path),
  # keep the basename, and source that exact path. pwd -P drops symlinks; we do not
  # follow a final-component symlink automatically so we can vet its target below.
  ecs_dir=$(dirname "$SBOM_CONFIG_FILE")
  ecs_base=$(basename "$SBOM_CONFIG_FILE")
  ecs_real_dir=$(cd "$ecs_dir" 2>/dev/null && pwd -P) || die "cannot resolve config directory (fail closed): $ecs_dir"
  case "$ecs_real_dir" in
    */) SBOM_RESOLVED_CONFIG_FILE="$ecs_real_dir$ecs_base" ;;
    *) SBOM_RESOLVED_CONFIG_FILE="$ecs_real_dir/$ecs_base" ;;
  esac

  is_true "${SBOM_ALLOW_UNSAFE_CONFIG:-false}" && return 0

  # Parent directory: a group/world-writable parent enables the TOCTOU swap even if
  # the file itself is locked down, so it is checked with the same rigor as the file.
  ecs_dir_owner=$(perm_owner "$ecs_real_dir") || die "cannot determine permissions of config directory (fail closed): $ecs_real_dir"
  if ! ecs_dir_perms=$(perm_mode_string "$ecs_real_dir"); then
    die "cannot determine permissions of config directory (fail closed): $ecs_real_dir"
  fi
  if dir_swap_unsafe "$ecs_dir_perms"; then
    die "refusing to source config from a group/world-writable directory (run 'chmod go-w \"$ecs_real_dir\"' or set SBOM_ALLOW_UNSAFE_CONFIG=true): $ecs_real_dir"
  fi
  if [ ! -O "$ecs_real_dir" ] && [ "$ecs_dir_owner" != "root" ]; then
    die "refusing to source config from a directory not owned by you or root (fix ownership or set SBOM_ALLOW_UNSAFE_CONFIG=true): $ecs_real_dir"
  fi

  # A symlinked config is only as trustworthy as the directory holding its target:
  # if that directory is writable the target can be swapped, so refuse it. readlink
  # (plain, no -f) is portable on GNU and BSD and prints the raw link target; a
  # relative target is resolved against the symlink's own directory. We then re-point
  # the resolved path at the REAL target file so the perm/owner checks below (and the
  # eventual source) inspect the file that is actually read, not the lrwxrwxrwx link.
  # A deeper symlink chain (target is itself a symlink) is left to fail closed at the
  # writable-file check below, which is safe.
  if [ -h "$SBOM_RESOLVED_CONFIG_FILE" ]; then
    ecs_link=$(readlink "$SBOM_RESOLVED_CONFIG_FILE" 2>/dev/null) || die "cannot read config symlink target (fail closed): $SBOM_RESOLVED_CONFIG_FILE"
    [ -n "$ecs_link" ] || die "cannot read config symlink target (fail closed): $SBOM_RESOLVED_CONFIG_FILE"
    ecs_target_dir=$(cd "$ecs_real_dir" 2>/dev/null && cd "$(dirname "$ecs_link")" 2>/dev/null && pwd -P) || die "cannot resolve config symlink target directory (fail closed): $ecs_link"
    if ! ecs_target_perms=$(perm_mode_string "$ecs_target_dir"); then
      die "cannot determine permissions of config symlink target directory (fail closed): $ecs_target_dir"
    fi
    if dir_swap_unsafe "$ecs_target_perms"; then
      die "refusing to source a config symlink whose target directory is group/world-writable (or set SBOM_ALLOW_UNSAFE_CONFIG=true): $ecs_target_dir"
    fi
    case "$ecs_target_dir" in
      */) SBOM_RESOLVED_CONFIG_FILE="$ecs_target_dir$(basename "$ecs_link")" ;;
      *) SBOM_RESOLVED_CONFIG_FILE="$ecs_target_dir/$(basename "$ecs_link")" ;;
    esac
    [ -f "$SBOM_RESOLVED_CONFIG_FILE" ] || die "config symlink target is not a regular file (fail closed): $SBOM_RESOLVED_CONFIG_FILE"
  fi

  # The config file itself: reject group/world-writable or foreign-owned files.
  ecs_owner=$(perm_owner "$SBOM_RESOLVED_CONFIG_FILE") || die "cannot determine permissions of config (fail closed): $SBOM_RESOLVED_CONFIG_FILE"
  if ! ecs_perms=$(perm_mode_string "$SBOM_RESOLVED_CONFIG_FILE"); then
    die "cannot determine permissions of config (fail closed): $SBOM_RESOLVED_CONFIG_FILE"
  fi
  if mode_group_or_world_writable "$ecs_perms"; then
    die "refusing to source group/world-writable config (run 'chmod go-w \"$SBOM_RESOLVED_CONFIG_FILE\"' or set SBOM_ALLOW_UNSAFE_CONFIG=true): $SBOM_RESOLVED_CONFIG_FILE"
  fi
  if [ ! -O "$SBOM_RESOLVED_CONFIG_FILE" ] && [ "$ecs_owner" != "root" ]; then
    die "refusing to source config not owned by you or root (fix ownership or set SBOM_ALLOW_UNSAFE_CONFIG=true): $SBOM_RESOLVED_CONFIG_FILE"
  fi
}

load_config() {
  if [ -n "${SBOM_CONFIG_FILE:-}" ]; then
    [ -f "$SBOM_CONFIG_FILE" ] || die "config file not found: $SBOM_CONFIG_FILE"
    enforce_config_source_safety
    # Snapshot SBOM_* environment variables before sourcing so they win over
    # config values: defaults < config file < environment < CLI flags.
    # (A multi-line SBOM_* env value would lose its tail here; values are
    # paths, numbers, and booleans in practice.)
    lc_env_snapshot=$(env | grep '^SBOM_' || true)
    # Source the exact resolved path validated above (not $SBOM_CONFIG_FILE) so the
    # check and the source name the same file, closing the TOCTOU swap window.
    # Config files are shell-style KEY=VALUE files.
    # shellcheck disable=SC1090
    . "$SBOM_RESOLVED_CONFIG_FILE"
    while IFS= read -r lc_line; do
      [ -n "$lc_line" ] || continue
      lc_key=${lc_line%%=*}
      case "$lc_key" in
        SBOM_*[!A-Z0-9_]*|SBOM_) continue ;;
        SBOM_*) printf -v "$lc_key" '%s' "${lc_line#*=}" ;;
        *) continue ;;
      esac
    done <<EOF
$lc_env_snapshot
EOF
  fi
}

load_auth_token() {
  if [ -z "${SBOM_AUTH_TOKEN:-}" ] && [ -n "${SBOM_AUTH_TOKEN_FILE:-}" ]; then
    [ -f "$SBOM_AUTH_TOKEN_FILE" ] || die "SBOM_AUTH_TOKEN_FILE not found: $SBOM_AUTH_TOKEN_FILE"
    # The token file holds a bearer credential; it must not be group/world-readable.
    # Fail CLOSED when perms are unreadable. Refuse under strict mode, else warn.
    if ! lat_perms=$(perm_mode_string "$SBOM_AUTH_TOKEN_FILE"); then
      lat_message="cannot determine permissions of token file: $SBOM_AUTH_TOKEN_FILE"
    elif mode_group_or_world_accessible "$lat_perms"; then
      lat_message="token file is readable or writable by group/other: $SBOM_AUTH_TOKEN_FILE"
    else
      lat_message=""
    fi
    if [ -n "$lat_message" ]; then
      if is_true "$SBOM_STRICT_CONFIG_PERMS"; then
        die "$lat_message"
      else
        warn "$lat_message"
      fi
    fi
    IFS= read -r SBOM_AUTH_TOKEN < "$SBOM_AUTH_TOKEN_FILE" || true
  fi
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --config)
        [ "$#" -ge 2 ] || die "--config requires a file path"
        SBOM_CONFIG_FILE=$2
        shift 2
        ;;
      --dry-run)
        CLI_DRY_RUN=true
        shift
        ;;
      --full)
        CLI_FORCE_FULL=true
        shift
        ;;
      --quiet)
        CLI_LOG_LEVEL=0
        shift
        ;;
      --verbose)
        CLI_LOG_LEVEL=2
        shift
        ;;
      --output)
        [ "$#" -ge 2 ] || die "--output requires a file path"
        SBOM_OUTPUT_FILE=$2
        shift 2
        ;;
      --report)
        CLI_REPORT=true
        shift
        ;;
      --malware)
        CLI_MALWARE=true
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done
}

# Universal tier: directory names that can never hold dependency evidence.
# Safe for ANY scan root.
default_universal_excludes() {
  printf '%s\n' "**/.git/**:**/.hg/**:**/.svn/**:**/__pycache__/**:**/node_modules/.cache/**"
}

# Home tier: cache directories inside a user home, anchored to a scan root
# that IS a home directory. Keep in sync with the ./home/*/ and ./Users/*/
# entries in default_exclude_paths_for_os below.
default_home_excludes() {
  case "$(uname -s)" in
    Darwin)
      printf '%s\n' "./.npm/_cacache/**:./.cargo/registry/**:./go/pkg/mod/**:./miniconda3/pkgs/**:./anaconda3/pkgs/**:./.conda/pkgs/**:./.Trash/**:./Library/Caches/**:./Library/Logs/**:./Library/CloudStorage/**:./Library/Mobile Documents/**:./Library/Developer/CoreSimulator/**:./Library/Developer/Xcode/DerivedData/**:./Library/Developer/Xcode/iOS DeviceSupport/**:./Library/Containers/**:./Library/Group Containers/**:./Library/Application Support/**:./Library/Mail/**:./Pictures/Photos Library.photoslibrary/**:./Library/pnpm/store/**"
      ;;
    *)
      printf '%s\n' "./.cache/**:./.npm/_cacache/**:./.cargo/registry/**:./go/pkg/mod/**:./.local/share/pnpm/store/**:./.local/share/containers/**:./.local/share/flatpak/**:./.local/share/Trash/**:./.docker/desktop/**:./miniconda3/pkgs/**:./anaconda3/pkgs/**:./.conda/pkgs/**"
      ;;
  esac
}

# Home tier re-anchored for scans of the homes PARENT (/home or /Users):
# each ./x/** entry becomes ./*/x/** so it applies inside every user home.
default_homes_parent_excludes() {
  dhp=$(default_home_excludes)
  dhp=${dhp//':./'/':./*/'}
  printf '%s\n' "./*/${dhp#./}"
}

# Effective exclude list for one scan root:
#   explicit SBOM_EXCLUDE_PATHS  -> used verbatim for every root
#   defaults disabled            -> empty
#   "/"                          -> full OS-aware list
#   /home or /Users (default)    -> universal + per-user home cache tier
#   a home directory itself      -> universal + home cache tier
#   anything else                -> universal tier only (anchored patterns
#                                   would be wrong relative to project roots)
effective_excludes_for_root() {
  eer_root=$1

  if [ -n "${SBOM_EXCLUDE_PATHS:-}" ] || ! is_true "$SBOM_USE_DEFAULT_EXCLUDES"; then
    printf '%s\n' "${SBOM_EXCLUDE_PATHS:-}"
    return 0
  fi

  if [ "$eer_root" = "/" ]; then
    default_exclude_paths_for_os
    return 0
  fi

  case "$eer_root" in
    /home|/Users)
      printf '%s:%s\n' "$(default_universal_excludes)" "$(default_homes_parent_excludes)"
      ;;
    /home/*/*|/Users/*/*)
      default_universal_excludes
      ;;
    /home/*|/Users/*|/root)
      printf '%s:%s\n' "$(default_universal_excludes)" "$(default_home_excludes)"
      ;;
    *)
      default_universal_excludes
      ;;
  esac
}

# OS-aware default excludes for full-filesystem scans. Root-anchored patterns
# so project directories like $HOME/project/tmp are never skipped by accident.
# The one non-anchored default is **/.git/** — git object stores are zlib
# blobs syft can never parse (pure traversal waste, zero coverage value).
#
# Deliberate coverage trade-offs (re-include via SBOM_EXCLUDE_PATHS):
# - container layer storage: covered by image scanning, not host scans
# - snap/flatpak runtime stores: app presence still shows via OS package DBs
# - macOS cloud placeholders: traversal can HYDRATE files (download on read)
default_exclude_paths_for_os() {
  case "$(uname -s)" in
    Darwin)
      printf '%s\n' "**/.git/**:**/.hg/**:**/.svn/**:**/__pycache__/**:**/node_modules/.cache/**:./dev/**:./Volumes/**:./System/Volumes/Data/private/tmp/**:./private/tmp/**:./private/var/tmp/**:./private/var/log/**:./private/var/folders/**:./System/Volumes/Data/private/var/folders/**:./System/Library/**:./System/Applications/**:./System/iOSSupport/**:./System/DriverKit/**:./System/Cryptexes/**:./Library/Developer/CommandLineTools/**:./.Spotlight-V100/**:./.fseventsd/**:./.DocumentRevisions-V100/**:./.TemporaryItems/**:./usr/share/man/**:./Library/Caches/**:./Library/Logs/**:./Users/*/Library/Caches/**:./Users/*/Library/Logs/**:./Users/*/.Trash/**:./Users/*/Library/CloudStorage/**:./Users/*/Library/Mobile Documents/**:./Users/*/Library/Developer/CoreSimulator/**:./Users/*/Library/Developer/Xcode/DerivedData/**:./Users/*/Library/Developer/Xcode/iOS DeviceSupport/**:./Users/*/Library/Containers/**:./Users/*/Library/Group Containers/**:./Users/*/Library/Application Support/**:./Users/*/Library/Mail/**:./Users/*/Pictures/Photos Library.photoslibrary/**:./Users/*/.npm/_cacache/**:./Users/*/.cargo/registry/**:./Users/*/go/pkg/mod/**:./Users/*/Library/pnpm/store/**:./usr/include/**:./Users/*/miniconda3/pkgs/**:./Users/*/anaconda3/pkgs/**:./Users/*/.conda/pkgs/**:./cores/**:./private/var/db/**:./Library/Apple/**:./Library/Updates/**:./Library/Application Support/**"
      ;;
    Linux)
      printf '%s\n' "**/.git/**:**/.hg/**:**/.svn/**:**/__pycache__/**:**/node_modules/.cache/**:./proc/**:./sys/**:./dev/**:./run/**:./tmp/**:./var/tmp/**:./var/log/**:./var/cache/**:./usr/share/doc/**:./usr/share/man/**:./usr/share/locale/**:./usr/src/**:./usr/lib/firmware/**:./var/lib/apt/lists/**:./home/*/.cache/**:./home/*/.local/share/Trash/**:./root/.cache/**:./var/lib/docker/**:./var/lib/containerd/**:./var/lib/containers/**:./home/*/.local/share/containers/**:./home/*/.docker/desktop/**:./snap/**:./var/lib/snapd/**:./var/lib/flatpak/**:./home/*/.local/share/flatpak/**:./home/*/.npm/_cacache/**:./var/lib/libvirt/images/**:./home/*/.cargo/registry/**:./home/*/go/pkg/mod/**:./home/*/.local/share/pnpm/store/**:./home/*/miniconda3/pkgs/**:./home/*/anaconda3/pkgs/**:./home/*/.conda/pkgs/**:./opt/conda/pkgs/**:./mnt/**:./media/**:./boot/**:./lost+found/**:./var/spool/**:./var/crash/**:./var/backups/**:./usr/share/icons/**:./usr/share/fonts/**:./usr/share/zoneinfo/**:./usr/include/**:./usr/share/go-*/**"
      ;;
    *)
      printf '%s\n' "**/.git/**:**/.hg/**:**/.svn/**:**/__pycache__/**:**/node_modules/.cache/**:./dev/**:./tmp/**:./var/tmp/**:./var/log/**:./var/cache/**:./home/*/.cache/**"
      ;;
  esac
}

set_defaults() {
  SBOM_STATE_DIR=${SBOM_STATE_DIR:-"$HOME/.sbom-inventory"}
  SBOM_QUEUE_DIR=${SBOM_QUEUE_DIR:-"$SBOM_STATE_DIR/queue"}
  SBOM_RAW_DIR=${SBOM_RAW_DIR:-"$SBOM_STATE_DIR/raw"}
  SBOM_ENDPOINT_ID_FILE=${SBOM_ENDPOINT_ID_FILE:-"$SBOM_STATE_DIR/endpoint-id"}
  SBOM_LOCK_DIR=${SBOM_LOCK_DIR:-"$SBOM_STATE_DIR/run.lock"}
  SBOM_SCAN_POLICY_VERSION=${SBOM_SCAN_POLICY_VERSION:-"$DEFAULT_SCAN_POLICY_VERSION"}

  SBOM_BATCH_SIZE=${SBOM_BATCH_SIZE:-500}
  SBOM_MAX_BATCH_BYTES=${SBOM_MAX_BATCH_BYTES:-2097152}
  SBOM_TIMEOUT_SECONDS=${SBOM_TIMEOUT_SECONDS:-30}
  SBOM_UPLOAD_RETRIES=${SBOM_UPLOAD_RETRIES:-2}
  SBOM_RETRY_DELAY_SECONDS=${SBOM_RETRY_DELAY_SECONDS:-5}
  SBOM_MAX_RETRY_AFTER_SECONDS=${SBOM_MAX_RETRY_AFTER_SECONDS:-300}
  SBOM_QUEUE_RETRY_LIMIT=${SBOM_QUEUE_RETRY_LIMIT:-25}
  SBOM_MAX_QUEUE_FILES=${SBOM_MAX_QUEUE_FILES:-10000}
  SBOM_MAX_QUEUE_BYTES=${SBOM_MAX_QUEUE_BYTES:-1073741824}

  SBOM_KEEP_RAW=${SBOM_KEEP_RAW:-false}
  SBOM_DRY_RUN=${SBOM_DRY_RUN:-false}
  SBOM_COMPRESS_UPLOAD=${SBOM_COMPRESS_UPLOAD:-true}
  # Strict by default: refuse a token-bearing config or token file readable/writable
  # by group/other (fail closed). Set SBOM_STRICT_CONFIG_PERMS=false to warn instead.
  SBOM_STRICT_CONFIG_PERMS=${SBOM_STRICT_CONFIG_PERMS:-true}
  # Bypass the source-safety check (group/world-writable or foreign-owned config).
  # Read directly from the environment in enforce_config_source_safety (which runs
  # before set_defaults); listed here for documentation/consistency.
  SBOM_ALLOW_UNSAFE_CONFIG=${SBOM_ALLOW_UNSAFE_CONFIG:-false}
  # Allow plaintext-http uploads (token + inventory in the clear). Default off.
  SBOM_ALLOW_INSECURE=${SBOM_ALLOW_INSECURE:-false}
  SBOM_FAIL_ON_UPLOAD_ERROR=${SBOM_FAIL_ON_UPLOAD_ERROR:-false}

  SBOM_SYFT_PARALLELISM=${SBOM_SYFT_PARALLELISM:-2}
  SBOM_DISABLE_FILE_CATALOGERS=${SBOM_DISABLE_FILE_CATALOGERS:-true}

  # Vulnerability scanning (grype on the syft SBOM). Vuln batches are tiny
  # (name/version/purl/id/severity/fix) so they upload independently of the SBOM.
  SBOM_ENABLE_VULN_SCAN=${SBOM_ENABLE_VULN_SCAN:-true}
  SBOM_GRYPE_BIN=${SBOM_GRYPE_BIN:-grype}
  SBOM_VULN_BATCH_SIZE=${SBOM_VULN_BATCH_SIZE:-1000}
  SBOM_GRYPE_DB_AUTO_UPDATE=${SBOM_GRYPE_DB_AUTO_UPDATE:-true}
  SBOM_NICE=${SBOM_NICE:-10}
  SBOM_ENABLE_IONICE=${SBOM_ENABLE_IONICE:-true}
  # macOS equivalent of ionice: taskpolicy -b runs the scanner at background
  # QoS so the OS throttles its CPU/IO whenever the user is active.
  SBOM_ENABLE_TASKPOLICY=${SBOM_ENABLE_TASKPOLICY:-true}
  SBOM_START_JITTER_SECONDS=${SBOM_START_JITTER_SECONDS:-0}
  SBOM_SKIP_ON_BATTERY=${SBOM_SKIP_ON_BATTERY:-false}
  SBOM_MAX_LOAD_1M=${SBOM_MAX_LOAD_1M:-}
  SBOM_MIN_FREE_MB=${SBOM_MIN_FREE_MB:-256}
  SBOM_MAX_RUN_SECONDS=${SBOM_MAX_RUN_SECONDS:-0}
  SBOM_SKIP_REMOTE_MOUNTS=${SBOM_SKIP_REMOTE_MOUNTS:-true}
  SBOM_SKIP_FILESYSTEM_TYPES=${SBOM_SKIP_FILESYSTEM_TYPES:-"proc,sysfs,devtmpfs,tmpfs,devfs,fdesc,autofs,nfs,nfs4,cifs,smbfs,sshfs,fuse.*,overlay,aufs,squashfs,tracefs,debugfs,securityfs,cgroup,cgroup2,pstore,bpf,nsfs,ramfs,9p,drvfs"}

  # Change gate: skip full scans when a cheap mtime sweep proves nothing
  # dependency-relevant changed. A forced full scan still happens every
  # SBOM_FULL_SCAN_INTERVAL_HOURS as the coverage guarantee.
  SBOM_CHANGE_GATE=${SBOM_CHANGE_GATE:-true}
  SBOM_FULL_SCAN_INTERVAL_HOURS=${SBOM_FULL_SCAN_INTERVAL_HOURS:-168}
  SBOM_HEARTBEAT_ON_UNCHANGED=${SBOM_HEARTBEAT_ON_UNCHANGED:-true}
  SBOM_GATE_EXTRA_PATHS=${SBOM_GATE_EXTRA_PATHS:-}
  SBOM_GATE_MANIFEST_NAMES=${SBOM_GATE_MANIFEST_NAMES:-"package.json:package-lock.json:yarn.lock:pnpm-lock.yaml:bun.lock:bun.lockb:requirements*.txt:pyproject.toml:poetry.lock:Pipfile.lock:uv.lock:go.mod:go.sum:Cargo.toml:Cargo.lock:Gemfile:Gemfile.lock:*.gemspec:pom.xml:build.gradle:build.gradle.kts:composer.json:composer.lock:*.csproj:packages.config:mix.exs:mix.lock:*.podspec"}
  SBOM_GATE_DEP_DIR_NAMES=${SBOM_GATE_DEP_DIR_NAMES:-"node_modules:site-packages:dist-packages:.venv:venv:vendor"}

  SBOM_ADAPTIVE_PARALLELISM=${SBOM_ADAPTIVE_PARALLELISM:-true}
  SBOM_MAX_PARALLELISM=${SBOM_MAX_PARALLELISM:-8}

  # Default scope: user home directories — where developer dependency
  # evidence lives. Set SBOM_SCAN_ROOTS="/" for full-filesystem coverage
  # (OS packages, /opt, /usr/local, ...).
  if [ -z "${SBOM_SCAN_ROOTS:-}" ]; then
    case "$(uname -s)" in
      Darwin) SBOM_SCAN_ROOTS="/Users" ;;
      *) SBOM_SCAN_ROOTS="/home" ;;
    esac
  fi

  # Tiered default excludes are resolved per scan root at scan time — see
  # effective_excludes_for_root. This knob disables them everywhere.
  SBOM_USE_DEFAULT_EXCLUDES=${SBOM_USE_DEFAULT_EXCLUDES:-true}
}

validate_config() {
  validate_positive_int SBOM_BATCH_SIZE "$SBOM_BATCH_SIZE"
  validate_positive_int SBOM_MAX_BATCH_BYTES "$SBOM_MAX_BATCH_BYTES"
  validate_positive_int SBOM_TIMEOUT_SECONDS "$SBOM_TIMEOUT_SECONDS"
  validate_nonnegative_int SBOM_UPLOAD_RETRIES "$SBOM_UPLOAD_RETRIES"
  validate_nonnegative_int SBOM_RETRY_DELAY_SECONDS "$SBOM_RETRY_DELAY_SECONDS"
  validate_positive_int SBOM_MAX_RETRY_AFTER_SECONDS "$SBOM_MAX_RETRY_AFTER_SECONDS"
  validate_nonnegative_int SBOM_QUEUE_RETRY_LIMIT "$SBOM_QUEUE_RETRY_LIMIT"
  validate_positive_int SBOM_MAX_QUEUE_FILES "$SBOM_MAX_QUEUE_FILES"
  validate_positive_int SBOM_MAX_QUEUE_BYTES "$SBOM_MAX_QUEUE_BYTES"
  validate_positive_int SBOM_SYFT_PARALLELISM "$SBOM_SYFT_PARALLELISM"
  validate_positive_int SBOM_VULN_BATCH_SIZE "$SBOM_VULN_BATCH_SIZE"
  validate_nonnegative_int SBOM_START_JITTER_SECONDS "$SBOM_START_JITTER_SECONDS"
  validate_positive_int SBOM_MIN_FREE_MB "$SBOM_MIN_FREE_MB"
  validate_nonnegative_int SBOM_MAX_RUN_SECONDS "$SBOM_MAX_RUN_SECONDS"
  validate_positive_int SBOM_FULL_SCAN_INTERVAL_HOURS "$SBOM_FULL_SCAN_INTERVAL_HOURS"
  validate_positive_int SBOM_MAX_PARALLELISM "$SBOM_MAX_PARALLELISM"
  with_colon_values "${SBOM_GATE_EXTRA_PATHS:-}" validate_gate_extra_path
  if is_true "$SBOM_CHANGE_GATE" && [ -z "$SBOM_GATE_MANIFEST_NAMES" ]; then
    die "SBOM_GATE_MANIFEST_NAMES must not be empty when SBOM_CHANGE_GATE is enabled"
  fi

  nice_digits=${SBOM_NICE#-}
  case "$nice_digits" in
    ''|*[!0-9]*) die "SBOM_NICE must be an integer" ;;
  esac

  validate_exclude_paths
  load_auth_token
  check_config_permissions

  # Local output mode needs no server (like --dry-run, but writes one JSON file).
  if ! is_true "$SBOM_DRY_RUN" && [ -z "$SBOM_OUTPUT_FILE" ]; then
    [ -n "${SBOM_SERVER_URL:-}" ] || die "SBOM_SERVER_URL is required"
    [ -n "${SBOM_AUTH_TOKEN:-}" ] || die "SBOM_AUTH_TOKEN or SBOM_AUTH_TOKEN_FILE is required"
    # The upload carries the bearer token and the full inventory. Refuse plaintext
    # HTTP (and any non-http scheme) unless explicitly allowed, so the credential
    # and data are not sent in the clear.
    case "$SBOM_SERVER_URL" in
      https://*) : ;;
      http://*)
        is_true "$SBOM_ALLOW_INSECURE" \
          || die "SBOM_SERVER_URL uses plaintext http (set SBOM_ALLOW_INSECURE=true to allow): $SBOM_SERVER_URL" ;;
      *) die "SBOM_SERVER_URL must be an http(s) URL: $SBOM_SERVER_URL" ;;
    esac
  fi

  if is_true "$SBOM_COMPRESS_UPLOAD"; then
    require_command gzip
  fi
}

ensure_endpoint_id() {
  endpoint_dir=$(dirname "$SBOM_ENDPOINT_ID_FILE")
  mkdir -p "$endpoint_dir"

  if [ -s "$SBOM_ENDPOINT_ID_FILE" ]; then
    IFS= read -r ENDPOINT_ID < "$SBOM_ENDPOINT_ID_FILE" || true
  else
    ENDPOINT_ID=$(make_id)
    tmp_id=$(mktemp "$endpoint_dir/.endpoint-id.XXXXXX")
    printf '%s\n' "$ENDPOINT_ID" > "$tmp_id"
    chmod 600 "$tmp_id" 2>/dev/null || true
    mv "$tmp_id" "$SBOM_ENDPOINT_ID_FILE"
  fi

  [ -n "${ENDPOINT_ID:-}" ] || die "endpoint ID is empty: $SBOM_ENDPOINT_ID_FILE"
}

acquire_lock() {
  lock_parent=$(dirname "$SBOM_LOCK_DIR")
  mkdir -p "$lock_parent"

  if mkdir "$SBOM_LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" > "$SBOM_LOCK_DIR/pid"
    LOCK_ACQUIRED=true
    return 0
  fi

  if [ -r "$SBOM_LOCK_DIR/pid" ]; then
    IFS= read -r existing_pid < "$SBOM_LOCK_DIR/pid" || true
    if [ -n "$existing_pid" ] && kill -0 "$existing_pid" 2>/dev/null; then
      SKIP_REASON="already-running"
      die "another collector run is active with pid $existing_pid"
    fi
    warn "removing stale lock: $SBOM_LOCK_DIR"
    rm -rf "$SBOM_LOCK_DIR"
    mkdir "$SBOM_LOCK_DIR" || die "could not acquire lock: $SBOM_LOCK_DIR"
    printf '%s\n' "$$" > "$SBOM_LOCK_DIR/pid"
    LOCK_ACQUIRED=true
    return 0
  fi

  die "could not acquire lock: $SBOM_LOCK_DIR"
}

release_lock() {
  if [ "${LOCK_ACQUIRED:-false}" = true ] && [ -d "${SBOM_LOCK_DIR:-}" ]; then
    rm -rf "$SBOM_LOCK_DIR"
  fi
}

queue_file_count() {
  if [ -d "$SBOM_QUEUE_DIR" ]; then
    find "$SBOM_QUEUE_DIR" -type f \( -name '*.json' -o -name '*.json.gz' \) 2>/dev/null | wc -l | awk '{print $1}'
  else
    printf '0\n'
  fi
}

queue_byte_count() {
  if [ -d "$SBOM_QUEUE_DIR" ]; then
    du -sk "$SBOM_QUEUE_DIR" 2>/dev/null | awk '{print $1 * 1024}'
  else
    printf '0\n'
  fi
}

queue_payload() {
  payload_file=$1
  mkdir -p "$SBOM_QUEUE_DIR"

  current_files=$(queue_file_count)
  current_bytes=$(queue_byte_count)
  payload_bytes=$(wc -c < "$payload_file" | awk '{print $1}')

  if [ "$current_files" -ge "$SBOM_MAX_QUEUE_FILES" ]; then
    warn "queue file limit reached; not queueing payload: $payload_file"
    BATCHES_DROPPED=$((BATCHES_DROPPED + 1))
    return 1
  fi

  if [ $((current_bytes + payload_bytes)) -gt "$SBOM_MAX_QUEUE_BYTES" ]; then
    warn "queue byte limit reached; not queueing payload: $payload_file"
    BATCHES_DROPPED=$((BATCHES_DROPPED + 1))
    return 1
  fi

  queue_name="$(date -u +%Y%m%dT%H%M%SZ)-$(make_id)-$(basename "$payload_file")"
  tmp_queue=$(mktemp "$SBOM_QUEUE_DIR/.queue.XXXXXX")
  cp "$payload_file" "$tmp_queue"
  mv "$tmp_queue" "$SBOM_QUEUE_DIR/$queue_name"
  BATCHES_QUEUED=$((BATCHES_QUEUED + 1))
  log "queued failed upload: $SBOM_QUEUE_DIR/$queue_name"
}

prepare_upload_body() {
  payload_file=$1
  if is_true "$SBOM_COMPRESS_UPLOAD"; then
    upload_body="$TMP_DIR/upload-$(make_id).json.gz"
    gzip -c "$payload_file" > "$upload_body"
    UPLOAD_BODY_FILE=$upload_body
    UPLOAD_CONTENT_ENCODING="gzip"
  else
    UPLOAD_BODY_FILE=$payload_file
    UPLOAD_CONTENT_ENCODING=""
  fi
}

upload_once() {
  payload_file=$1
  LAST_UPLOAD_HTTP_CODE=""
  LAST_RETRY_AFTER=""

  prepare_upload_body "$payload_file"
  response_file="$TMP_DIR/curl-response-$(make_id).txt"
  header_file="$TMP_DIR/curl-headers-$(make_id).txt"
  error_file="$TMP_DIR/curl-error-$(make_id).txt"

  # Pass the bearer token via a curl config file (inside the 0700 TMP_DIR) instead
  # of -H on the command line, so it never appears in `ps`/`/proc/<pid>/cmdline`.
  auth_config_file="$TMP_DIR/curl-auth-$(make_id).conf"
  (umask 077; printf 'header = "Authorization: Bearer %s"\n' "$SBOM_AUTH_TOKEN" > "$auth_config_file")

  curl_args=(
    --silent
    --show-error
    --output "$response_file"
    --dump-header "$header_file"
    --write-out "%{http_code}"
    --max-time "$SBOM_TIMEOUT_SECONDS"
    --config "$auth_config_file"
    -X POST "$SBOM_SERVER_URL"
    -H "Content-Type: application/json"
  )

  if [ -n "$UPLOAD_CONTENT_ENCODING" ]; then
    curl_args+=(-H "Content-Encoding: $UPLOAD_CONTENT_ENCODING")
  fi

  set +e
  http_code=$(curl "${curl_args[@]}" --data-binary "@$UPLOAD_BODY_FILE" 2>"$error_file")
  rm -f "$auth_config_file"
  curl_status=$?
  set -e

  LAST_UPLOAD_HTTP_CODE=$http_code
  LAST_RETRY_AFTER=$(awk 'BEGIN{IGNORECASE=1} /^Retry-After:/ {gsub("\r", "", $2); print $2; exit}' "$header_file" 2>/dev/null || true)
  vlog "upload attempt HTTP ${http_code:-none}: $(basename "$payload_file")"

  if [ "$curl_status" -ne 0 ]; then
    error_text=$(tr '\n' ' ' < "$error_file")
    warn "upload curl failure: $error_text"
    return 1
  fi

  case "$http_code" in
    2??) return 0 ;;
    429)
      SERVER_BACKPRESSURE=true
      warn "server returned 429 Too Many Requests"
      return 1
      ;;
    413)
      warn "server rejected batch as too large: $payload_file"
      return 1
      ;;
    5??)
      warn "server returned transient HTTP $http_code"
      return 1
      ;;
    *)
      warn "server returned non-retryable HTTP $http_code"
      return 1
      ;;
  esac
}

sleep_before_retry() {
  sbr_next=$1
  sbr_max=$2
  delay=$SBOM_RETRY_DELAY_SECONDS

  if [ -n "${LAST_RETRY_AFTER:-}" ]; then
    case "$LAST_RETRY_AFTER" in
      *[!0-9]*|"") ;;
      *)
        delay=$LAST_RETRY_AFTER
        if [ "$delay" -gt "$SBOM_MAX_RETRY_AFTER_SECONDS" ]; then
          delay=$SBOM_MAX_RETRY_AFTER_SECONDS
        fi
        ;;
    esac
  fi

  if [ "$delay" -gt 0 ]; then
    log "upload retry $sbr_next/$sbr_max in ${delay}s"
    sleep "$delay"
  fi
}

upload_file() {
  payload_file=$1
  attempt=0
  max_attempts=$((SBOM_UPLOAD_RETRIES + 1))

  while [ "$attempt" -lt "$max_attempts" ]; do
    attempt=$((attempt + 1))
    if upload_once "$payload_file"; then
      return 0
    fi

    case "${LAST_UPLOAD_HTTP_CODE:-}" in
      4??)
        [ "$LAST_UPLOAD_HTTP_CODE" = "429" ] || return 1
        ;;
    esac

    [ "$attempt" -lt "$max_attempts" ] || break
    sleep_before_retry "$((attempt + 1))" "$max_attempts"
  done

  return 1
}

retry_queue() {
  if is_true "$SBOM_DRY_RUN"; then
    return 0
  fi

  [ -d "$SBOM_QUEUE_DIR" ] || return 0
  [ "$SBOM_QUEUE_RETRY_LIMIT" -gt 0 ] || return 0

  rt_backlog=$(queue_file_count)
  [ "$rt_backlog" -gt 0 ] || return 0
  rt_to_retry=$rt_backlog
  if [ "$rt_to_retry" -gt "$SBOM_QUEUE_RETRY_LIMIT" ]; then
    rt_to_retry=$SBOM_QUEUE_RETRY_LIMIT
  fi
  log "retrying $rt_to_retry of $rt_backlog queued payload(s)"

  retried=0
  while IFS= read -r queued_file; do
    [ -n "$queued_file" ] || continue
    [ "$retried" -lt "$SBOM_QUEUE_RETRY_LIMIT" ] || break
    if [ "$SERVER_BACKPRESSURE" = true ]; then
      break
    fi

    retried=$((retried + 1))
    log "retrying queued payload $retried/$rt_to_retry: $(basename "$queued_file")"
    if upload_file "$queued_file"; then
      rm -f "$queued_file"
      log "uploaded queued payload: $(basename "$queued_file")"
    else
      warn "queued payload still failed: $(basename "$queued_file")"
    fi
  done < <(find "$SBOM_QUEUE_DIR" -type f \( -name '*.json' -o -name '*.json.gz' \) -print 2>/dev/null | sort)
}

status_begin() {
  STATUS_SPIN_IDX=0
  STATUS_NEXT_HEARTBEAT=60
}

status_tick() {
  st_label=$1
  st_start=$2
  [ "$LOG_LEVEL" -ge 1 ] || return 0
  st_elapsed=$(( $(date +%s) - st_start ))

  if [ "$STDERR_IS_TTY" = true ]; then
    # The last frame is a literal backslash, not an escaped quote.
    # shellcheck disable=SC1003
    case $((STATUS_SPIN_IDX % 4)) in
      0) st_spin='|' ;;
      1) st_spin='/' ;;
      2) st_spin='-' ;;
      *) st_spin='\' ;;
    esac
    STATUS_SPIN_IDX=$((STATUS_SPIN_IDX + 1))
    st_line="$(ts)$st_spin $st_label (elapsed $(fmt_elapsed "$st_elapsed"))"
    st_pad=$STATUS_LAST_LEN
    if [ "${#st_line}" -gt "$st_pad" ]; then
      st_pad=${#st_line}
    fi
    printf '\r%-*s' "$st_pad" "$st_line" >&2
    STATUS_LAST_LEN=$st_pad
    STATUS_ACTIVE=true
  elif [ "$st_elapsed" -ge "$STATUS_NEXT_HEARTBEAT" ]; then
    emit "still running: $st_label (elapsed $(fmt_elapsed "$st_elapsed"))"
    STATUS_NEXT_HEARTBEAT=$((STATUS_NEXT_HEARTBEAT + 60))
  fi
}

status_end() {
  clear_status_line
}

run_syft_with_timeout() {
  rswt_out=$1
  rswt_err=$2
  rswt_label=$3
  shift 3

  "$@" > "$rswt_out" 2>"$rswt_err" &
  ACTIVE_CHILD_PID=$!
  rswt_start=$(date +%s)
  status_begin

  while kill -0 "$ACTIVE_CHILD_PID" 2>/dev/null; do
    rswt_elapsed=$(( $(date +%s) - rswt_start ))
    if [ "$SBOM_MAX_RUN_SECONDS" -gt 0 ] && [ "$rswt_elapsed" -ge "$SBOM_MAX_RUN_SECONDS" ]; then
      status_end
      kill "$ACTIVE_CHILD_PID" 2>/dev/null || true
      sleep 2
      kill -9 "$ACTIVE_CHILD_PID" 2>/dev/null || true
      wait "$ACTIVE_CHILD_PID" 2>/dev/null || true
      ACTIVE_CHILD_PID=""
      printf 'scan exceeded SBOM_MAX_RUN_SECONDS=%s\n' "$SBOM_MAX_RUN_SECONDS" >> "$rswt_err"
      return 124
    fi
    status_tick "$rswt_label" "$rswt_start"
    sleep 2
  done

  status_end
  wait "$ACTIVE_CHILD_PID"
  rswt_rc=$?
  ACTIVE_CHILD_PID=""
  return "$rswt_rc"
}

write_failed_payload() {
  output_file=$1
  root=$2
  error_message=$3

  jq -n \
    --arg scan_id "$SCAN_ID" \
    --arg collector_version "$COLLECTOR_VERSION" \
    --arg payload_schema_version "$PAYLOAD_SCHEMA_VERSION" \
    --arg scan_policy_version "$SBOM_SCAN_POLICY_VERSION" \
    --arg scanned_at "$SCANNED_AT" \
    --arg started_at "$RUN_STARTED_AT" \
    --arg endpoint_id "$ENDPOINT_ID" \
    --arg hostname "$ENDPOINT_HOSTNAME" \
    --arg username "$ENDPOINT_USERNAME" \
    --arg os "$ENDPOINT_OS" \
    --arg kernel "$ENDPOINT_KERNEL" \
    --arg arch "$ENDPOINT_ARCH" \
    --arg syft_version "$SYFT_VERSION" \
    --arg syft_schema_version "$SYFT_SCHEMA_VERSION" \
    --arg source_root "$root" \
    --arg source_name "${SBOM_SOURCE_NAME:-}" \
    --arg error_message "$error_message" \
    --argjson syft_parallelism "${EFFECTIVE_PARALLELISM:-$SBOM_SYFT_PARALLELISM}" \
    '{
      scan_id: $scan_id,
      payload_schema_version: $payload_schema_version,
      collector_version: $collector_version,
      scan_policy_version: $scan_policy_version,
      scanned_at: $scanned_at,
      collector: {
        started_at: $started_at,
        resource_limits: {
          syft_parallelism: $syft_parallelism
        }
      },
      endpoint: {
        id: $endpoint_id,
        hostname: $hostname,
        username: $username,
        os: $os,
        kernel: $kernel,
        arch: $arch
      },
      scanner: {
        name: "syft",
        version: $syft_version,
        schema_version: $syft_schema_version
      },
      source: {
        name: $source_name,
        root: $source_root,
        type: "directory",
        status: "failed",
        error: $error_message
      },
      package_count: 0,
      dependency_edge_count: 0,
      packages: [],
      dependency_edges: []
    }' > "$output_file"
}

normalize_syft_json() {
  input_file=$1
  output_file=$2
  root=$3

  jq \
    --arg scan_id "$SCAN_ID" \
    --arg collector_version "$COLLECTOR_VERSION" \
    --arg payload_schema_version "$PAYLOAD_SCHEMA_VERSION" \
    --arg scan_policy_version "$SBOM_SCAN_POLICY_VERSION" \
    --arg scanned_at "$SCANNED_AT" \
    --arg started_at "$RUN_STARTED_AT" \
    --arg endpoint_id "$ENDPOINT_ID" \
    --arg hostname "$ENDPOINT_HOSTNAME" \
    --arg username "$ENDPOINT_USERNAME" \
    --arg os "$ENDPOINT_OS" \
    --arg kernel "$ENDPOINT_KERNEL" \
    --arg arch "$ENDPOINT_ARCH" \
    --arg syft_version "$SYFT_VERSION" \
    --arg syft_schema_version "$SYFT_SCHEMA_VERSION" \
    --arg source_root "$root" \
    --arg source_name "${SBOM_SOURCE_NAME:-}" \
    --argjson syft_parallelism "${EFFECTIVE_PARALLELISM:-$SBOM_SYFT_PARALLELISM}" \
    '
    def package_key($a):
      if (($a.purl // "") != "") then
        $a.purl
      else
        (($a.type // "unknown") + ":" + ($a.name // "unknown") + ":" + ($a.version // ""))
      end;

    def full_path($root; $path):
      if (($path // "") == "") then
        ""
      elif $root == "/" then
        $path
      elif ($path | startswith("/")) then
        (($root | rtrimstr("/")) + $path)
      else
        (($root | rtrimstr("/")) + "/" + $path)
      end;

    def license_value:
      if type == "string" then
        .
      elif type == "object" then
        (.value // .spdxExpression // .name // .id // empty)
      else
        empty
      end;

    def scope_for($a; $kind):
      if (($a.metadata.dev // false) == true) then
        "dev"
      elif (($a.metadata.optional // false) == true) then
        "optional"
      elif (($a.metadata.peer // false) == true) then
        "peer"
      elif (($a.type // "") == "github-action") then
        "runtime"
      elif (($a.metadataType // "") == "python-pip-requirements-entry") then
        "runtime"
      elif $kind == "root" then
        "runtime"
      else
        "unknown"
      end;

    def primary_kind($kinds):
      if ($kinds | index("root")) then
        "root"
      elif ($kinds | index("direct")) then
        "direct"
      elif ($kinds | index("transitive")) then
        "transitive"
      elif ($kinds | length) == 1 then
        $kinds[0]
      else
        "unknown"
      end;

    (.artifacts // []) as $artifacts |
    ($artifacts
      | map({key: .id, value: package_key(.)})
      | from_entries) as $id_to_key |
    ($artifacts
      | map(select(
          (.metadataType // "") == "javascript-npm-package-lock-entry"
          and ((.metadata.resolved // "") == "")
          and (.metadata.dependencies != null)
        ) | (.metadata.dependencies | keys))
      | add // []
      | unique) as $npm_root_dependency_names |
    ($artifacts
      | map(. as $a |
        (package_key($a)) as $key |
        (if (($a.metadataType // "") == "javascript-npm-package-lock-entry"
             and (($a.metadata.resolved // "") == "")) then
           "root"
         elif (($a.type // "") == "github-action") then
           "direct"
         elif (($a.metadataType // "") == "python-pip-requirements-entry") then
           "direct"
         elif (($a.metadataType // "") == "go-module-entry") then
           "direct"
         elif ((($a.metadataType // "") == "javascript-npm-package-lock-entry")
               and (($npm_root_dependency_names | index($a.name // "")) != null)) then
           "direct"
         elif ((($a.metadataType // "") == "javascript-npm-package-lock-entry")
               and (($npm_root_dependency_names | length) > 0)
               and (($a.metadata.resolved // "") != "")) then
           "transitive"
         else
           "unknown"
         end) as $dependency_kind |
        ([$a.locations[]? | full_path($source_root; (.path // ""))] | map(select(. != "")) | unique) as $locations |
        {
          key: $key,
          artifact_id: ($a.id // ""),
          name: ($a.name // ""),
          version: ($a.version // ""),
          type: ($a.type // ""),
          language: ($a.language // ""),
          purl: ($a.purl // ""),
          licenses: ([$a.licenses[]? | license_value] | unique),
          found_by: ($a.foundBy // ""),
          metadata_type: ($a.metadataType // ""),
          dependency_kind: $dependency_kind,
          dependency_scope: scope_for($a; $dependency_kind),
          dependency_evidence:
            (if $dependency_kind == "root" then
               "manifest-declared"
             elif $dependency_kind == "direct" then
               "manifest-declared"
             elif $dependency_kind == "transitive" then
               "lockfile-graph"
             else
               "cataloger-only"
             end),
          dependency_kind_note: "best-effort",
          locations: $locations,
          occurrence: {
            artifact_id: ($a.id // ""),
            source_root: $source_root,
            manifest_path: ($locations[0] // ""),
            locations: $locations,
            dependency_kind: $dependency_kind,
            dependency_scope: scope_for($a; $dependency_kind),
            dependency_evidence:
              (if $dependency_kind == "transitive" then "lockfile-graph"
               elif $dependency_kind == "unknown" then "cataloger-only"
               else "manifest-declared" end),
            found_by: ($a.foundBy // ""),
            metadata_type: ($a.metadataType // "")
          }
        })
      | sort_by(.key)
      | group_by(.key)
      | map(
        . as $items |
        $items[0] as $first |
        ($items | map(.dependency_kind) | unique) as $dependency_kinds |
        {
          key: $first.key,
          name: $first.name,
          version: $first.version,
          type: $first.type,
          language: $first.language,
          purl: $first.purl,
          licenses: ($items | map(.licenses[]) | unique),
          found_by: ($items | map(.found_by) | unique),
          metadata_types: ($items | map(.metadata_type) | unique),
          dependency_kind: primary_kind($dependency_kinds),
          dependency_kind_note: "best-effort",
          dependency_kinds: $dependency_kinds,
          dependency_scope:
            (($items | map(.dependency_scope) | unique) as $scopes |
             if ($scopes | index("runtime")) then "runtime"
             elif ($scopes | index("dev")) then "dev"
             elif ($scopes | index("optional")) then "optional"
             elif ($scopes | index("peer")) then "peer"
             elif ($scopes | length) == 1 then $scopes[0]
             else "unknown"
             end),
          dependency_scopes: ($items | map(.dependency_scope) | unique),
          dependency_evidence: ($items | map(.dependency_evidence) | unique),
          locations: ($items | map(.locations[]) | unique),
          occurrences: ($items | map(.occurrence)),
          occurrence_count: ($items | length)
        }
      )) as $packages |
    ((.artifactRelationships // [])
      | map(select(.type == "dependency-of" or .type == "depends-on")
        | {
          from_key: ($id_to_key[.parent] // .parent // ""),
          to_key: ($id_to_key[.child] // .child // ""),
          relationship_type: (.type // ""),
          source_root: $source_root
        })
      | map(select(.from_key != "" and .to_key != "" and .from_key != .to_key))
      | unique) as $dependency_edges |
    {
      scan_id: $scan_id,
      payload_schema_version: $payload_schema_version,
      collector_version: $collector_version,
      scan_policy_version: $scan_policy_version,
      scanned_at: $scanned_at,
      collector: {
        started_at: $started_at,
        resource_limits: {
          syft_parallelism: $syft_parallelism
        }
      },
      endpoint: {
        id: $endpoint_id,
        hostname: $hostname,
        username: $username,
        os: $os,
        kernel: $kernel,
        arch: $arch
      },
      scanner: {
        name: "syft",
        version: (.descriptor.version // $syft_version),
        schema_version: (.schema.version // $syft_schema_version)
      },
      source: {
        name: $source_name,
        root: $source_root,
        type: (.source.type // "directory"),
        status: "success",
        syft_source_id: (.source.id // "")
      },
      package_count: ($packages | length),
      dependency_edge_count: ($dependency_edges | length),
      packages: $packages,
      dependency_edges: $dependency_edges
    }' "$input_file" > "$output_file"
}

write_batches() {
  local normalized_file=$1
  local batch_dir=$2
  local source_hash=$3
  local batch_json batch_id output_path byte_count

  mkdir -p "$batch_dir"

  jq -c --argjson batch_size "$SBOM_BATCH_SIZE" --arg source_hash "$source_hash" '
    def contains_key($keys; $key): ($keys | index($key)) != null;

    . as $doc |
    ($doc.packages // []) as $packages |
    ($packages | length) as $package_count |
    (if $package_count == 0 then 1 else (($package_count + $batch_size - 1) / $batch_size | floor) end) as $batch_count |
    [
      range(0; $batch_count) as $idx |
      ($packages[($idx * $batch_size):(($idx + 1) * $batch_size)]) as $batch_packages |
      ($batch_packages | map(.key) | unique) as $batch_keys |
      $doc
      | .batch_id = (.scan_id + "-" + $source_hash + "-" + (($idx + 1) | tostring))
      | .batch_index = ($idx + 1)
      | .batch_count = $batch_count
      | .batch_package_count = ($batch_packages | length)
      | .packages = $batch_packages
      | .dependency_edges = ((.dependency_edges // [])
          | map(select(contains_key($batch_keys; .from_key))))
    ][]' "$normalized_file" |
    while IFS= read -r batch_json; do
      batch_id=$(printf '%s\n' "$batch_json" | jq -r '.batch_id')
      output_path="$batch_dir/$batch_id.json"
      printf '%s\n' "$batch_json" > "$output_path"
      byte_count=$(wc -c < "$output_path" | awk '{print $1}')
      jq --argjson byte_count "$byte_count" '.batch_byte_count = $byte_count' "$output_path" > "$output_path.tmp"
      mv "$output_path.tmp" "$output_path"
      if [ "$byte_count" -gt "$SBOM_MAX_BATCH_BYTES" ]; then
        warn "batch exceeds SBOM_MAX_BATCH_BYTES ($byte_count > $SBOM_MAX_BATCH_BYTES): $output_path"
      fi
    done
}

process_batch_file() {
  local batch_file=$1
  local pbf_label=${2:-?}
  TOTAL_BATCHES=$((TOTAL_BATCHES + 1))

  if is_true "$SBOM_DRY_RUN"; then
    vlog "processing batch $pbf_label (dry-run): $(basename "$batch_file")"
    jq . "$batch_file"
    return 0
  fi

  if [ "$STOP_UPLOADS" = true ]; then
    log "queueing batch $pbf_label (server backpressure): $(basename "$batch_file")"
    queue_payload "$batch_file" || UPLOAD_FAILURES=$((UPLOAD_FAILURES + 1))
    return 0
  fi

  log "uploading batch $pbf_label: $(basename "$batch_file")"
  vlog "batch bytes: $(wc -c < "$batch_file" | awk '{print $1}')"
  if upload_file "$batch_file"; then
    BATCHES_UPLOADED=$((BATCHES_UPLOADED + 1))
    log "uploaded batch $pbf_label: $(basename "$batch_file")"
  else
    UPLOAD_FAILURES=$((UPLOAD_FAILURES + 1))
    warn "upload failed (batch $pbf_label): $(basename "$batch_file")"
    queue_payload "$batch_file" || true
    if [ "$SERVER_BACKPRESSURE" = true ]; then
      STOP_UPLOADS=true
      warn "server backpressure active; remaining current-run batches will be queued"
    fi
  fi
}

normalize_grype_json() {
  local input_file=$1
  local output_file=$2
  local root=$3

  # Keep vuln records minimal: package name/version/purl + vulnerability id,
  # severity, and fix. Endpoint SBOMs are huge; vulns ride a separate, tiny batch.
  jq \
    --arg scan_id "$SCAN_ID" \
    --arg collector_version "$COLLECTOR_VERSION" \
    --arg payload_schema_version "$PAYLOAD_SCHEMA_VERSION" \
    --arg scan_policy_version "$SBOM_SCAN_POLICY_VERSION" \
    --arg scanned_at "$SCANNED_AT" \
    --arg endpoint_id "$ENDPOINT_ID" \
    --arg hostname "$ENDPOINT_HOSTNAME" \
    --arg username "$ENDPOINT_USERNAME" \
    --arg os "$ENDPOINT_OS" \
    --arg kernel "$ENDPOINT_KERNEL" \
    --arg arch "$ENDPOINT_ARCH" \
    --arg grype_version "$GRYPE_VERSION" \
    --arg source_root "$root" \
    --arg source_name "${SBOM_SOURCE_NAME:-}" \
    '
    [ (.matches // [])[] | {
        name: (.artifact.name // ""),
        version: (.artifact.version // ""),
        purl: (.artifact.purl // ""),
        id: (.vulnerability.id // ""),
        severity: (.vulnerability.severity // "Unknown"),
        fix: (((.vulnerability.fix // {}).versions // []) | join(","))
      } ]
    | unique_by(.id + "|" + .purl + "|" + .name + "|" + .version) as $vulns
    | {
        scan_id: $scan_id,
        payload_schema_version: $payload_schema_version,
        payload_type: "vulnerabilities",
        collector_version: $collector_version,
        scan_policy_version: $scan_policy_version,
        scanned_at: $scanned_at,
        endpoint: { id: $endpoint_id, hostname: $hostname, username: $username, os: $os, kernel: $kernel, arch: $arch },
        scanner: { name: "grype", version: $grype_version },
        source: { name: $source_name, root: $source_root, type: "directory", status: "success" },
        vulnerability_count: ($vulns | length),
        vulnerabilities: $vulns
      }
    ' "$input_file" > "$output_file"
}

write_vuln_batches() {
  local normalized_file=$1
  local batch_dir=$2
  local source_hash=$3
  local batch_json batch_id output_path byte_count

  mkdir -p "$batch_dir"

  jq -c --argjson batch_size "$SBOM_VULN_BATCH_SIZE" --arg source_hash "$source_hash" '
    . as $doc |
    ($doc.vulnerabilities // []) as $vulns |
    ($vulns | length) as $count |
    (if $count == 0 then 1 else (($count + $batch_size - 1) / $batch_size | floor) end) as $batch_count |
    [
      range(0; $batch_count) as $idx |
      ($vulns[($idx * $batch_size):(($idx + 1) * $batch_size)]) as $batch_vulns |
      $doc
      | .batch_id = (.scan_id + "-vuln-" + $source_hash + "-" + (($idx + 1) | tostring))
      | .batch_index = ($idx + 1)
      | .batch_count = $batch_count
      | .batch_vulnerability_count = ($batch_vulns | length)
      | .vulnerabilities = $batch_vulns
    ][]' "$normalized_file" |
    while IFS= read -r batch_json; do
      batch_id=$(printf '%s\n' "$batch_json" | jq -r '.batch_id')
      output_path="$batch_dir/$batch_id.json"
      printf '%s\n' "$batch_json" > "$output_path"
      byte_count=$(wc -c < "$output_path" | awk '{print $1}')
      jq --argjson byte_count "$byte_count" '.batch_byte_count = $byte_count' "$output_path" > "$output_path.tmp"
      mv "$output_path.tmp" "$output_path"
      if [ "$byte_count" -gt "$SBOM_MAX_BATCH_BYTES" ]; then
        warn "vuln batch exceeds SBOM_MAX_BATCH_BYTES ($byte_count > $SBOM_MAX_BATCH_BYTES): $output_path"
      fi
    done
}

# --- Change gate: skip full scans when nothing dependency-relevant changed ---

gate_active() {
  # The gate never applies to local-output mode: --output promises a complete
  # inventory in one file, so it always scans fully and touches no gate state.
  is_true "$SBOM_CHANGE_GATE" && [ -z "$SBOM_OUTPUT_FILE" ]
}

gate_root_state_dir() {
  printf '%s/roots/%s\n' "$SBOM_STATE_DIR" "$1"
}

gate_write_value() {
  gwv_file=$1
  gwv_value=$2
  if is_true "$SBOM_DRY_RUN"; then
    return 0
  fi
  gwv_dir=$(dirname "$gwv_file")
  mkdir -p "$gwv_dir"
  gwv_tmp=$(mktemp "$gwv_dir/.tmp.XXXXXX")
  printf '%s\n' "$gwv_value" > "$gwv_tmp"
  mv "$gwv_tmp" "$gwv_file"
}

gate_read_line() {
  GATE_READ_VALUE=""
  if [ -f "$1" ]; then
    IFS= read -r GATE_READ_VALUE < "$1" || true
  fi
}

gate_add_prune() {
  if [ "${#GATE_FIND_PRUNES[@]}" -gt 0 ]; then
    GATE_FIND_PRUNES+=(-o)
  fi
  GATE_FIND_PRUNES+=(-path "$1")
}

# Convert syft exclude patterns into find -path prunes. Only directory-subtree
# excludes (ending in /**) convert; file-level patterns are skipped, so the
# sweep watches MORE than syft scans — over-detection costs an extra scan,
# never lost coverage.
gate_exclude_to_prune() {
  gep=$1
  case "$gep" in
    *'/**') ;;
    *) return 0 ;;
  esac
  gep_dir=${gep%'/**'}
  case "$gep_dir" in
    ./*)
      gep_rel=${gep_dir#./}
      if [ "$GATE_ROOT" = "/" ]; then
        gate_add_prune "/$gep_rel"
      else
        gate_add_prune "$GATE_ROOT/$gep_rel"
      fi
      ;;
    '**/'*)
      gate_add_prune "*/${gep_dir#\*\*/}"
      ;;
    \*/*)
      gate_add_prune "*/${gep_dir#\*/}"
      ;;
  esac
}

gate_mount_prune_cb() {
  case "$1" in
    "/"|"") return 0 ;;
    /*) gate_add_prune "$1" ;;
  esac
}

gate_add_self_prune() {
  gsp=$1
  if [ -z "$gsp" ]; then
    return 0
  fi
  gsp=${gsp%/}
  case "$gsp" in
    /*) ;;
    *) return 0 ;;
  esac
  if [ "$GATE_ROOT" = "/" ]; then
    gate_add_prune "$gsp"
    return 0
  fi
  case "$gsp" in
    "$GATE_ROOT"|"$GATE_ROOT"/*) gate_add_prune "$gsp" ;;
  esac
}

gate_add_name_test() {
  if [ "${#GATE_NAME_TESTS[@]}" -gt 0 ]; then
    GATE_NAME_TESTS+=(-o)
  fi
  GATE_NAME_TESTS+=(-name "$1")
}

gate_add_dir_test() {
  if [ "${#GATE_DIR_TESTS[@]}" -gt 0 ]; then
    GATE_DIR_TESTS+=(-o)
  fi
  GATE_DIR_TESTS+=(-name "$1")
}

gate_build_name_tests() {
  GATE_NAME_TESTS=()
  GATE_DIR_TESTS=()
  with_colon_values "$SBOM_GATE_MANIFEST_NAMES" gate_add_name_test
  with_colon_values "${SBOM_GATE_DEP_DIR_NAMES:-}" gate_add_dir_test
}

# BSD/macOS + GNU find compatible: only -path/-prune/-name/-type/-newer/-print/-o.
# Short-circuit comes from `head -n 1` (no GNU -quit needed).
gate_build_sweep_cmd() {
  gbs_root=$1
  gbs_marker=$2
  GATE_ROOT=$gbs_root
  GATE_FIND_PRUNES=()
  with_colon_values "$(effective_excludes_for_root "$gbs_root")" gate_exclude_to_prune
  with_skipped_mounts "$gbs_root" gate_mount_prune_cb
  # Collector state churns every run; without these self-prunes a / scan root
  # would never report unchanged.
  gate_add_self_prune "$SBOM_STATE_DIR"
  gate_add_self_prune "$SBOM_QUEUE_DIR"
  gate_add_self_prune "$SBOM_RAW_DIR"
  gate_add_self_prune "${TMPDIR:-/tmp}"

  GATE_SWEEP_CMD=(find "$gbs_root")
  if [ "${#GATE_FIND_PRUNES[@]}" -gt 0 ]; then
    GATE_SWEEP_CMD+=( \( "${GATE_FIND_PRUNES[@]}" \) -prune -o )
  fi
  if [ "${#GATE_DIR_TESTS[@]}" -gt 0 ]; then
    GATE_SWEEP_CMD+=( \( "${GATE_DIR_TESTS[@]}" \) -type d -newer "$gbs_marker" -print -o )
  fi
  GATE_SWEEP_CMD+=( \( "${GATE_NAME_TESTS[@]}" \) -type f -newer "$gbs_marker" -print )
}

run_sweep() {
  rs_hit=$1
  rs_label=$2

  ( { "${GATE_SWEEP_CMD[@]}" 2>/dev/null || true; } | head -n 1 > "$rs_hit" ) &
  ACTIVE_CHILD_PID=$!
  rs_start=$(date +%s)
  status_begin

  while kill -0 "$ACTIVE_CHILD_PID" 2>/dev/null; do
    rs_elapsed=$(( $(date +%s) - rs_start ))
    if [ "$SBOM_MAX_RUN_SECONDS" -gt 0 ] && [ "$rs_elapsed" -ge "$SBOM_MAX_RUN_SECONDS" ]; then
      status_end
      kill "$ACTIVE_CHILD_PID" 2>/dev/null || true
      sleep 1
      kill -9 "$ACTIVE_CHILD_PID" 2>/dev/null || true
      wait "$ACTIVE_CHILD_PID" 2>/dev/null || true
      ACTIVE_CHILD_PID=""
      return 124
    fi
    status_tick "$rs_label" "$rs_start"
    sleep 1
  done

  status_end
  wait "$ACTIVE_CHILD_PID" 2>/dev/null || true
  ACTIVE_CHILD_PID=""
  return 0
}

# OS package databases get cheap direct checks before the big sweep. Homebrew
# upgrades touch Cellar/<formula>/, not Cellar/ itself, hence -maxdepth 2.
gate_check_one_os_path() {
  gcp=$1
  if [ "$GATE_OS_CHANGED" = true ]; then
    return 0
  fi
  if [ ! -e "$gcp" ]; then
    return 0
  fi
  if [ "$GATE_OS_ROOT" != "/" ]; then
    case "$gcp" in
      "$GATE_OS_ROOT"|"$GATE_OS_ROOT"/*) ;;
      *) return 0 ;;
    esac
  fi

  if [ -d "$gcp" ]; then
    gcp_hit=$(find "$gcp" -maxdepth 2 -newer "$GATE_OS_MARKER" -print 2>/dev/null | head -n 1 || true)
    if [ -n "$gcp_hit" ]; then
      GATE_CHANGE_HINT=$gcp_hit
      GATE_OS_CHANGED=true
    fi
  elif [ "$gcp" -nt "$GATE_OS_MARKER" ]; then
    GATE_CHANGE_HINT=$gcp
    GATE_OS_CHANGED=true
  fi
}

gate_os_paths_changed() {
  GATE_OS_ROOT=$1
  GATE_OS_MARKER=$2
  GATE_OS_CHANGED=false
  GATE_CHANGE_HINT=""

  gop_paths="/var/lib/dpkg/status:/var/lib/rpm:/lib/apk/db/installed:/opt/homebrew/Cellar:/opt/homebrew/Caskroom:/usr/local/Cellar:/usr/local/Caskroom:/Library/Apple/System/Library/Receipts:/var/db/receipts:/private/var/db/receipts"
  if [ -n "${SBOM_GATE_EXTRA_PATHS:-}" ]; then
    gop_paths="$gop_paths:$SBOM_GATE_EXTRA_PATHS"
  fi

  with_colon_values "$gop_paths" gate_check_one_os_path
  [ "$GATE_OS_CHANGED" = true ]
}

# Decide what to do for one root. Sets GATE_RESULT to one of:
#   disabled | full-forced | full-changed | unchanged
# The pending marker is created BEFORE the sweep so anything modified during
# the sweep or the scan itself is newer than it and re-detected next run.
gate_decide_root() {
  gd_root=$1
  gd_hash=$2
  GATE_RESULT=""
  GATE_REASON=""
  GATE_PENDING_MARKER=""

  if ! gate_active; then
    GATE_RESULT="disabled"
    return 0
  fi

  gd_state_dir=$(gate_root_state_dir "$gd_hash")
  if ! is_true "$SBOM_DRY_RUN"; then
    mkdir -p "$gd_state_dir"
    rm -f "$gd_state_dir"/.marker.* 2>/dev/null || true
    GATE_PENDING_MARKER=$(mktemp "$gd_state_dir/.marker.XXXXXX")
    if [ ! -f "$gd_state_dir/root-path" ]; then
      gate_write_value "$gd_state_dir/root-path" "$gd_root"
    fi
  fi

  if is_true "$CLI_FORCE_FULL"; then
    GATE_RESULT="full-forced"
    GATE_REASON="cli-full"
    return 0
  fi

  gd_marker="$gd_state_dir/marker"
  gate_read_line "$gd_state_dir/last-full-epoch"
  gd_last_full=$GATE_READ_VALUE
  case "$gd_last_full" in
    ''|*[!0-9]*) gd_last_full="" ;;
  esac
  if [ ! -f "$gd_marker" ] || [ -z "$gd_last_full" ]; then
    GATE_RESULT="full-forced"
    GATE_REASON="first-run"
    return 0
  fi

  gd_now=$(date +%s)
  if [ $((gd_now - gd_last_full)) -ge $((SBOM_FULL_SCAN_INTERVAL_HOURS * 3600)) ]; then
    GATE_RESULT="full-forced"
    GATE_REASON="interval-elapsed"
    log "forced full scan for $gd_root (last full scan older than ${SBOM_FULL_SCAN_INTERVAL_HOURS}h)"
    return 0
  fi

  gd_sweep_start=$(date +%s)
  if gate_os_paths_changed "$gd_root" "$gd_marker"; then
    GATE_SWEEP_SECONDS=$((GATE_SWEEP_SECONDS + $(date +%s) - gd_sweep_start))
    GATE_RESULT="full-changed"
    GATE_REASON="os-db"
    log "changes detected under $GATE_CHANGE_HINT (will scan $gd_root)"
    return 0
  fi

  gate_build_sweep_cmd "$gd_root" "$gd_marker"
  gd_hit_file="$TMP_DIR/sweep-hit-$gd_hash.txt"
  vlog "sweep command: ${GATE_SWEEP_CMD[*]}"
  if run_sweep "$gd_hit_file" "change sweep: $gd_root"; then
    gd_sweep_rc=0
  else
    gd_sweep_rc=$?
  fi
  GATE_SWEEP_SECONDS=$((GATE_SWEEP_SECONDS + $(date +%s) - gd_sweep_start))

  if [ "$gd_sweep_rc" -eq 124 ]; then
    GATE_RESULT="full-changed"
    GATE_REASON="sweep-timeout"
    warn "change sweep timed out for $gd_root; treating as changed"
    return 0
  fi

  gate_read_line "$gd_hit_file"
  gd_hit=$GATE_READ_VALUE
  if [ -n "$gd_hit" ]; then
    GATE_RESULT="full-changed"
    GATE_REASON="changed"
    log "changes detected under $gd_hit (will scan $gd_root)"
  else
    GATE_RESULT="unchanged"
    GATE_REASON="no-changes"
    log "change sweep: $gd_root (no changes, $(fmt_elapsed $(( $(date +%s) - gd_sweep_start ))))"
  fi
  return 0
}

gate_promote_marker() {
  if is_true "$SBOM_DRY_RUN"; then
    return 0
  fi
  if [ -n "${GATE_PENDING_MARKER:-}" ] && [ -f "$GATE_PENDING_MARKER" ]; then
    mv "$GATE_PENDING_MARKER" "$(gate_root_state_dir "$1")/marker"
    GATE_PENDING_MARKER=""
  fi
}

gate_discard_marker() {
  if [ -n "${GATE_PENDING_MARKER:-}" ]; then
    rm -f "$GATE_PENDING_MARKER"
    GATE_PENDING_MARKER=""
  fi
}

gate_store_pkg_state() {
  gate_write_value "$(gate_root_state_dir "$1")/pkg-state" "$2 $(date +%s)"
}

gate_store_last_full() {
  gsl_dir=$(gate_root_state_dir "$1")
  gate_write_value "$gsl_dir/last-full-epoch" "$(date +%s)"
  gate_write_value "$gsl_dir/last-full-id" "$SCAN_ID"
  gate_write_value "$gsl_dir/last-full-at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

gate_record_result() {
  GATE_RESULTS="${GATE_RESULTS}${2}${GATE_TAB}${1}${GATE_TAB}${3:-}
"
}

# Track the oldest last-full timestamp across roots (ISO strings sort lexically).
note_last_full_at() {
  if [ -z "$1" ]; then
    return 0
  fi
  if [ -z "$LAST_FULL_SCAN_AT" ] || [[ "$1" < "$LAST_FULL_SCAN_AT" ]]; then
    LAST_FULL_SCAN_AT=$1
  fi
}

gate_collect_heartbeat_root() {
  ghr_root=$1
  ghr_dir=$(gate_root_state_dir "$2")
  gate_read_line "$ghr_dir/last-full-id"
  ghr_id=$GATE_READ_VALUE
  gate_read_line "$ghr_dir/last-full-at"
  ghr_at=$GATE_READ_VALUE
  note_last_full_at "$ghr_at"
  HEARTBEAT_ROOTS="${HEARTBEAT_ROOTS}${ghr_root}${GATE_TAB}${ghr_id}${GATE_TAB}${ghr_at}
"
}

write_heartbeat_payload() {
  whp_file=$1

  jq -n \
    --arg scan_id "$SCAN_ID" \
    --arg payload_schema_version "$PAYLOAD_SCHEMA_VERSION" \
    --arg collector_version "$COLLECTOR_VERSION" \
    --arg scan_policy_version "$SBOM_SCAN_POLICY_VERSION" \
    --arg scanned_at "$SCANNED_AT" \
    --arg started_at "$RUN_STARTED_AT" \
    --arg endpoint_id "$ENDPOINT_ID" \
    --arg hostname "$ENDPOINT_HOSTNAME" \
    --arg username "$ENDPOINT_USERNAME" \
    --arg os "$ENDPOINT_OS" \
    --arg kernel "$ENDPOINT_KERNEL" \
    --arg arch "$ENDPOINT_ARCH" \
    --arg roots "$HEARTBEAT_ROOTS" \
    --argjson syft_parallelism "${EFFECTIVE_PARALLELISM:-$SBOM_SYFT_PARALLELISM}" \
    '
    ($roots | split("\n") | map(select(length > 0) | split("\t")
      | {root: .[0], status: "unchanged", last_full_scan_id: (.[1] // ""), last_full_finished_at: (.[2] // "")})) as $root_list |
    ($root_list | map(select(.last_full_finished_at != "")) | sort_by(.last_full_finished_at) | first // {}) as $oldest |
    {
      scan_id: $scan_id,
      payload_schema_version: $payload_schema_version,
      payload_type: "heartbeat",
      collector_version: $collector_version,
      scan_policy_version: $scan_policy_version,
      scanned_at: $scanned_at,
      collector: {
        started_at: $started_at,
        resource_limits: { syft_parallelism: $syft_parallelism }
      },
      endpoint: { id: $endpoint_id, hostname: $hostname, username: $username, os: $os, kernel: $kernel, arch: $arch },
      status: "unchanged",
      last_full_scan: {
        scan_id: ($oldest.last_full_scan_id // ""),
        finished_at: ($oldest.last_full_finished_at // "")
      },
      roots: $root_list
    }' > "$whp_file"
}

# Heartbeats are liveness-only and best-effort: never queued (a stale heartbeat
# is misleading and the next run supersedes it) and a failed heartbeat does not
# flip RUN_STATUS — the server inventory is still correct and covered by the
# forced-full interval.
maybe_send_heartbeat() {
  if ! gate_active; then
    return 0
  fi
  if [ "$ROOTS_TOTAL" -eq 0 ] || [ "$ROOTS_UNCHANGED" -ne "$ROOTS_TOTAL" ]; then
    return 0
  fi
  if ! is_true "$SBOM_HEARTBEAT_ON_UNCHANGED"; then
    HEARTBEAT_STATUS="disabled"
    return 0
  fi

  hb_file="$TMP_DIR/heartbeat.json"
  write_heartbeat_payload "$hb_file"

  if is_true "$SBOM_DRY_RUN"; then
    jq . "$hb_file"
    HEARTBEAT_STATUS="printed"
    log "heartbeat: printed (dry-run)"
    return 0
  fi

  if [ "$STOP_UPLOADS" = true ] || [ "$SERVER_BACKPRESSURE" = true ]; then
    HEARTBEAT_STATUS="skipped-backpressure"
    log "heartbeat: skipped (server backpressure)"
    return 0
  fi

  if upload_file "$hb_file"; then
    HEARTBEAT_STATUS="sent"
    log "heartbeat: sent (all roots unchanged)"
  else
    HEARTBEAT_STATUS="failed"
    warn "heartbeat upload failed (next run supersedes it; not queued)"
  fi
}

# --- Local CLI output (--output): accumulate across roots, write one JSON ---
local_accumulate() {
  acc=$1
  src=$2
  key=$3
  [ -s "$src" ] || return 0
  jq -s --arg k "$key" '.[0] + (.[1][$k] // [])' "$acc" "$src" > "$acc.tmp" && mv "$acc.tmp" "$acc"
}

# --malware: query OSV /v1/querybatch (by purl) for the scanned packages and keep
# MAL-* (malicious-package) hits. Echoes a JSON array; degrades to [] on any error.
osv_malware_check() {
  local purls total i=0 chunk body resp hits out="[]"
  purls=$(jq -c '[.[] | (.purl // "") | select(. != "")] | unique' "$LOCAL_PKGS_FILE" 2>/dev/null || printf '[]')
  total=$(printf '%s' "$purls" | jq 'length' 2>/dev/null || printf 0)
  if [ "${total:-0}" -eq 0 ]; then printf '[]'; return 0; fi
  log "malware check: querying OSV for $total package(s)…"
  while [ "$i" -lt "$total" ]; do
    chunk=$(printf '%s' "$purls" | jq -c ".[$i:$((i + 500))]")
    body=$(printf '%s' "$chunk" | jq -c '{queries: [.[] | {package: {purl: .}}]}')
    resp=$(printf '%s' "$body" | curl -s --max-time "$SBOM_TIMEOUT_SECONDS" \
      -X POST "https://api.osv.dev/v1/querybatch" -H 'Content-Type: application/json' --data @- 2>/dev/null || printf '')
    if [ -n "$resp" ]; then
      hits=$(jq -n --argjson purls "$chunk" --argjson resp "$resp" '
        ($resp.results // []) as $r
        | [ range(0; ($purls | length)) as $j
            | {purl: $purls[$j],
               advisory_ids: (($r[$j].vulns // []) | map(.id) | map(select(startswith("MAL-"))))}
            | select(.advisory_ids | length > 0) ]' 2>/dev/null || printf '[]')
      out=$(jq -n --argjson a "$out" --argjson b "$hits" '$a + $b' 2>/dev/null || printf '%s' "$out")
    fi
    i=$((i + 500))
  done
  jq -n --argjson hits "$out" --slurpfile pkgs "$LOCAL_PKGS_FILE" '
    ($pkgs[0]) as $p
    | $hits | map(. as $h | ($p | map(select(.purl == $h.purl)) | .[0]) as $pkg
        | {advisory_id: $h.advisory_ids[0], advisory_ids: $h.advisory_ids,
           package: ($pkg.name // ""), version: ($pkg.version // ""), purl: $h.purl})' 2>/dev/null || printf '[]'
}

write_local_output() {
  malware_json="[]"
  if is_true "$CLI_MALWARE"; then
    malware_json=$(osv_malware_check)
  fi
  consolidated=$(jq -n \
    --slurpfile pkgs "$LOCAL_PKGS_FILE" \
    --slurpfile vulns "$LOCAL_VULNS_FILE" \
    --argjson malware "$malware_json" \
    --arg endpoint_id "$ENDPOINT_ID" \
    --arg hostname "$ENDPOINT_HOSTNAME" \
    --arg username "$ENDPOINT_USERNAME" \
    --arg os "$ENDPOINT_OS" \
    --arg kernel "$ENDPOINT_KERNEL" \
    --arg arch "$ENDPOINT_ARCH" \
    --arg scan_id "$SCAN_ID" \
    --arg scanned_at "$SCANNED_AT" \
    --arg syft_version "${SYFT_VERSION:-}" \
    --arg grype_version "${GRYPE_VERSION:-}" \
    '{
      scan_id: $scan_id,
      scanned_at: $scanned_at,
      endpoint: {id: $endpoint_id, hostname: $hostname, username: $username,
                 os: $os, kernel: $kernel, arch: $arch},
      scanner: {syft: $syft_version, grype: $grype_version},
      packages: ($pkgs[0] // []),
      vulnerabilities: ($vulns[0] // []),
      malware: $malware
    }')
  if is_true "$CLI_REPORT"; then
    consolidated=$(printf '%s' "$consolidated" | jq '{
      target: .endpoint.hostname,
      asset_type: "endpoint",
      summary: {components: (.packages | length), vulnerabilities: (.vulnerabilities | length),
                malware: (.malware | length)},
      components: [.packages[] | {name: .name, version: .version, ecosystem: (.type // ""), purl: .purl}],
      vulnerabilities: [.vulnerabilities[] | {id: .id, severity: .severity,
                                              package: .name, version: .version, fix: .fix}],
      malware: [.malware[] | {advisory_id: .advisory_id, package: .package, version: .version}]
    }')
  fi
  printf '%s\n' "$consolidated" > "$SBOM_OUTPUT_FILE"
  if is_true "$CLI_REPORT"; then
    log "wrote report JSON to $SBOM_OUTPUT_FILE"
  else
    log "wrote inventory JSON to $SBOM_OUTPUT_FILE"
  fi
}

scan_vulnerabilities() {
  local syft_file=$1
  local root=$2
  local source_hash=$3
  local grype_raw grype_norm grype_batch_dir grype_err
  local vuln_count sv_scan_start sv_batch_total sv_batch_idx vuln_batch_file
  local -a grype_cmd

  is_true "$SBOM_ENABLE_VULN_SCAN" || return 0
  command -v "$SBOM_GRYPE_BIN" >/dev/null 2>&1 || return 0
  [ -s "$syft_file" ] || return 0

  grype_raw="$TMP_DIR/grype-$source_hash.json"
  grype_norm="$TMP_DIR/vuln-normalized-$source_hash.json"
  grype_batch_dir="$TMP_DIR/vuln-batches-$source_hash"
  grype_err="$TMP_DIR/grype-error-$source_hash.txt"

  grype_cmd=()
  if is_true "$SBOM_ENABLE_IONICE" && [ "$ENDPOINT_OS" = "Linux" ] && command -v ionice >/dev/null 2>&1; then
    grype_cmd+=(ionice -c 3)
  fi
  if is_true "$SBOM_ENABLE_TASKPOLICY" && [ "$ENDPOINT_OS" = "Darwin" ] && command -v taskpolicy >/dev/null 2>&1; then
    grype_cmd+=(taskpolicy -b)
  fi
  if [ "${SBOM_NICE:-0}" != "0" ] && command -v nice >/dev/null 2>&1; then
    grype_cmd+=(nice -n "$SBOM_NICE")
  fi
  grype_cmd+=(env GRYPE_CHECK_FOR_APP_UPDATE=false)
  if ! is_true "$SBOM_GRYPE_DB_AUTO_UPDATE"; then
    grype_cmd+=(env GRYPE_DB_AUTO_UPDATE=false)
  fi
  # grype reads the syft SBOM we already produced — no second filesystem walk.
  grype_cmd+=("$SBOM_GRYPE_BIN" "sbom:$syft_file" -o json -q)

  log "vuln-scanning: $root"
  vlog "grype command: ${grype_cmd[*]}"
  sv_scan_start=$(date +%s)
  if run_syft_with_timeout "$grype_raw" "$grype_err" "grype scan: $root" "${grype_cmd[@]}"; then
    normalize_grype_json "$grype_raw" "$grype_norm" "$root"
    vuln_count=$(jq -r '.vulnerability_count // 0' "$grype_norm")
    TOTAL_VULNERABILITIES=$((TOTAL_VULNERABILITIES + vuln_count))
    log "vuln scan complete: $root ($vuln_count vulnerabilities, elapsed $(fmt_elapsed $(( $(date +%s) - sv_scan_start ))))"
    if [ -n "$SBOM_OUTPUT_FILE" ]; then
      local_accumulate "$LOCAL_VULNS_FILE" "$grype_norm" vulnerabilities
    else
      write_vuln_batches "$grype_norm" "$grype_batch_dir" "$source_hash"
      sv_batch_total=0
      for vuln_batch_file in "$grype_batch_dir"/*.json; do
        [ -e "$vuln_batch_file" ] || continue
        sv_batch_total=$((sv_batch_total + 1))
      done
      sv_batch_idx=0
      for vuln_batch_file in "$grype_batch_dir"/*.json; do
        [ -e "$vuln_batch_file" ] || continue
        sv_batch_idx=$((sv_batch_idx + 1))
        process_batch_file "$vuln_batch_file" "vuln $sv_batch_idx/$sv_batch_total"
      done
    fi
  else
    SR_GRYPE_OK=false
    RUN_STATUS="partial-failure"
    warn "grype scan failed for $root: $(tr '\n' ' ' < "$grype_err")"
  fi
}

scan_root() {
  root=$1
  sr_gate_mode=${2:-disabled}
  source_hash=$(make_hash "$root")
  safe_root=$source_hash
  raw_file="$TMP_DIR/raw-$safe_root.json"
  normalized_file="$TMP_DIR/normalized-$safe_root.json"
  batch_dir="$TMP_DIR/batches-$safe_root"
  error_file="$TMP_DIR/error-$safe_root.txt"
  sr_uploads_before=$UPLOAD_FAILURES
  sr_drops_before=$BATCHES_DROPPED
  sr_syft_ok=false
  sr_digest=""
  SR_GRYPE_OK=true
  SR_FINAL_RESULT=$sr_gate_mode

  log "scanning: $root"

  EFFECTIVE_EXCLUDE_PATHS=$(effective_excludes_for_root "$root")
  vlog "effective excludes for $root: ${EFFECTIVE_EXCLUDE_PATHS:-none}"

  syft_args=(-q "dir:$root" -o syft-json --parallelism "${EFFECTIVE_PARALLELISM:-$SBOM_SYFT_PARALLELISM}" --base-path "$root")
  if [ -n "${SBOM_SOURCE_NAME:-}" ]; then
    syft_args+=(--source-name "$SBOM_SOURCE_NAME")
  fi
  if is_true "$SBOM_DISABLE_FILE_CATALOGERS"; then
    syft_args+=(--select-catalogers=-file)
  fi
  append_syft_excludes
  append_dynamic_mount_excludes "$root"

  syft_cmd=()
  if is_true "$SBOM_ENABLE_IONICE" && [ "$ENDPOINT_OS" = "Linux" ] && command -v ionice >/dev/null 2>&1; then
    syft_cmd+=(ionice -c 3)
  fi
  if is_true "$SBOM_ENABLE_TASKPOLICY" && [ "$ENDPOINT_OS" = "Darwin" ] && command -v taskpolicy >/dev/null 2>&1; then
    syft_cmd+=(taskpolicy -b)
  fi
  if [ "${SBOM_NICE:-0}" != "0" ] && command -v nice >/dev/null 2>&1; then
    syft_cmd+=(nice -n "$SBOM_NICE")
  fi
  syft_cmd+=(env SYFT_CHECK_FOR_APP_UPDATE=false syft "${syft_args[@]}")

  vlog "syft command: ${syft_cmd[*]}"
  sr_scan_start=$(date +%s)
  if run_syft_with_timeout "$raw_file" "$error_file" "syft scan: $root" "${syft_cmd[@]}"; then
    sr_syft_ok=true
    if is_true "$SBOM_KEEP_RAW"; then
      mkdir -p "$SBOM_RAW_DIR"
      cp "$raw_file" "$SBOM_RAW_DIR/$SCAN_ID-$safe_root.syft.json"
    fi
    normalize_syft_json "$raw_file" "$normalized_file" "$root"
    log "scan complete: $root ($(jq -r '.package_count // 0' "$normalized_file") packages, elapsed $(fmt_elapsed $(( $(date +%s) - sr_scan_start ))))"

    if gate_active; then
      # Scan + normalize succeeded: the pending marker is a safe new baseline
      # even if grype or uploads fail (queued batches deliver later).
      gate_promote_marker "$source_hash"
      sr_digest=$(compute_package_digest "$normalized_file")
      gate_read_line "$(gate_root_state_dir "$source_hash")/pkg-state"
      sr_stored_digest=${GATE_READ_VALUE%% *}
      # Identical package set: a manifest mtime changed but the inventory did
      # not. Skip grype and the re-upload; the heartbeat covers freshness.
      # Forced-full runs never take this shortcut.
      if [ "$sr_gate_mode" = "full-changed" ] && [ -n "$sr_stored_digest" ] && [ "$sr_stored_digest" = "$sr_digest" ]; then
        log "inventory unchanged for $root (digest match); skipping grype and upload"
        GRYPE_SKIPPED=$((GRYPE_SKIPPED + 1))
        package_count=$(jq -r '.package_count // 0' "$normalized_file")
        TOTAL_PACKAGES=$((TOTAL_PACKAGES + package_count))
        SR_FINAL_RESULT="unchanged-content"
        return 0
      fi
    fi

    # Pass the syft SBOM to grype and upload the vulnerabilities separately.
    scan_vulnerabilities "$raw_file" "$root" "$source_hash"
  else
    gate_discard_marker
    SCAN_FAILURES=$((SCAN_FAILURES + 1))
    RUN_STATUS="partial-failure"
    error_message=$(tr '\n' ' ' < "$error_file")
    warn "syft scan failed for $root: $error_message"
    write_failed_payload "$normalized_file" "$root" "$error_message"
  fi

  package_count=$(jq -r '.package_count // 0' "$normalized_file")
  TOTAL_PACKAGES=$((TOTAL_PACKAGES + package_count))

  if [ -n "$SBOM_OUTPUT_FILE" ]; then
    local_accumulate "$LOCAL_PKGS_FILE" "$normalized_file" packages
    return 0
  fi

  write_batches "$normalized_file" "$batch_dir" "$source_hash"

  sr_batch_total=0
  for batch_file in "$batch_dir"/*.json; do
    [ -e "$batch_file" ] || continue
    sr_batch_total=$((sr_batch_total + 1))
  done
  sr_batch_idx=0
  for batch_file in "$batch_dir"/*.json; do
    [ -e "$batch_file" ] || continue
    sr_batch_idx=$((sr_batch_idx + 1))
    process_batch_file "$batch_file" "$sr_batch_idx/$sr_batch_total"
  done

  # Commit gate state only when the entire per-root pipeline succeeded:
  # syft + grype + every batch uploaded or queued without drops. A failed run
  # stores nothing, so the next change or forced full retries everything.
  if gate_active && ! is_true "$SBOM_DRY_RUN" \
    && [ "$sr_syft_ok" = true ] && [ "$SR_GRYPE_OK" = true ] \
    && [ "$UPLOAD_FAILURES" -eq "$sr_uploads_before" ] \
    && [ "$BATCHES_DROPPED" -eq "$sr_drops_before" ]; then
    gate_store_pkg_state "$source_hash" "$sr_digest"
    gate_store_last_full "$source_hash"
    note_last_full_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi
}

is_on_battery() {
  case "$ENDPOINT_OS" in
    Darwin)
      command -v pmset >/dev/null 2>&1 || return 1
      pmset -g batt 2>/dev/null | grep -q "Battery Power"
      ;;
    Linux)
      for online_file in /sys/class/power_supply/*/online; do
        [ -e "$online_file" ] || continue
        value=$(cat "$online_file" 2>/dev/null || true)
        [ "$value" = "1" ] && return 1
      done
      [ -d /sys/class/power_supply ] && return 0
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

current_load_1m() {
  if [ -r /proc/loadavg ]; then
    awk '{print $1}' /proc/loadavg
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n vm.loadavg 2>/dev/null | awk '{gsub(/[{}]/, ""); print $1}'
  else
    printf '\n'
  fi
}

cpu_core_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc 2>/dev/null || printf '2\n'
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu 2>/dev/null || printf '2\n'
  else
    printf '2\n'
  fi
}

# Raise syft parallelism toward half the cores only when the machine looks
# idle and is on AC power; otherwise stay at the conservative configured value.
compute_effective_parallelism() {
  EFFECTIVE_PARALLELISM=$SBOM_SYFT_PARALLELISM

  if ! is_true "$SBOM_ADAPTIVE_PARALLELISM"; then
    return 0
  fi

  if is_on_battery; then
    log "parallelism: on battery, keeping $EFFECTIVE_PARALLELISM"
    return 0
  fi

  cep_cores=$(cpu_core_count)
  case "$cep_cores" in
    ''|*[!0-9]*) cep_cores=2 ;;
  esac
  cep_half=$((cep_cores / 2))
  if [ "$cep_half" -lt 1 ]; then
    cep_half=1
  fi

  cep_load=$(current_load_1m)
  if [ -n "$cep_load" ] && awk "BEGIN {exit !($cep_load >= $cep_half)}"; then
    log "parallelism: 1m load $cep_load >= $cep_half, keeping $EFFECTIVE_PARALLELISM"
    return 0
  fi

  cep_target=$cep_half
  if [ "$cep_target" -lt "$SBOM_SYFT_PARALLELISM" ]; then
    cep_target=$SBOM_SYFT_PARALLELISM
  fi
  if [ "$cep_target" -gt "$SBOM_MAX_PARALLELISM" ]; then
    cep_target=$SBOM_MAX_PARALLELISM
  fi
  EFFECTIVE_PARALLELISM=$cep_target

  if [ "$EFFECTIVE_PARALLELISM" -ne "$SBOM_SYFT_PARALLELISM" ]; then
    log "parallelism: adaptive raised to $EFFECTIVE_PARALLELISM (cores=$cep_cores, load=${cep_load:-unavailable})"
  fi
}

preflight_resource_checks() {
  if is_true "$SBOM_SKIP_ON_BATTERY" && is_on_battery; then
    SKIP_REASON="on-battery"
    log "skipping scan: endpoint is on battery"
    return 1
  fi

  if [ -n "$SBOM_MAX_LOAD_1M" ]; then
    load_1m=$(current_load_1m)
    if [ -n "$load_1m" ] && awk "BEGIN {exit !($load_1m > $SBOM_MAX_LOAD_1M)}"; then
      SKIP_REASON="high-load"
      log "skipping scan: 1m load $load_1m exceeds $SBOM_MAX_LOAD_1M"
      return 1
    fi
  fi

  mkdir -p "$SBOM_STATE_DIR"
  free_mb=$(df -Pm "$SBOM_STATE_DIR" 2>/dev/null | awk 'NR==2 {print $4}')
  if [ -n "$free_mb" ] && [ "$free_mb" -lt "$SBOM_MIN_FREE_MB" ]; then
    SKIP_REASON="low-disk"
    log "skipping scan: free disk ${free_mb}MB is below ${SBOM_MIN_FREE_MB}MB"
    return 1
  fi

  log "preflight checks passed (free disk: ${free_mb:-unknown}MB)"
  return 0
}

apply_start_jitter() {
  if [ "$SBOM_START_JITTER_SECONDS" -gt 0 ] && ! is_true "$SBOM_DRY_RUN"; then
    jitter=$((RANDOM % (SBOM_START_JITTER_SECONDS + 1)))
    log "startup jitter: sleeping $(fmt_elapsed "$jitter")"
    jitter_start=$(date +%s)
    status_begin
    while [ $(( $(date +%s) - jitter_start )) -lt "$jitter" ]; do
      status_tick "startup jitter ($(fmt_elapsed "$jitter") total)" "$jitter_start"
      sleep 2 || true
    done
    status_end
  fi
}

write_run_status() {
  mkdir -p "$SBOM_STATE_DIR"
  finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  queue_files=$(queue_file_count)
  queue_bytes=$(queue_byte_count)
  gate_enabled_json=false
  if gate_active; then
    gate_enabled_json=true
  fi

  jq -n \
    --arg scan_id "${SCAN_ID:-}" \
    --arg status "$RUN_STATUS" \
    --arg skip_reason "$SKIP_REASON" \
    --arg started_at "${RUN_STARTED_AT:-}" \
    --arg finished_at "$finished_at" \
    --arg endpoint_id "${ENDPOINT_ID:-}" \
    --arg collector_version "$COLLECTOR_VERSION" \
    --arg payload_schema_version "$PAYLOAD_SCHEMA_VERSION" \
    --arg scan_policy_version "$SBOM_SCAN_POLICY_VERSION" \
    --argjson total_packages "$TOTAL_PACKAGES" \
    --argjson total_vulnerabilities "$TOTAL_VULNERABILITIES" \
    --argjson total_batches "$TOTAL_BATCHES" \
    --argjson batches_uploaded "$BATCHES_UPLOADED" \
    --argjson batches_queued "$BATCHES_QUEUED" \
    --argjson batches_dropped "$BATCHES_DROPPED" \
    --argjson upload_failures "$UPLOAD_FAILURES" \
    --argjson scan_failures "$SCAN_FAILURES" \
    --argjson queue_files "$queue_files" \
    --argjson queue_bytes "$queue_bytes" \
    --argjson gate_enabled "$gate_enabled_json" \
    --arg gate_results "$GATE_RESULTS" \
    --argjson gate_sweep_seconds "$GATE_SWEEP_SECONDS" \
    --argjson roots_scanned "$ROOTS_SCANNED" \
    --argjson roots_unchanged "$ROOTS_UNCHANGED" \
    --argjson grype_skipped "$GRYPE_SKIPPED" \
    --arg last_full_scan_at "$LAST_FULL_SCAN_AT" \
    --arg heartbeat "$HEARTBEAT_STATUS" \
    --argjson effective_parallelism "${EFFECTIVE_PARALLELISM:-$SBOM_SYFT_PARALLELISM}" \
    '{
      scan_id: $scan_id,
      status: $status,
      skip_reason: $skip_reason,
      started_at: $started_at,
      finished_at: $finished_at,
      endpoint_id: $endpoint_id,
      collector_version: $collector_version,
      payload_schema_version: $payload_schema_version,
      scan_policy_version: $scan_policy_version,
      total_packages: $total_packages,
      total_vulnerabilities: $total_vulnerabilities,
      total_batches: $total_batches,
      batches_uploaded: $batches_uploaded,
      batches_queued: $batches_queued,
      batches_dropped: $batches_dropped,
      upload_failures: $upload_failures,
      scan_failures: $scan_failures,
      gate: {
        enabled: $gate_enabled,
        results: ($gate_results | split("\n") | map(select(length > 0) | split("\t") | {result: .[0], root: .[1], reason: (.[2] // "")})),
        sweep_seconds: $gate_sweep_seconds
      },
      roots_scanned: $roots_scanned,
      roots_unchanged: $roots_unchanged,
      grype_skipped: $grype_skipped,
      last_full_scan_at: $last_full_scan_at,
      heartbeat: $heartbeat,
      effective_parallelism: $effective_parallelism,
      queue: {
        files: $queue_files,
        bytes: $queue_bytes
      }
    }' > "$SBOM_STATE_DIR/last-run.json"
}

log_run_summary() {
  log "run summary:"
  log "  status:           $RUN_STATUS${SKIP_REASON:+ (skip reason: $SKIP_REASON)}"
  log "  duration:         $(fmt_elapsed $(( $(date +%s) - SCRIPT_START_EPOCH )))"
  log "  packages:         $TOTAL_PACKAGES"
  log "  vulnerabilities:  $TOTAL_VULNERABILITIES"
  log "  batches:          $TOTAL_BATCHES total, $BATCHES_UPLOADED uploaded, $BATCHES_QUEUED queued, $BATCHES_DROPPED dropped"
  log "  upload failures:  $UPLOAD_FAILURES   scan failures: $SCAN_FAILURES"
  if gate_active; then
    log "  gate:             enabled, $ROOTS_SCANNED scanned / $ROOTS_UNCHANGED unchanged, sweep $(fmt_elapsed "$GATE_SWEEP_SECONDS"), grype skipped: $GRYPE_SKIPPED"
  else
    log "  gate:             disabled"
  fi
  log "  parallelism:      ${EFFECTIVE_PARALLELISM:-$SBOM_SYFT_PARALLELISM} (configured $SBOM_SYFT_PARALLELISM)"
  log "  heartbeat:        $HEARTBEAT_STATUS"
  log "  queue backlog:    ${queue_files:-0} files, ${queue_bytes:-0} bytes"
}

# Owner-only by default for everything we create: state/queue dirs (0700), queued
# payloads and raw SBOMs (0600). These hold the machine's full software inventory,
# which must not be world/group-readable on shared hosts.
umask 077

parse_args "$@"
load_config
if is_true "$CLI_DRY_RUN"; then
  SBOM_DRY_RUN=true
fi
set_defaults
init_logging

require_command bash
require_command syft
require_command jq
require_command curl
require_command uname
require_command hostname
require_command date
require_command awk
require_command mktemp
require_command find
require_command du
require_command df

validate_config
log "collector v$COLLECTOR_VERSION starting (dry_run=$SBOM_DRY_RUN, roots=$SBOM_SCAN_ROOTS)"
vlog "state_dir=$SBOM_STATE_DIR queue_dir=$SBOM_QUEUE_DIR server=${SBOM_SERVER_URL:-none}"
vlog "exclude_paths=${SBOM_EXCLUDE_PATHS:-per-root defaults}"
mkdir -p "$SBOM_STATE_DIR" "$SBOM_QUEUE_DIR"
ensure_endpoint_id
acquire_lock

collector_cleanup() {
  clear_status_line
  if [ -n "${ACTIVE_CHILD_PID:-}" ]; then
    kill "$ACTIVE_CHILD_PID" 2>/dev/null || true
    kill -9 "$ACTIVE_CHILD_PID" 2>/dev/null || true
  fi
  release_lock
  rm -rf "$TMP_DIR"
}

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sbom-inventory.XXXXXX")
trap collector_cleanup EXIT INT TERM

# Local CLI output: accumulate packages + vulns across all roots into one file.
if [ -n "$SBOM_OUTPUT_FILE" ]; then
  LOCAL_PKGS_FILE="$TMP_DIR/local-packages.json"
  LOCAL_VULNS_FILE="$TMP_DIR/local-vulns.json"
  printf '[]' > "$LOCAL_PKGS_FILE"
  printf '[]' > "$LOCAL_VULNS_FILE"
fi

RUN_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
apply_start_jitter

ENDPOINT_HOSTNAME=$(hostname 2>/dev/null || uname -n)
ENDPOINT_USERNAME=${USER:-${LOGNAME:-unknown}}
if [ "$ENDPOINT_USERNAME" = "unknown" ] && command -v id >/dev/null 2>&1; then
  ENDPOINT_USERNAME=$(id -un 2>/dev/null || printf 'unknown')
fi
ENDPOINT_OS=$(uname -s)
ENDPOINT_KERNEL=$(uname -r)
ENDPOINT_ARCH=$(uname -m)

if ! preflight_resource_checks; then
  RUN_STATUS="skipped"
  SCAN_ID=$(make_id)
  SCANNED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  write_run_status
  log_run_summary
  exit 0
fi

compute_effective_parallelism

SYFT_VERSION_OUTPUT=$(SYFT_CHECK_FOR_APP_UPDATE=false syft version 2>/dev/null || true)
SYFT_VERSION=$(printf '%s\n' "$SYFT_VERSION_OUTPUT" | awk -F: '/^Version:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')
SYFT_SCHEMA_VERSION=$(printf '%s\n' "$SYFT_VERSION_OUTPUT" | awk -F: '/^SchemaVersion:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')
SYFT_VERSION=${SYFT_VERSION:-unknown}
SYFT_SCHEMA_VERSION=${SYFT_SCHEMA_VERSION:-unknown}
vlog "syft version: $SYFT_VERSION (schema $SYFT_SCHEMA_VERSION)"

# Vulnerability scanning needs grype; degrade gracefully if it is unavailable.
if is_true "$SBOM_ENABLE_VULN_SCAN"; then
  if command -v "$SBOM_GRYPE_BIN" >/dev/null 2>&1; then
    GRYPE_VERSION=$("$SBOM_GRYPE_BIN" version -o json 2>/dev/null | jq -r '.version // "unknown"' 2>/dev/null || printf 'unknown')
    GRYPE_VERSION=${GRYPE_VERSION:-unknown}
    vlog "grype version: $GRYPE_VERSION"
  else
    warn "grype not found ($SBOM_GRYPE_BIN); vulnerability scanning disabled"
    SBOM_ENABLE_VULN_SCAN=false
  fi
fi

SCAN_ID=$(make_id)
SCANNED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# No upload queue to drain in local-output mode.
[ -n "$SBOM_OUTPUT_FILE" ] || retry_queue

scan_one_root() {
  configured_root=$1
  root=$(normalize_root "$configured_root" || true)
  if [ -z "$root" ]; then
    log "skipping empty scan root"
    return 0
  fi
  if [ ! -e "$root" ]; then
    log "skipping missing scan root: $root"
    return 0
  fi
  if [ ! -r "$root" ]; then
    log "skipping unreadable scan root: $root"
    return 0
  fi

  ROOTS_TOTAL=$((ROOTS_TOTAL + 1))
  sor_hash=$(make_hash "$root")
  gate_decide_root "$root" "$sor_hash"

  if [ "$GATE_RESULT" = "unchanged" ]; then
    ROOTS_UNCHANGED=$((ROOTS_UNCHANGED + 1))
    gate_promote_marker "$sor_hash"
    gate_collect_heartbeat_root "$root" "$sor_hash"
    gate_record_result "$root" "unchanged" "$GATE_REASON"
    return 0
  fi

  ROOTS_SCANNED=$((ROOTS_SCANNED + 1))
  sor_reason=$GATE_REASON
  scan_root "$root" "$GATE_RESULT"
  if [ "$SR_FINAL_RESULT" = "unchanged-content" ]; then
    ROOTS_SCANNED=$((ROOTS_SCANNED - 1))
    ROOTS_UNCHANGED=$((ROOTS_UNCHANGED + 1))
    gate_collect_heartbeat_root "$root" "$sor_hash"
    sor_reason="digest-match"
  fi
  gate_record_result "$root" "$SR_FINAL_RESULT" "$sor_reason"
}

if gate_active; then
  gate_build_name_tests
fi

with_colon_values "$SBOM_SCAN_ROOTS" scan_one_root

# Local CLI mode: write the single consolidated JSON and stop (no upload/status).
if [ -n "$SBOM_OUTPUT_FILE" ]; then
  write_local_output
  exit 0
fi

maybe_send_heartbeat

if [ "$UPLOAD_FAILURES" -gt 0 ] || [ "$BATCHES_DROPPED" -gt 0 ]; then
  RUN_STATUS="partial-failure"
fi

write_run_status
log_run_summary

if is_true "$SBOM_FAIL_ON_UPLOAD_ERROR" && [ "$UPLOAD_FAILURES" -gt 0 ]; then
  exit 2
fi

exit 0
