#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ENV_FILE=${SUPPLYDRIFT_ENV_FILE:-$ROOT_DIR/.env}
PROJECT_NAME=${SUPPLYDRIFT_LOCAL_PROJECT:-supplydrift-local}
PLATFORM_URL=${SUPPLYDRIFT_URL:-http://127.0.0.1:8765}

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

dotenv_value() {
  local key=$1 line value
  line=$(grep -m1 "^${key}=" "$ENV_FILE" 2>/dev/null || true)
  value=${line#*=}
  value=${value%$'\r'}
  case "$value" in
    \"*\") value=${value#\"}; value=${value%\"} ;;
    \'*\') value=${value#\'}; value=${value%\'} ;;
  esac
  printf '%s' "$value"
}

require_env() {
  [ -f "$ENV_FILE" ] || die "missing .env; copy .env.example to .env and configure it"
}

require_private_env() {
  local mode
  require_env
  mode=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || true)
  [ "$mode" = "600" ] || die ".env contains secrets and must have mode 600"
}

compose() {
  docker compose -p "$PROJECT_NAME" --env-file "$ENV_FILE" "$@"
}

doctor() {
  local failures=0 key value mode

  say "SupplyDrift local environment check"
  say "  project:  $PROJECT_NAME"
  say "  platform: $PLATFORM_URL"

  for key in docker curl; do
    if command -v "$key" >/dev/null 2>&1; then
      say "  [ok] $key"
    else
      say "  [missing] $key"
      failures=1
    fi
  done

  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      say "  [ok] docker compose"
    else
      say "  [missing] docker compose plugin"
      failures=1
    fi
    if docker info >/dev/null 2>&1; then
      say "  [ok] Docker engine"
    else
      say "  [unavailable] Docker engine"
      failures=1
    fi
  fi

  if [ ! -f "$ENV_FILE" ]; then
    say "  [missing] .env (copy .env.example and configure it)"
    failures=1
  else
    mode=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || true)
    if [ "$mode" = "600" ]; then
      say "  [ok] .env permissions (600)"
    else
      say "  [fix] .env permissions are ${mode:-unknown}; run: chmod 600 .env"
      failures=1
    fi

    for key in SUPPLYDRIFT_ADMIN_USER SUPPLYDRIFT_ADMIN_PASSWORD \
      SUPPLYDRIFT_SECRET_KEY MYSQL_PASSWORD MYSQL_ROOT_PASSWORD; do
      value=$(dotenv_value "$key")
      case "$value" in
        "")
          say "  [fix] set $key in .env"
          failures=1
          ;;
        change-me-please|change-me-supplydrift|change-me-root)
          say "  [warning] $key still uses the local example value"
          ;;
        *) say "  [ok] $key is configured" ;;
      esac
    done

    if [ -n "$(dotenv_value ENDPOINT_SCANNER_TOKEN)" ]; then
      say "  [ok] endpoint ingest token is configured"
    else
      say "  [optional] endpoint ingest token is not configured"
    fi
  fi

  for key in syft grype jq gzip; do
    if command -v "$key" >/dev/null 2>&1; then
      say "  [ok] $key (endpoint scanning)"
    else
      say "  [optional] $key is needed only for endpoint scanning"
    fi
  done

  if [ -f "$HOME/.kube/config" ]; then
    say "  [ok] kubeconfig found (Kubernetes scanning enabled on start)"
  else
    say "  [optional] no kubeconfig at $HOME/.kube/config"
  fi

  [ "$failures" -eq 0 ] || die "local environment check failed"
}

up_stack() {
  require_env
  doctor

  if [ -z "${KUBECONFIG_HOST:-}" ] && [ -f "$HOME/.kube/config" ]; then
    export KUBECONFIG_HOST
    KUBECONFIG_HOST=$(realpath "$HOME/.kube/config")
  fi

  say "Building and starting SupplyDrift..."
  compose up -d --build

  say "Waiting for the platform health endpoint..."
  local ready=false
  for _ in $(seq 1 60); do
    if curl -fsS "$PLATFORM_URL/api/health" >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 2
  done
  [ "$ready" = true ] || die "platform did not become healthy; run: $0 logs platform"

  compose ps
  say "SupplyDrift is ready at $PLATFORM_URL"
}

status_stack() {
  require_env
  compose ps
  if curl -fsS "$PLATFORM_URL/api/health" >/dev/null 2>&1; then
    say "Platform health: ok"
  else
    say "Platform health: unavailable"
    return 1
  fi
}

logs_stack() {
  require_env
  if [ "$#" -gt 0 ]; then
    compose logs -f --tail=100 "$@"
  else
    compose logs -f --tail=100
  fi
}

down_stack() {
  require_env
  compose down
  say "Containers stopped. Database volumes were preserved."
}

endpoint_scan() (
  set -euo pipefail
  require_private_env
  need curl
  need syft
  need grype
  need jq
  need gzip
  need realpath

  local scan_root=/home force_full=true root_set=false arg
  for arg in "$@"; do
    case "$arg" in
      --full) force_full=true ;;
      --incremental) force_full=false ;;
      -*) die "unknown endpoint option: $arg" ;;
      *)
        [ "$root_set" = false ] || die "provide only one endpoint scan path"
        scan_root=$arg
        root_set=true
        ;;
    esac
  done

  [ -d "$scan_root" ] || die "endpoint scan path is not a directory: $scan_root"
  scan_root=$(realpath "$scan_root")
  curl -fsS "$PLATFORM_URL/api/health" >/dev/null \
    || die "platform is unavailable at $PLATFORM_URL"

  local token token_count token_file state_dir policy
  token_count=$(grep -c '^ENDPOINT_SCANNER_TOKEN=' "$ENV_FILE" || true)
  [ "$token_count" -eq 1 ] \
    || die "set exactly one ENDPOINT_SCANNER_TOKEN entry in .env (scope: ingest)"
  token=$(dotenv_value ENDPOINT_SCANNER_TOKEN)
  [ -n "$token" ] || die "ENDPOINT_SCANNER_TOKEN is empty in .env"

  token_file=$(mktemp "${TMPDIR:-/tmp}/supplydrift-endpoint-token.XXXXXX")
  trap 'rm -f -- "$token_file"' EXIT
  chmod 600 "$token_file"
  printf '%s\n' "$token" > "$token_file"
  unset token

  state_dir=${SUPPLYDRIFT_ENDPOINT_STATE_DIR:-$HOME/.local/state/supplydrift-endpoint}
  mkdir -p "$state_dir"
  chmod 700 "$state_dir"

  case "$scan_root" in
    /) policy=fullfs-v1 ;;
    /home) policy=homes-v1 ;;
    *) policy=workspace-v1 ;;
  esac

  local -a collector_args=(--verbose)
  if [ "$force_full" = true ]; then
    collector_args=(--full --verbose)
  fi

  say "Scanning endpoint path: $scan_root"
  say "State directory:       $state_dir"
  say "Mode:                  $([ "$force_full" = true ] && printf full || printf incremental)"

  env \
    SBOM_SERVER_URL="$PLATFORM_URL/api/sync/endpoints" \
    SBOM_ALLOW_INSECURE=true \
    SBOM_AUTH_TOKEN_FILE="$token_file" \
    SBOM_SCAN_ROOTS="$scan_root" \
    SBOM_STATE_DIR="$state_dir" \
    SBOM_SOURCE_NAME=local-endpoint \
    SBOM_SCAN_POLICY_VERSION="$policy" \
    SBOM_COMPRESS_UPLOAD=true \
    SBOM_ENABLE_VULN_SCAN=true \
    SBOM_GRYPE_DB_AUTO_UPDATE=true \
    SBOM_START_JITTER_SECONDS=0 \
    SBOM_SKIP_ON_BATTERY=false \
    SBOM_FAIL_ON_UPLOAD_ERROR=true \
    bash "$ROOT_DIR/endpoint-dep-inventory/collect-sbom-inventory.sh" "${collector_args[@]}"

  say "Endpoint scan result:"
  jq '{status,total_packages,total_vulnerabilities,total_batches,batches_uploaded,batches_queued,batches_dropped,upload_failures,scan_failures,grype_skipped}' \
    "$state_dir/last-run.json"
)

usage() {
  cat <<EOF
Usage: $(basename "$0") COMMAND [ARGS]

Commands:
  doctor                         Check local prerequisites and .env safely
  up                             Build and start platform plus all runners
  status                         Show Compose services and platform health
  logs [SERVICE ...]             Follow all logs or selected service logs
  endpoint [PATH] [--full]       Scan PATH (default /home) and upload results
  endpoint [PATH] --incremental  Use the endpoint change gate on a repeat run
  down                           Stop containers and preserve database volumes
  help                           Show this help

Defaults:
  Compose project: $PROJECT_NAME
  Platform URL:    $PLATFORM_URL
EOF
}

command=${1:-help}
shift || true
case "$command" in
  doctor) doctor "$@" ;;
  up) up_stack "$@" ;;
  status) status_stack "$@" ;;
  logs) logs_stack "$@" ;;
  endpoint) endpoint_scan "$@" ;;
  down) down_stack "$@" ;;
  help|-h|--help) usage ;;
  *) die "unknown command '$command'; run: $0 help" ;;
esac
