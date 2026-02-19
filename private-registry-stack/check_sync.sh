#!/bin/bash

# ==============================================================================
# Name: check_sync.sh
# Description: A bash script to check for and sync Docker images using
#              regsync across multiple configuration files. Rate-limit aware,
#              includes retry logic, detailed ntfy alerts, and rich payload
#              reporting to Healthchecks.io.
#
# buildplan.org
# 10-11-2025 - v4
# ==============================================================================

# ==============================================================================
# Configuration
# ==============================================================================
PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
SECRETS_DIR="${PROJECT_DIR}/secrets"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"
LOG_DIR="${PROJECT_DIR}/logs"
SCRIPT_LOG_FILE="${LOG_DIR}/check_sync.log"
STATE_FILE="${LOG_DIR}/.check_sync_state"

NTFY_URL=$(<"${SECRETS_DIR}/ntfy_url")
NTFY_TOPIC=$(<"${SECRETS_DIR}/ntfy_topic")
NTFY_TOKEN_FILE="${SECRETS_DIR}/ntfy_token"
HC_URL_FILE="${SECRETS_DIR}/cs_hc_url"
HC_URL=""
if [[ -f "${HC_URL_FILE}" ]]; then
    HC_URL=$(<"${HC_URL_FILE}")
fi

HOSTNAME=$(hostname -s)
HUB_USER_FILE="${SECRETS_DIR}/hub_user"
HUB_TOKEN_FILE="${SECRETS_DIR}/hub_token"
DOCKER_HUB_REGISTRY="registry-1.docker.io"
RATE_CHECK_IMAGE="ratelimitpreview/test"

MAX_RETRIES=3
RETRY_DELAY=600
MIN_INTERVAL_HOURS=6

CRITICAL_THRESHOLD=75
WARNING_THRESHOLD=175

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; GRAY='\033[0;90m'; NC='\033[0m'

# Global variable to track the script's status for Healthchecks payload
HC_MESSAGE="Script aborted unexpectedly."

# ==============================================================================
# Logging & Notification
# ==============================================================================
log()    { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${BLUE}[INFO]${NC} $*" >&2; }
warn()   { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${YELLOW}[WARN]${NC} $*" >&2; }
error()  { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}[ERROR]${NC} $*" >&2; }
success(){ echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${GREEN}[SUCCESS]${NC} $*" >&2; }

# Helper to cleanly exit and pass the reason to the Healthchecks trap
fatal() {
  HC_MESSAGE="$1"
  error "${HC_MESSAGE}"
  exit 1
}

send_ntfy() {
  local title="$1" message="$2" priority="$3" tags="$4"
  local auth_header=()
  [[ -f "${NTFY_TOKEN_FILE}" ]] && auth_header=(-H "Authorization: Bearer $(<"${NTFY_TOKEN_FILE}")")
  curl -sf --connect-timeout 5 --max-time 10 "${auth_header[@]}" \
    -H "Title: ${title}" -H "Priority: ${priority}" -H "Tags: ${tags}" \
    -d "${message}" "${NTFY_URL}/${NTFY_TOPIC}" &
}

ping_healthcheck() {
    [[ -z "${HC_URL}" ]] && return 0
    local endpoint="$1"
    local message="$2"

    # If a message is provided, POST it as raw data. Otherwise, standard ping.
    if [[ -n "$message" ]]; then
        curl -fsS -m 10 --retry 3 -X POST --data-raw "${message}" "${HC_URL}${endpoint}" > /dev/null 2>&1 || warn "Healthcheck POST failed: ${endpoint}"
    else
        curl -fsS -m 10 --retry 3 "${HC_URL}${endpoint}" > /dev/null 2>&1 || warn "Healthcheck GET failed: ${endpoint}"
    fi
}

cleanup_and_report() {
    local code=$?
    [[ -z "${HC_URL}" ]] && return

    # Send the explicit exit code alongside our captured status message
    local payload="Exit Code: ${code}\nStatus: ${HC_MESSAGE}"
    ping_healthcheck "/${code}" "${payload}"
}

# ==============================================================================
# Docker Hub Rate-Limit Helpers
# ==============================================================================
docker_hub_login() {
  if [[ -r "${HUB_USER_FILE}" && -r "${HUB_TOKEN_FILE}" ]]; then
    local user token
    user=$(<"${HUB_USER_FILE}") token=$(<"${HUB_TOKEN_FILE}")
    log "Attempting Docker Hub login as '${user}'..."
    if docker login -u "${user}" -p "${token}" &>/dev/null; then
      success "Docker Hub login successful."
      echo "${user}"
      return 0
    else
      warn "Docker Hub login failed; using anonymous."
      return 1
    fi
  else
    log "No Docker Hub credentials; using anonymous."
    return 1
  fi
}

get_auth_token() {
  if [[ -r "${HUB_USER_FILE}" && -r "${HUB_TOKEN_FILE}" ]]; then
    local user token
    user=$(<"${HUB_USER_FILE}") token=$(<"${HUB_TOKEN_FILE}")
    if [[ -n "$user" && -n "$token" ]]; then
      curl -s -u "${user}:${token}" \
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${RATE_CHECK_IMAGE}:pull" \
        | jq -r .token 2>/dev/null && return
    fi
  fi
  curl -s \
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${RATE_CHECK_IMAGE}:pull" \
    | jq -r .token 2>/dev/null
}

check_rate_limit() {
  log "Checking Docker Hub rate limits..."
  docker_hub_login &>/dev/null || true
  local token headers limit remaining
  token=$(get_auth_token) || { warn "Failed to fetch auth token"; return 1; }
  headers=$(curl -s -I -H "Authorization: Bearer ${token}" \
    "https://${DOCKER_HUB_REGISTRY}/v2/${RATE_CHECK_IMAGE}/manifests/latest")
  limit=$(grep -i '^ratelimit-limit:' <<<"$headers" | awk '{print $2}' | cut -d';' -f1)
  remaining=$(grep -i '^ratelimit-remaining:' <<<"$headers" | awk '{print $2}' | cut -d';' -f1)

  if [[ -z "$limit" || -z "$remaining" ]]; then
    warn "Unable to parse rate-limit headers. Raw headers below:"
    echo "$headers" >&2
    return 0
  fi

  # Log the exact status to Healthchecks.io Events tab without changing job status
  ping_healthcheck "/log" "Docker Hub Rate Limit: ${remaining}/${limit} pulls remaining on ${HOSTNAME}."

  log "Rate limit: ${remaining}/${limit} remaining"
  if (( remaining < CRITICAL_THRESHOLD )); then
    error "Critical threshold reached (${remaining} < ${CRITICAL_THRESHOLD})"
    return 2
  elif (( remaining < WARNING_THRESHOLD )); then
    warn "Warning threshold reached (${remaining} < ${WARNING_THRESHOLD})"
    return 1
  else
    success "Rate limit OK."
    return 0
  fi
}

run_manual_check() {
  docker_hub_login &>/dev/null || true
  local token headers limit remaining used usage user_info user
  user_info="Anonymous"
  if user=$(docker_hub_login); then
    user_info="Authenticated as ${user}"
  fi

  token=$(get_auth_token)
  if [[ -z "$token" ]]; then
    error "Could not fetch auth token from Docker Hub."
    exit 1
  fi

  headers=$(curl -s -I -H "Authorization: Bearer ${token}" \
    "https://${DOCKER_HUB_REGISTRY}/v2/${RATE_CHECK_IMAGE}/manifests/latest")
  limit=$(grep -i '^ratelimit-limit:' <<<"$headers" | awk '{print $2}' | cut -d';' -f1)
  remaining=$(grep -i '^ratelimit-remaining:' <<<"$headers" | awk '{print $2}' | cut -d';' -f1)

  if [[ -z "$limit" || -z "$remaining" ]]; then
    warn "Could not parse rate-limit headers. Raw headers below:"
    echo "$headers" >&2
    exit 1
  fi

  used=$((limit - remaining))
  usage=$((used * 100 / limit))

  echo "----------------------------------------"
  echo "Docker Hub Rate Limit Status (Current 6hr Window)"
  echo "----------------------------------------"
  echo -e "Account:      ${GREEN}${user_info}${NC}"
  echo -e "Window Limit: ${GREEN}${limit}${NC} manifest pulls per 6 hours"
  echo -e "Remaining:    ${GREEN}${remaining}${NC} (resets every 6 hours)"
  echo -e "Used:         ${YELLOW}${used}${NC} (${usage}% of current window)"
  echo -e "${GRAY}Note: Version checks (HEAD requests) do not count${NC}"
  echo "----------------------------------------"
  exit 0
}

# ==============================================================================
# Regsync Wrapper with Retry
# ==============================================================================
run_regsync_for_file() {
  local mode="$1"
  local config_file="$2"
  local config_basename
  config_basename=$(basename "$config_file")

  # Path inside the container
  local container_path="/config/${config_basename}"
  local cmd_out rc=0

  for attempt in $(seq 1 "${MAX_RETRIES}"); do
    log "Running regsync '${mode}' on ${config_basename} (attempt ${attempt})..."

    # Capture output and exit code
    cmd_out=$(docker compose -f "${COMPOSE_FILE}" run --rm -T regsync -c "${container_path}" "${mode}" 2>&1) || rc=$?

    if [[ $rc -eq 0 ]] || [[ "$mode" == "check" && $rc -eq 1 ]]; then
      success "Success: ${config_basename} (RC=${rc})"
      echo "$cmd_out" # Output result for main loop to capture
      return 0
    fi

    # Failure handling
    error "Failed: ${config_basename} (attempt ${attempt} - RC=${rc})"

    # Check for rate limits
    if grep -qiE 'too.*many.*requests|rate.*limit|429' <<<"$cmd_out"; then
      warn "Rate limit detected. Waiting ${RETRY_DELAY}s..."
      sleep "${RETRY_DELAY}"
    else
      # If it's a config error (not a rate limit), fail immediately
      error "Non-retryable error. Failing file."
      echo "$cmd_out"
      return 1
    fi
  done

  # If we exhausted retries
  echo "$cmd_out"
  return 1
}

# ==============================================================================
# Main Logic
# ==============================================================================
main() {
  mkdir -p "${LOG_DIR}"

  # Set up exit trap for Healthchecks.io reporting
  trap cleanup_and_report EXIT

  # Send start ping with diagnostic body
  ping_healthcheck "/start" "Regsync execution started on ${HOSTNAME}."

  # Config validation
  [[ -r "${COMPOSE_FILE}" ]] || fatal "Missing compose file: ${COMPOSE_FILE}"
  compgen -G "${PROJECT_DIR}/regsync*.yml" > /dev/null || fatal "No regsync*.yml files found"
  [[ -r "${NTFY_TOKEN_FILE}" ]] || warn "Missing ntfy token; notifications may fail"

  # Prerequisites
  for cmd in docker curl jq date; do
    command -v "$cmd" &>/dev/null || fatal "Required command not found: $cmd"
  done
  if ! docker compose version &>/dev/null; then
    fatal "Required command 'docker compose' not found. Please ensure Docker Compose v2 is installed."
  fi

  # Force & interval
  local force=0
  [[ "${1:-}" == "--force" ]] && force=1 && log "Force run enabled"
  if (( MIN_INTERVAL_HOURS > 0 && force == 0 )); then
    if [[ -f "${STATE_FILE}" ]]; then
      local last now delta
      last=$(<"${STATE_FILE}") now=$(date +%s)
      delta=$((now - last))
      if (( delta < MIN_INTERVAL_HOURS * 3600 )); then
        HC_MESSAGE="Skipped: Last run was $((delta/60)) minutes ago."
        log "$HC_MESSAGE"
        exit 0
      fi
    fi
  fi

  log "===== Starting Regsync on ${HOSTNAME} ====="

  # Pre-check rate limit and abort if critical
  local status=0
  check_rate_limit || status=$?
  if [[ $status -eq 2 ]]; then
    send_ntfy "[Regsync] ABORTED" "Critical rate-limit on ${HOSTNAME}" high stop_sign
    fatal "Critical rate-limit reached (${CRITICAL_THRESHOLD}). Aborting run."
  fi

  send_ntfy "[Regsync] START" "Beginning sync on ${HOSTNAME}" default hourglass

  local overall_success=true

  # Loop through all regsync*.yml files
  for config_path in "${PROJECT_DIR}"/regsync*.yml; do
    [[ -e "$config_path" ]] || continue

    local config_basename
    config_basename=$(basename "$config_path")
    log "Processing: ${config_basename}"

    # 1. Run Check and capture output
    local check_output
    if ! check_output=$(run_regsync_for_file "check" "$config_path"); then
        # Print the error output to log
        echo "$check_output"
        send_ntfy "[Regsync] CHECK FAILED" "Failed config: ${config_basename}" high x
        overall_success=false
        continue
    fi

    # Print success output to log
    echo "$check_output"

    # 2. Run Sync if needed
    if grep -q "Image sync needed" <<<"$check_output"; then
       local sync_output
       if sync_output=$(run_regsync_for_file "once" "$config_path"); then
          echo "$sync_output"
          local summary
          summary=$(grep 'sync needed' <<<"$check_output" | sed 's/.*: //' | tr '\n' ', ')
          send_ntfy "[Regsync] SYNC SUCCESS" "Synced in ${config_basename}: ${summary}" high tada
       else
          echo "$sync_output"
          send_ntfy "[Regsync] SYNC FAILED" "Failed sync: ${config_basename}" high x
          overall_success=false
       fi
    else
       log "No sync needed for ${config_basename}"
    fi
  done

  if [[ "$overall_success" == "false" ]]; then
      fatal "One or more configurations failed during sync."
  fi

  send_ntfy "[Regsync] COMPLETE" "All configs up-to-date on ${HOSTNAME}" default white_check_mark
  check_rate_limit || true
  date +%s >"${STATE_FILE}"

  HC_MESSAGE="All configurations processed and synced successfully."
  log "===== Regsync Completed ====="
}

# ==============================================================================
# Usage & Dispatch
# ==============================================================================
usage() {
  printf "\n" >&2
  printf "${GREEN}Usage:${NC} ${CYAN}%s${NC} [--force | --hub-limit]\n" "$0" >&2
  printf "\n" >&2
  printf "  ${YELLOW}%-15s${NC} %s\n" "--force" "Bypass the minimum run interval check." >&2
  printf "  ${YELLOW}%-15s${NC} %s\n" "--hub-limit" "Only check the Docker Hub rate limit and exit." >&2
  printf "\n" >&2
  exit 1
}

# Enable pipefail so the pipeline fails if 'main' fails
set -o pipefail

case "${1:-}" in
  --hub-limit)
    run_manual_check
    ;;
  ""|--force)
    main "$@" 2>&1 | tee -a "${SCRIPT_LOG_FILE}"
    # Exit with main exit code
    exit "${PIPESTATUS[0]}"
    ;;
  *)
    usage
    ;;
esac
