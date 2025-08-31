#!/bin/bash

# ==============================================================================
# Name: check_sync.sh
# Description: A bash script to check for and sync Docker images using
#              regsync. It is designed to be run periodically (e.g., via a
#              cron job). The script is rate-limit aware for Docker Hub,
#              includes retry logic for transient errors, and provides detailed
#              logging and notifications via ntfy.
#
# buildplan.org
# 28-08-2025
# ==============================================================================

# --- PURPOSE ---
# This script automates the process of keeping a local Docker registry mirror
# up-to-date with upstream public registries. It prevents unnecessary runs,
# avoids failures due to Docker Hub's rate limits, and provides clear
# success/failure notifications.

# --- PREREQUISITES ---
# 1. `docker` and `docker compose` must be installed and running.
# 2. `curl` is required for sending ntfy notifications and checking rate limits.
# 3. `jq` is required to parse the JSON response for the Docker Hub auth token.
# 4. A `docker-compose.yml` file with a configured `regsync` service.
# 5. A ntfy token file located at `secrets/ntfy_token` within the PROJECT_DIR.

# --- CONFIGURATION ---
# All user-configurable variables are located in the "Configuration" section
# at the top of the script. Key variables include:
# - PROJECT_DIR: The root directory of your registry project.
# - MIN_INTERVAL_HOURS: The minimum time between script runs. Set to 0 to disable.
# - NTFY_URL/TOPIC/TOKEN: Settings for ntfy push notifications.
# - CRITICAL_THRESHOLD: If Docker Hub pulls are below this, the script will abort.
# - WARNING_THRESHOLD: If pulls are below this, a warning is logged.
# - MAX_RETRIES: How many times to retry a failed regsync command.
# - RETRY_DELAY: How many seconds to wait between retries.

# --- USAGE ---
# 1. Standard Execution (respects the time interval):
#    ./check_and_sync.sh
# 2. Force Execution (bypasses the time interval check):
#    ./check_and_sync.sh --force
# 3. Manual Rate-Limit Check (only checks the limit and exits):
#    ./check_and_sync.sh --check

# --- WORKFLOW ---
# 1.  Parses command-line arguments (e.g., --force).
# 2.  Checks if the minimum time interval has passed since the last run. If not,
#     it exits unless the --force flag is used.
# 3.  Performs a pre-check of the Docker Hub API rate limit. If the remaining
#     pulls are below the CRITICAL_THRESHOLD, it aborts the run.
# 4.  Runs `regsync check` with retry logic.
# 5.  If the check command fails after all retries, it sends a failure
#     notification and exits.
# 6.  If the check output indicates that images need syncing, it proceeds to run
#     `regsync once` with the same retry logic.
# 7.  Sends a final notification indicating success, failure, or that all
#     images were already up-to-date.
# 8.  Performs a final rate-limit check to log the status after the run.
# 9.  All output is printed to the console and appended to the log file specified
#     by SCRIPT_LOG_FILE.
#
# --- FUNCTIONS ---
#
# log(), warn(), error(), success()
#   - Helper functions for color-coded and formatted log output.
#
# send_ntfy(title, message, priority, tags)
#   - Sends a push notification to the configured ntfy topic.
#
# get_auth_token()
#   - Fetches a temporary authentication token from Docker Hub required for
#     querying the rate-limit API.
#
# check_rate_limit()
#   - Makes an API call to Docker Hub to get the current rate-limit status
#     (limit, remaining, reset time) and compares it against the thresholds.
#
# run_regsync_with_retry(mode)
#   - A robust wrapper that executes a regsync command ('check' or 'once').
#   - It captures all output and intelligently retries the command if it fails,
#     with a longer delay for rate-limit specific errors.
#
# main()
#   - The primary function that orchestrates the entire script workflow from
#     start to finish.
#
# ==============================================================================

set -euo pipefail

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

HOSTNAME=$(hostname -s)
HUB_USER_FILE="${SECRETS_DIR}/hub_user"
HUB_TOKEN_FILE="${SECRETS_DIR}/hub_token"
DOCKER_HUB_REGISTRY="registry-1.docker.io"
RATE_CHECK_IMAGE="ratelimitpreview/test"

MAX_RETRIES=3
RETRY_DELAY=300
MIN_INTERVAL_HOURS=6

CRITICAL_THRESHOLD=75
WARNING_THRESHOLD=175

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# ==============================================================================
# Logging & Notification
# ==============================================================================
log()    { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${BLUE}[INFO]${NC} $*" >&2; }
warn()   { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${YELLOW}[WARN]${NC} $*" >&2; }
error()  { echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}[ERROR]${NC} $*" >&2; }
success(){ echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${GREEN}[SUCCESS]${NC} $*" >&2; }

send_ntfy() {
  local title="$1" message="$2" priority="$3" tags="$4"
  local auth_header=()
  if [[ -f "${NTFY_TOKEN_FILE}" ]]; then
    local token
    token=$(<"${NTFY_TOKEN_FILE}")
    [[ -n "$token" ]] && auth_header=(-H "Authorization: Bearer ${token}")
  fi
  curl -sf --connect-timeout 5 --max-time 10 \
    "${auth_header[@]}" \
    -H "Title: ${title}" -H "Priority: ${priority}" -H "Tags: ${tags}" \
    -d "${message}" \
    "${NTFY_URL}/${NTFY_TOPIC}" &
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

# ==============================================================================
# Manual Rate-Limit Check (for --check)
# ==============================================================================
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
  echo "Docker Hub Rate Limit Status"
  echo "----------------------------------------"
  echo -e "Account:      ${GREEN}${user_info}${NC}"
  echo -e "Limit:        ${GREEN}${limit}${NC} pulls per 6 hours"
  echo -e "Remaining:    ${GREEN}${remaining}${NC}"
  echo -e "Used:         ${YELLOW}${used}${NC} (${usage}%)"
  echo "----------------------------------------"
  exit 0
}

# ==============================================================================
# Regsync Wrapper with Retry
# ==============================================================================
REGSYNC_OUTPUT=""
run_regsync_with_retry() {
  local mode=$1
  REGSYNC_OUTPUT=""
  for attempt in $(seq 1 "${MAX_RETRIES}"); do
    log "Running regsync '${mode}' (attempt ${attempt}/${MAX_RETRIES})..."
    local cmd_out rc=0
    cmd_out=$(docker compose -f "${COMPOSE_FILE}" run --rm -T regsync -c /config/regsync.yml "${mode}" 2>&1) || rc=$?
    REGSYNC_OUTPUT="$cmd_out"
    if [[ $rc -eq 0 ]]; then
      success "Regsync '${mode}' completed successfully."
      return 0
    fi
    error "Regsync '${mode}' failed on attempt ${attempt} with exit code ${rc}."
    if grep -qiE 'too.*many.*requests|rate.*limit|429' <<<"$cmd_out"; then
      warn "Rate-limit error detected."
      if (( attempt < MAX_RETRIES )); then
        log "Waiting for ${RETRY_DELAY}s before retrying..."
        sleep "${RETRY_DELAY}"
        continue
      fi
    else
      error "Non-retryable error detected. Failing fast."
      echo -e "${RED}--- Begin Regsync Error Output ---\n${REGSYNC_OUTPUT}\n--- End Regsync Error Output ---${NC}" >&2
      return 1
    fi
  done
  error "Regsync '${mode}' has failed after all ${MAX_RETRIES} attempts."
  return 1
}

# ==============================================================================
# Main Logic
# ==============================================================================
main() {
  mkdir -p "${LOG_DIR}"

  # Config validation
  [[ -r "${COMPOSE_FILE}" ]] || { error "Missing compose file: ${COMPOSE_FILE}"; exit 1; }
  [[ -r "${PROJECT_DIR}/regsync.yml" ]] || { error "Missing regsync.yml"; exit 1; }
  [[ -r "${NTFY_TOKEN_FILE}" ]] || warn "Missing ntfy token; notifications may fail"

  # Prerequisites
  for cmd in docker curl jq date; do
    command -v "$cmd" &>/dev/null || { error "Required command not found: $cmd"; exit 1; }
  done
  if ! docker compose version &>/dev/null; then
    error "Required command 'docker compose' not found. Please ensure Docker Compose v2 is installed."
    exit 1
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
        log "Skipping: last run $((delta/60)) minutes ago"
        exit 0
      fi
    fi
  fi

  log "===== Starting Regsync on ${HOSTNAME} ====="

  # Pre-check rate limit
  local status=0
  check_rate_limit || status=$?
  if [[ $status -eq 2 ]]; then
    send_ntfy "[Regsync] ABORTED" "Critical rate-limit on ${HOSTNAME}" high stop_sign
    exit 1
  fi

  send_ntfy "[Regsync] START" "Beginning sync on ${HOSTNAME}" default hourglass

  # Regsync check
  if ! run_regsync_with_retry check; then
    send_ntfy "[Regsync] CHECK FAILED" "Regsync check failed on ${HOSTNAME}" high x
    exit 1
  fi
  echo "${REGSYNC_OUTPUT}"

  # Sync if needed
  if grep -q "Image sync needed" <<<"${REGSYNC_OUTPUT}"; then
    if run_regsync_with_retry once; then
      local summary
      summary=$(grep 'sync needed' <<<"${REGSYNC_OUTPUT}" | sed 's/.*: //')
      send_ntfy "[Regsync] SYNC SUCCESS" "Updated: ${summary}" high tada
    else
      send_ntfy "[Regsync] SYNC FAILED" "Sync failed on ${HOSTNAME}" high x
      exit 1
    fi
  else
    send_ntfy "[Regsync] UP-TO-DATE" "All images up to date on ${HOSTNAME}" default white_check_mark
  fi

  # Final rate-limit log
  check_rate_limit || true

  # On success, update state
  log "Run complete—updating state timestamp"
  date +%s >"${STATE_FILE}"

  log "===== Regsync Completed Successfully ====="
  exit 0
}

# ==============================================================================
# Usage & Dispatch
# ==============================================================================
usage() {
  cat >&2 <<EOF
Usage: $0 [--force | --check]
  --force    Bypass interval check
  --check    Only perform rate-limit check
EOF
  exit 1
}

# Enable pipefail so the pipeline fails if 'main' fails
set -o pipefail

case "${1:-}" in
  --check)
    run_manual_check
    ;;
  ""|--force)
    main "$@" 2>&1 | tee -a "${SCRIPT_LOG_FILE}"
    # Exit with 'main'’s exit code, not tee’s
    exit "${PIPESTATUS[0]}"
    ;;
  *)
    usage
    ;;
esac
