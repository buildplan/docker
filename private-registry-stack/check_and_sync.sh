#!/bin/bash

# --- v4 - updated 2025-08-18 ---

# Script to check Docker logins, attempt login using secrets if needed,
# then check for regsync updates and run sync only if needed.

# --- Configuration ---
REGSYNC_FILE="regsync.yml"
SECRETS_DIR="/path/to/private-registry-setup/secrets" # Absolute path to secrets
LOG_DIR="/path/to/private-registry-setup/logs"        # Path to logs dir.
GOTIFY_TOKEN_FILE="${SECRETS_DIR}/gotify_token"
YQ_CMD="yq" # Path to yq binary if not in default PATH
SCRIPT_LOG_FILE="${LOG_DIR}/check_sync.log"
PROJECT_DIR="/path/to/private-registry-setup" # Base directory of the project
DOCKER_NETWORK="private-registry-setup_registry-net" # Verify network name if needed
REGSYNC_IMAGE="ghcr.io/regclient/regsync:v0.8.3" # Use pinned version

# --- Read Secrets Reliably ---
# Use 'read -r' to read the first line of a file and automatically strip the trailing newline.
GOTIFY_URL_SECRET_FILE="${SECRETS_DIR}/gotify_url_secret"
if [[ -f "${GOTIFY_URL_SECRET_FILE}" ]]; then
    read -r GOTIFY_URL < "${GOTIFY_URL_SECRET_FILE}"
else
    echo -e "\033[0;31m[ERROR]\033[0m Gotify URL secret file not found: ${GOTIFY_URL_SECRET_FILE}" >&2
    GOTIFY_URL=""
fi

PRIVATE_REGISTRY_IDENTIFIER_FILE="${SECRETS_DIR}/private_registry_identifier"
if [[ -f "${PRIVATE_REGISTRY_IDENTIFIER_FILE}" ]]; then
    read -r PRIVATE_REGISTRY_ID_FROM_SECRET < "${PRIVATE_REGISTRY_IDENTIFIER_FILE}"
else
    echo -e "\033[0;31m[ERROR]\033[0m Private registry identifier file not found: ${PRIVATE_REGISTRY_IDENTIFIER_FILE}" >&2
    PRIVATE_REGISTRY_ID_FROM_SECRET=""
fi

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Helper Functions ---
log()   { echo -e "${BLUE}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
success(){ echo -e "${GREEN}[SUCCESS]${NC} $*"; }

check_yq() {
  if ! command -v "$YQ_CMD" &>/dev/null; then error "'yq' command not found."; exit 1; fi
  local yq_version; yq_version=$("$YQ_CMD" --version 2>&1)
  if [[ $? -ne 0 ]] || [[ ! "$yq_version" =~ yq[[:space:]].*[[:space:]]version[[:space:]]v4\.[0-9]+(\.[0-9]+)* ]]; then
    error "yq version 4.x required. Found: $yq_version"; exit 1; fi
}

send_gotify() {
  local title="$1" message="$2" priority="$3"
  if [[ -z "${GOTIFY_URL}" ]]; then warn "Gotify URL is not configured. Cannot send notification."; return 1; fi
  if [[ ! -f "${GOTIFY_TOKEN_FILE}" ]]; then warn "Gotify token file missing: ${GOTIFY_TOKEN_FILE}"; return 1; fi
  local token; token=$(<"$GOTIFY_TOKEN_FILE")
  [[ -z "$token" ]] && { warn "Gotify token file is empty: ${GOTIFY_TOKEN_FILE}"; return 1; }
  curl -sf --connect-timeout 5 --max-time 10 -X POST "${GOTIFY_URL}/message?token=${token}" \
    -F "title=${title}" -F "message=${message}" -F "priority=${priority}" &>/dev/null
  return $?
}

perform_login() {
    local registry_host_from_yaml="$1"
    local user_file pass_file username password
    log "Attempting non-interactive login to [$registry_host_from_yaml] using secrets..."

    if [[ "$registry_host_from_yaml" == "$PRIVATE_REGISTRY_ID_FROM_SECRET" ]]; then
        user_file="${SECRETS_DIR}/registry_user"
        pass_file="${SECRETS_DIR}/registry_pass"
    elif [[ "$registry_host_from_yaml" == "docker.io" ]]; then
        user_file="${SECRETS_DIR}/hub_user"
        pass_file="${SECRETS_DIR}/hub_token"
    elif [[ "$registry_host_from_yaml" == "ghcr.io" ]]; then
        user_file="${SECRETS_DIR}/ghcr_user"
        pass_file="${SECRETS_DIR}/ghcr_token"
    else
        error "Unknown registry host '$registry_host_from_yaml' for automated login."
        return 1
    fi

    if [[ ! -f "$user_file" || ! -f "$pass_file" ]]; then
        error "Required secret files ($user_file or $pass_file) not found for $registry_host_from_yaml."
        return 1
    fi

    read -r username < "$user_file"
    read -r password < "$pass_file"
    username=$(echo "$username" | xargs)
    password=$(echo "$password" | xargs)

    if [[ -z "$username" || -z "$password" ]]; then
        error "Username or password/token file is empty for $registry_host_from_yaml."
        return 1
    fi

    if echo "$password" | docker login "$registry_host_from_yaml" -u "$username" --password-stdin; then
        success "Login successful for $registry_host_from_yaml."
        send_gotify "[Regsync Check] Login OK" "Successfully logged into $registry_host_from_yaml" 3
        return 0
    else
        error "Login FAILED for $registry_host_from_yaml."
        send_gotify "[Regsync Check] Login FAIL" "Failed to log into $registry_host_from_yaml non-interactively." 7
        return 1
    fi
}

# --- Main Execution ---

# Create a temporary, isolated Docker config directory to bypass any interactive credential helpers.
export DOCKER_CONFIG
DOCKER_CONFIG=$(mktemp -d)

# Ensure the temporary directory is cleaned up when the script exits, for any reason.
trap 'rm -rf "$DOCKER_CONFIG"' EXIT

# Fail fast if critical configuration is missing.
if [[ -z "${GOTIFY_URL}" ]]; then
    error "GOTIFY_URL is not set or its secret file is empty. Exiting."
    exit 1
fi
if [[ -z "${PRIVATE_REGISTRY_ID_FROM_SECRET}" ]]; then
    error "PRIVATE_REGISTRY_ID_FROM_SECRET is not set or its file is empty. Exiting."
    exit 1
fi

check_yq || exit 1
mkdir -p "${LOG_DIR}"

# Redirect all output to log file AND terminal.
exec > >(tee -a "${SCRIPT_LOG_FILE}") 2>&1

log "===== Starting Regsync Check Script ====="
log "Using temporary Docker config directory: $DOCKER_CONFIG"
log "Using Gotify URL: ${GOTIFY_URL}"
log "Private Registry Identifier for login logic: ${PRIVATE_REGISTRY_ID_FROM_SECRET}"

# 1. Perform logins for required registries.
log "--- Checking Required Logins ---"
mapfile -t required_registries < <("$YQ_CMD" eval '.creds[].registry // ""' "${PROJECT_DIR}/${REGSYNC_FILE}" | grep -v '^{{file' | sort -u | grep .)

login_ok=true
if [[ ${#required_registries[@]} -gt 0 ]]; then
    for registry in "${required_registries[@]}"; do
        perform_login "$registry" || login_ok=false
    done
    if ! $login_ok; then
        error "One or more required logins failed. Aborting sync check."
        log "===== Regsync Check Script Finished (with Login Errors) ====="
        exit 1
    fi
    log "--- All required login checks/attempts complete ---"
else
    log "--- No registries found in regsync.yml requiring login credentials. Skipping login checks. ---"
fi

# 2. Run regsync check.
log "--- Running Regsync Check ---"
check_output=$(docker run --rm -i \
  --network "${DOCKER_NETWORK}" \
  -v "${PROJECT_DIR}/${REGSYNC_FILE}:/app/regsync.yml:ro" \
  -v "${SECRETS_DIR}:/secrets:ro" \
  -v "${DOCKER_CONFIG}:${DOCKER_CONFIG}:ro" \
  -e "DOCKER_CONFIG=${DOCKER_CONFIG}" \
  "${REGSYNC_IMAGE}" \
  -c /app/regsync.yml check 2>&1)
check_exit_code=$?
echo "$check_output"

# 3. Conditionally run regsync once.
if [[ $check_exit_code -eq 0 ]] && echo "$check_output" | grep -q "Image sync needed"; then
    log "--- Updates Found: Running Regsync Once ---"
    docker run --rm -it \
      --network "${DOCKER_NETWORK}" \
      -v "${PROJECT_DIR}/${REGSYNC_FILE}:/app/regsync.yml:ro" \
      -v "${SECRETS_DIR}:/secrets:ro" \
      -v "${DOCKER_CONFIG}:${DOCKER_CONFIG}:ro" \
      -e "DOCKER_CONFIG=${DOCKER_CONFIG}" \
      "${REGSYNC_IMAGE}" \
      -c /app/regsync.yml once
    sync_exit_code=$?

    if [[ $sync_exit_code -eq 0 ]]; then
        success "Sync 'once' completed successfully."
        send_gotify "[Regsync Check] Sync Done" "Manual Sync 'once' completed successfully." 4
    else
        error "Sync 'once' failed with exit code: $sync_exit_code."
        send_gotify "[Regsync Check] Sync FAIL" "Manual Sync 'once' failed. Exit code: $sync_exit_code." 7
        exit $sync_exit_code
    fi
elif [[ $check_exit_code -eq 0 ]]; then
    log "--- No updates needed according to check ---"
else
    error "--- Regsync Check command failed! Exit code: $check_exit_code ---"
    send_gotify "[Regsync Check] Check FAIL" "Regsync check command failed. Exit code: $check_exit_code." 7
    exit $check_exit_code
fi

log "===== Regsync Check Script Finished Successfully ====="
exit 0
