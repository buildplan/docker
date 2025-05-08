#!/bin/bash

# Script to check Docker logins, attempt login using secrets if needed,
# then check for regsync updates and run sync only if needed.

# --- Configuration ---
REGSYNC_FILE="regsync.yml"
SECRETS_DIR="/home/n2ali/private-registry-setup/secrets" # Absolute path
LOG_DIR="/home/n2ali/private-registry-setup/logs"
GOTIFY_TOKEN_FILE="${SECRETS_DIR}/gotify_token"

# --- Read Gotify URL from secrets file ---
GOTIFY_URL_SECRET_FILE="${SECRETS_DIR}/gotify_url_secret"
if [[ -f "${GOTIFY_URL_SECRET_FILE}" ]]; then
    GOTIFY_URL=$(cat "${GOTIFY_URL_SECRET_FILE}")
else
    echo -e "\033[0;31m[ERROR]\033[0m Gotify URL secret file not found: ${GOTIFY_URL_SECRET_FILE}" >&2
    GOTIFY_URL="" # Will cause an error later if not set
fi

# --- Read the private registry identifier from a single secrets file ---
# This identifier MUST EXACTLY MATCH the 'registry:' field in your regsync.yml for your private registry.
PRIVATE_REGISTRY_IDENTIFIER_FILE="${SECRETS_DIR}/private_registry_identifier"
if [[ -f "${PRIVATE_REGISTRY_IDENTIFIER_FILE}" ]]; then
    PRIVATE_REGISTRY_ID_FROM_SECRET=$(cat "${PRIVATE_REGISTRY_IDENTIFIER_FILE}")
else
    echo -e "\033[0;31m[ERROR]\033[0m Private registry identifier file not found: ${PRIVATE_REGISTRY_IDENTIFIER_FILE}" >&2
    PRIVATE_REGISTRY_ID_FROM_SECRET="" # Will cause an error later if not set
fi

YQ_CMD="yq" # Path to yq binary if not in default PATH
SCRIPT_LOG_FILE="${LOG_DIR}/check_sync.log"
PROJECT_DIR="/home/n2ali/private-registry-setup" # Base directory of the project
DOCKER_NETWORK="private-registry-setup_registry-net" # Verify network name if needed
REGSYNC_IMAGE="ghcr.io/regclient/regsync:v0.8.3" # Use pinned version

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

# Function to check if yq exists
check_yq() {
  if ! command -v "$YQ_CMD" &>/dev/null; then error "'yq' command not found."; exit 1; fi
  local yq_version; yq_version=$("$YQ_CMD" --version 2>&1)
  if [[ $? -ne 0 ]] || [[ ! "$yq_version" =~ yq[[:space:]].*[[:space:]]version[[:space:]]v4\.[0-9]+(\.[0-9]+)* ]]; then
    error "yq version 4.x required. Found: $yq_version"; exit 1; fi
}

# Function to send Gotify message
send_gotify() {
  local title="$1" message="$2" priority="$3"
  if [[ -z "${GOTIFY_URL}" ]]; then # Check if GOTIFY_URL was successfully loaded
    warn "Gotify URL is not configured. Cannot send notification."
    return 1
  fi
  if [[ ! -f "${GOTIFY_TOKEN_FILE}" ]]; then warn "Gotify token file missing: ${GOTIFY_TOKEN_FILE}"; return 1; fi
  local token; token=$(<"$GOTIFY_TOKEN_FILE")
  [[ -z "$token" ]] && { warn "Gotify token file is empty: ${GOTIFY_TOKEN_FILE}"; return 1; }

  curl -sf --connect-timeout 5 --max-time 10 -X POST "${GOTIFY_URL}/message?token=${token}" \
    -F "title=${title}" -F "message=${message}" -F "priority=${priority}" &>/dev/null
  return $?
}

# Function to perform non-interactive login using secrets
perform_login() {
    local registry_host_from_yaml="$1" # This is the value from regsync.yml
    local user_file pass_file username password
    log "Attempting non-interactive login to [$registry_host_from_yaml] using secrets..."
    local login_host_for_docker_cli="$registry_host_from_yaml" # Usually the same, but can be overridden (e.g. docker.io)

    # Ensure PRIVATE_REGISTRY_ID_FROM_SECRET was loaded for comparison if we are dealing with the private registry
    # This check is more for robustness; the main script will exit if it's not set at the start.
    if [[ "$registry_host_from_yaml" == "$PRIVATE_REGISTRY_ID_FROM_SECRET" && -z "$PRIVATE_REGISTRY_ID_FROM_SECRET" ]]; then
        error "Private registry identifier (PRIVATE_REGISTRY_ID_FROM_SECRET) is empty, but needed for $registry_host_from_yaml."
        return 1
    fi

    case "$registry_host_from_yaml" in
        "$PRIVATE_REGISTRY_ID_FROM_SECRET") # Matches the content of 'private_registry_identifier' file
            user_file="${SECRETS_DIR}/registry_user"
            pass_file="${SECRETS_DIR}/registry_pass"
            ;;
        "docker.io")
            # login_host_for_docker_cli is already "docker.io"
            user_file="${SECRETS_DIR}/hub_user"
            pass_file="${SECRETS_DIR}/hub_token"
            ;;
        "ghcr.io")
            # login_host_for_docker_cli is already "ghcr.io"
            user_file="${SECRETS_DIR}/ghcr_user"
            pass_file="${SECRETS_DIR}/ghcr_token"
            ;;
        *)
            error "Unknown registry host '$registry_host_from_yaml' for automated login in script."
            error "Ensure '$registry_host_from_yaml' (from regsync.yml) is one of '$PRIVATE_REGISTRY_ID_FROM_SECRET', 'docker.io', or 'ghcr.io', or add a new case."
            return 1 # Indicate failure for this specific registry
            ;;
    esac

    if [[ ! -f "$user_file" || ! -f "$pass_file" ]]; then
        error "Required secret files ($user_file or $pass_file) not found for $registry_host_from_yaml."
        return 1
    fi

    username=$(<"$user_file")
    password=$(<"$pass_file") # Read password or token

    if [[ -z "$username" || -z "$password" ]]; then
        error "Username or password/token file is empty in ($user_file or $pass_file) for $registry_host_from_yaml."
        return 1
    fi

    # Pipe password/token to docker login via stdin
    if echo "$password" | docker login "$login_host_for_docker_cli" -u "$username" --password-stdin; then
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
# Initial checks for critical configurations
if [[ -z "${GOTIFY_URL}" ]]; then
    error "GOTIFY_URL is not set (was not found in ${GOTIFY_URL_SECRET_FILE} or file is empty). Exiting."
    exit 1
fi
if [[ -z "${PRIVATE_REGISTRY_ID_FROM_SECRET}" ]]; then
    error "PRIVATE_REGISTRY_ID_FROM_SECRET is not set (was not found in ${PRIVATE_REGISTRY_IDENTIFIER_FILE} or file is empty). This is needed to identify your private registry. Exiting."
    exit 1
fi

check_yq || exit 1
mkdir -p "${LOG_DIR}" # Ensure log directory exists
# Redirect all output to log file AND terminal
exec > >(tee -a "${SCRIPT_LOG_FILE}") 2>&1

log "===== Starting Regsync Check Script ====="
log "Using Gotify URL: ${GOTIFY_URL}"
log "Private Registry Identifier for login logic: ${PRIVATE_REGISTRY_ID_FROM_SECRET}"
log "Regsync configuration file: ${PROJECT_DIR}/${REGSYNC_FILE}"

# 1. Check/Perform Logins for required registries
log "--- Checking Required Logins ---"
# Use yq to get unique registry hosts from the creds section of regsync.yml
mapfile -t required_registries < <("$YQ_CMD" eval '.creds[].registry // ""' "${PROJECT_DIR}/${REGSYNC_FILE}" | grep -v '^{{file' | sort -u | grep .)

if [[ ${#required_registries[@]} -eq 0 ]]; then
    warn "No registries requiring credentials found in ${PROJECT_DIR}/${REGSYNC_FILE} under '.creds[].registry'."
    warn "If this is unexpected, check your regsync.yml. Proceeding, but regsync might fail if auth is needed."
fi

login_ok=true
if [[ ${#required_registries[@]} -gt 0 ]]; then # Only loop if there are registries found in regsync.yml
    for registry_from_yaml in "${required_registries[@]}"; do
        log "Processing registry for login: $registry_from_yaml"
        perform_login "$registry_from_yaml" || login_ok=false
    done

    if ! $login_ok; then
        error "One or more required logins failed. Aborting sync check."
        log "===== Regsync Check Script Finished (with Login Errors) ====="
        exit 1 # CRUCIAL: Exit if any login failed
    fi
    log "--- All required login checks/attempts complete ---"
else
    log "--- No registries found in regsync.yml requiring login credentials. Skipping login checks. ---"
fi


# 2. Run regsync check
log "--- Running Regsync Check ---"
# Corrected volume mount for SECRETS_DIR, assuming SECRETS_DIR is an absolute path
check_output=$(docker run --rm -i \
  --network "${DOCKER_NETWORK}" \
  -v "${PROJECT_DIR}/${REGSYNC_FILE}:/app/regsync.yml:ro" \
  -v "${SECRETS_DIR}:/secrets:ro" \
  "${REGSYNC_IMAGE}" \
  -c /app/regsync.yml check 2>&1)
check_exit_code=$?

echo "$check_output" # Log the check output

# 3. Conditionally run regsync once
if [[ $check_exit_code -eq 0 ]] && echo "$check_output" | grep -q "Image sync needed"; then
  log "--- Updates Found: Running Regsync Once ---"
  # Corrected volume mount for SECRETS_DIR
  docker run --rm -it \
    --network "${DOCKER_NETWORK}" \
    -v "${PROJECT_DIR}/${REGSYNC_FILE}:/app/regsync.yml:ro" \
    -v "${SECRETS_DIR}:/secrets:ro" \
    "${REGSYNC_IMAGE}" \
    -c /app/regsync.yml once
  sync_exit_code=$?

  if [[ $sync_exit_code -eq 0 ]]; then
    success "Sync 'once' completed successfully."
    send_gotify "[Regsync Check] Sync Done" "Manual Sync 'once' completed successfully." 4
  else
    error "Sync 'once' failed with exit code: $sync_exit_code."
    send_gotify "[Regsync Check] Sync FAIL" "Manual Sync 'once' failed. Exit code: $sync_exit_code." 7
    exit $sync_exit_code # Exit with regsync's error code
  fi

elif [[ $check_exit_code -eq 0 ]]; then
  log "--- No updates needed according to check ---"
else
  error "--- Regsync Check command failed! Exit code: $check_exit_code ---"
  send_gotify "[Regsync Check] Check FAIL" "Regsync check command failed. Exit code: $check_exit_code." 7
  exit $check_exit_code # Exit with regsync check's error code
fi

log "===== Regsync Check Script Finished Successfully ====="
exit 0
