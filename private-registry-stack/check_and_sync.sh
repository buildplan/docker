#!/bin/bash

# Script to check Docker logins, attempt login using secrets if needed,
# then check for regsync updates and run sync only if needed.

# --- Configuration ---
REGSYNC_FILE="regsync.yml"
SECRETS_DIR="./secrets" # Assumes script is run from private-registry-setup
LOG_DIR="./logs"
GOTIFY_TOKEN_FILE="${SECRETS_DIR}/gotify_token"
GOTIFY_URL="https://gotify.my_domin.com" # change this to gotify domain
PRIVATE_REGISTRY_HOST=$(cat "${SECRETS_DIR}/registry_host" 2>/dev/null || echo "registry.my_domin.com") # Read host or use default
YQ_CMD="yq" # Path to yq binary if not in default PATH
SCRIPT_LOG_FILE="${LOG_DIR}/check_sync.log"
PROJECT_DIR="/home/vps_user/private-registry-setup" # Verify this path
DOCKER_NETWORK="private-registry-setup_registry-net" # Verify network name if needed
REGSYNC_IMAGE="ghcr.io/regclient/regsync:v0.8.3" # Use pinned version
# --- End Configuration ---

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
  if [[ ! -f "${GOTIFY_TOKEN_FILE}" ]]; then warn "Gotify token file missing"; return 1; fi
  local token; token=$(<"$GOTIFY_TOKEN_FILE")
  [[ -z "$token" ]] && { warn "Gotify token file is empty"; return 1; }
  curl -sf --connect-timeout 5 --max-time 10 -X POST "${GOTIFY_URL}/message?token=${token}" \
    -F "title=${title}" -F "message=${message}" -F "priority=${priority}" &>/dev/null
  return $?
}

# Function to check login status using credential helper
check_login_status() {
    local registry_host="$1"
    log "Checking login status for [$registry_host] via helper..."
    if printf "%s" "$registry_host" | docker-credential-pass get > /dev/null 2>&1; then
        success "Credentials found for [$registry_host] via helper."
        return 0
    else
        warn "Credentials NOT found for [$registry_host] via helper."
        return 1
    fi
}

# Function to perform non-interactive login using secrets
perform_login() {
    local registry_host="$1" user_file pass_file username password
    log "Attempting non-interactive login to [$registry_host] using secrets..."
    local login_host="$registry_host" # Host to use for docker login command

    # Determine secret file paths based on host
    case "$registry_host" in
        "registry.my_domin.com")
            user_file="${SECRETS_DIR}/registry_user"
            pass_file="${SECRETS_DIR}/registry_pass"
            ;;
        "docker.io")
            # Docker Hub login often uses the index URL or just 'docker.io'
            login_host="docker.io" # Use consistent name for login command
            user_file="${SECRETS_DIR}/hub_user"
            pass_file="${SECRETS_DIR}/hub_token"
            ;;
        "ghcr.io")
            user_file="${SECRETS_DIR}/ghcr_user"
            pass_file="${SECRETS_DIR}/ghcr_token"
            ;;
        *)
            error "Unknown registry host '$registry_host' for automated login in script."
            return 1
            ;;
    esac

    if [[ ! -f "$user_file" || ! -f "$pass_file" ]]; then
        error "Required secret files ($user_file or $pass_file) not found for $registry_host."
        return 1
    fi

    username=$(<"$user_file")
    password=$(<"$pass_file") # Read password or token

    if [[ -z "$username" || -z "$password" ]]; then
         error "Username or password/token file is empty for $registry_host."
         return 1
    fi

    # Pipe password/token to docker login via stdin
    if echo "$password" | docker login "$login_host" -u "$username" --password-stdin; then
         success "Login successful for $registry_host."
         send_gotify "[Regsync Check] Login OK" "Successfully logged into $registry_host" 3
         return 0
    else
         error "Login FAILED for $registry_host."
         send_gotify "[Regsync Check] Login FAIL" "Failed to log into $registry_host non-interactively." 7
         return 1
    fi
}

# --- Main Execution ---
check_yq || exit 1
mkdir -p "${LOG_DIR}"
# Redirect all output to log file AND terminal
exec > >(tee -a "${SCRIPT_LOG_FILE}") 2>&1

log "===== Starting Regsync Check Script ====="

# 1. Check/Perform Logins for required registries
log "--- Checking Required Logins ---"
# Use yq to get unique registry hosts from the creds section
mapfile -t required_registries < <("$YQ_CMD" eval '.creds[].registry // ""' "${PROJECT_DIR}/${REGSYNC_FILE}" | grep -v '^{{file' | sort -u | grep .) # Read registries, ignore file template in case it exists, sort, remove empty lines
login_ok=true
for registry in "${required_registries[@]}"; do
    # Skip if check_login_status succeeds (returns 0)
    check_login_status "$registry" || perform_login "$registry" || login_ok=false
done

if ! $login_ok; then
    error "One or more required logins failed. Aborting sync check."
    log "===== Regsync Check Script Finished (with Login Errors) ====="
    exit 1
fi
log "--- Login Checks/Attempts Complete ---"


# 2. Run regsync check
log "--- Running Regsync Check ---"
check_output=$(docker run --rm -i \
  --network "${DOCKER_NETWORK}" \
  -v "${PROJECT_DIR}/${REGSYNC_FILE}:/app/regsync.yml:ro" \
  -v "${PROJECT_DIR}/${SECRETS_DIR}:/secrets:ro" \
  "${REGSYNC_IMAGE}" \
  -c /app/regsync.yml check 2>&1) # <-- Corrected Path
check_exit_code=$?

echo "$check_output" # Log the check output

# 3. Conditionally run regsync once
if [[ $check_exit_code -eq 0 ]] && echo "$check_output" | grep -q "Image sync needed"; then
  log "--- Updates Found: Running Regsync Once ---"
  # Run interactively (-it) so user can see progress if run manually
  docker run --rm -it \
    --network "${DOCKER_NETWORK}" \
    -v "${PROJECT_DIR}/${REGSYNC_FILE}:/app/regsync.yml:ro" \
    -v "${PROJECT_DIR}/${SECRETS_DIR}:/secrets:ro" \
    "${REGSYNC_IMAGE}" \
    -c /app/regsync.yml once # <-- Corrected Path
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
