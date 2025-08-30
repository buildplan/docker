#!/bin/bash

# This script uses rsync to backup registry directory to Hetzner Storage Box.

set -euo pipefail

# --- Configuration ---
HOSTNAME=$(hostname -s)

# Path to the directory backing up
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

# Secrets, Logs and Lock
SECRETS_DIR="${SOURCE_DIR}/secrets"
LOG_DIR="${SOURCE_DIR}/logs"
LOG_FILE="${LOG_DIR}/run_backup.log"
LOCK_FILE="${LOG_DIR}/run_backup.lock"

# Backup destination details for Hetzner Storage Box
HETZNER_USER=$(<"${SECRETS_DIR}/hetzner_user")
HETZNER_HOST=$(<"${SECRETS_DIR}/hetzner_host")
HETZNER_TARGET_DIR=$(<"${SECRETS_DIR}/hetzner_target")
SSH_PORT=$(<"${SECRETS_DIR}/hetzner_port")

# Determine the correct home directory whether running with sudo or not
if [[ -n "${SUDO_USER-}" ]]; then
  EFFECTIVE_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  EFFECTIVE_HOME="${HOME}"
fi
SSH_KEY_PATH="${EFFECTIVE_HOME}/.ssh/id_run_backup"

# Docker Compose file path
COMPOSE_FILE="${SOURCE_DIR}/docker-compose.yml"
REGISTRY_SERVICE="registry"

# ntfy Notification Details
NTFY_URL=$(<"${SECRETS_DIR}/ntfy_url")
NTFY_TOPIC=$(<"${SECRETS_DIR}/ntfy_topic")
NTFY_TOKEN=$(<"${SECRETS_DIR}/ntfy_token")
# --- End Configuration ---

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Re-running with sudo..."
   exec sudo -E "$0" "$@"
fi

mkdir -p "${LOG_DIR}"

# --- Helper Functions ---
log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "${LOG_FILE}"
}

send_ntfy() {
  local title="$1"; local message="$2"; local priority="$3"; local tags="$4"
  if [[ -z "$NTFY_TOKEN" ]]; then
    log_message "Error: ntfy token is empty"; return 1;
  fi
  curl -s -f -H "Authorization: Bearer ${NTFY_TOKEN}" -H "Title: ${title}" -H "Priority: ${priority}" -H "Tags: ${tags}" -d "${message}" "${NTFY_URL}/${NTFY_TOPIC}" > /dev/null
  return $?
}

cleanup() {
    log_message "Executing cleanup..."
    local container_id
    container_id=$(docker compose -f "${COMPOSE_FILE}" ps -q "${REGISTRY_SERVICE}" 2>/dev/null || true)
    if [[ -n "$container_id" ]]; then
        local status
        status=$(docker inspect --format='{{.State.Status}}' "$container_id")
        if [[ "$status" != "running" ]]; then
            log_message "Attempting to restart registry service (${REGISTRY_SERVICE}) during cleanup..."
            docker compose -f "${COMPOSE_FILE}" start "${REGISTRY_SERVICE}"
            log_message "Registry service start command issued."
        fi
    fi
    rm -f "${LOCK_FILE}"
    log_message "Lock file removed. Cleanup finished."
}
trap cleanup EXIT

if [ -e "${LOCK_FILE}" ]; then
    log_message "Lock file exists. Another backup process may be running. Aborting."
    exit 1
else
    echo $$ > "${LOCK_FILE}"
    log_message "Lock file created."
fi

# --- Main Backup Logic ---
rsync_exit_code=0

log_message "--------------------"
log_message "Registry Backup started on ${HOSTNAME}"
send_ntfy "[Registry Backup] Start" "Backup process started on ${HOSTNAME}" "2" "gear" || log_message "Warning: Failed to send ntfy start notification."

# 1. SSH Connection Test
log_message "Testing SSH connection to backup host..."
if ! ssh -p "${SSH_PORT}" -i "${SSH_KEY_PATH}" -o ConnectTimeout=10 -o BatchMode=yes "${HETZNER_USER}@${HETZNER_HOST}" exit; then
    log_message "Error: Cannot connect to backup host. Aborting."
    send_ntfy "[Registry Backup] FAILED" "Could not connect to backup host ${HETZNER_HOST}. Backup aborted." "high" "x"
    exit 1
fi
log_message "SSH connection successful."

# 2. Stop Registry Service
log_message "Stopping registry service (${REGISTRY_SERVICE})..."
docker compose -f "${COMPOSE_FILE}" stop "${REGISTRY_SERVICE}"
log_message "Registry service stopped."

# 3. Perform rsync
log_message "Starting rsync to ${HETZNER_USER}@${HETZNER_HOST}:${HETZNER_TARGET_DIR}..."
/usr/bin/rsync -avz --delete -e "ssh -p ${SSH_PORT} -i ${SSH_KEY_PATH}" "${SOURCE_DIR}/" "${HETZNER_USER}@${HETZNER_HOST}:${HETZNER_TARGET_DIR}/" >> "${LOG_FILE}" 2>&1 || rsync_exit_code=$?

# 4. Restart Registry Service
log_message "Starting registry service (${REGISTRY_SERVICE})..."
docker compose -f "${COMPOSE_FILE}" start "${REGISTRY_SERVICE}"
log_message "Registry service start command issued."

# 5. Final Status Check and Notification
if [ $rsync_exit_code -ne 0 ]; then
    log_message "Rsync FAILED! Exit code: ${rsync_exit_code}"
    error_msg=$(tail -n 10 "${LOG_FILE}")
    send_ntfy "[Registry Backup] FAILED!" "Backup FAILED on ${HOSTNAME} with Rsync Exit code: ${rsync_exit_code}\n\nLog Tail:\n${error_msg}" "high" "x"
else
    log_message "Rsync finished successfully. Waiting 5 seconds for service to stabilize..."
    sleep 5
    log_message "Checking registry service status..."
    service_is_running=false # Default to false
    container_id=$(docker compose -f "${COMPOSE_FILE}" ps -q "${REGISTRY_SERVICE}" || true)
    if [[ -n "$container_id" ]]; then
        status=$(docker inspect --format='{{.State.Status}}' "$container_id")
        log_message "Service '${REGISTRY_SERVICE}' final state is: ${status}"
        if [[ "$status" == "running" ]]; then
            service_is_running=true
        fi
    else
        log_message "Could not find a container for service '${REGISTRY_SERVICE}'."
    fi

    if [ "$service_is_running" = true ]; then
        log_message "Backup finished successfully and registry service is running."
        send_ntfy "[Registry Backup] Success" "Backup finished successfully and registry service is running on ${HOSTNAME}." "2" "tada"
    else
        log_message "Error: Rsync successful, but FAILED to restart registry service."
        send_ntfy "[Registry Backup] WARNING" "Backup was successful, but the registry service FAILED to restart on ${HOSTNAME}!" "high" "warning"
    fi
fi

log_message "Registry Backup finished."
log_message "--------------------"

exit $rsync_exit_code
