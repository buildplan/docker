#!/bin/bash

# This script uses rsync to backup registry directory to Hetzner Storage Box.

set -euo pipefail

# --- Configuration ---
# Path to the directory backing up
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
HOSTNAME=$(hostname -s)

# Secrets and Logs
SECRETS_DIR="${SOURCE_DIR}/secrets"
LOG_DIR="${SOURCE_DIR}/logs"
LOG_FILE="${LOG_DIR}/backup.log"

# Backup destination details for Hetzner Storage Box
HETZNER_USER=$(<"${SECRETS_DIR}/hetzner_user")
HETZNER_HOST=$(<"${SECRETS_DIR}/hetzner_host")
HETZNER_TARGET_DIR=$(<"${SECRETS_DIR}/hetzner_target")
SSH_PORT="23"

# Determine the correct home directory whether running with sudo or not
if [[ -n "${SUDO_USER-}" ]]; then
  EFFECTIVE_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  EFFECTIVE_HOME="${HOME}"
fi
SSH_KEY_PATH="${EFFECTIVE_HOME}/.ssh/id_hetzner_backup"

# Docker Compose file path
COMPOSE_FILE="${SOURCE_DIR}/docker-compose.yml"
REGISTRY_SERVICE="registry"

# ntfy Notification Details
NTFY_URL=$(<"${SECRETS_DIR}/ntfy_url")
NTFY_TOPIC=$(<"${SECRETS_DIR}/ntfy_topic")
NTFY_TOKEN_FILE="${SECRETS_DIR}/ntfy_token"
# --- End Configuration ---

# Re-run the script with sudo if not already root
if [[ $EUID -ne 0 ]]; then
  echo "Re-running script as root using sudo..."
  exec sudo -E "$0" "$@"
fi

# Ensure log directory exists
mkdir -p "${LOG_DIR}"

# --- Helper Functions ---
log_message() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "${LOG_FILE}"
}

send_ntfy() {
  local title="$1"; local message="$2"; local priority="$3"; local tags="$4"
  if [[ ! -f "${NTFY_TOKEN_FILE}" ]]; then
    log_message "Error: ntfy token file not found at ${NTFY_TOKEN_FILE}"; return 1;
  fi
  local token; token=$(cat "${NTFY_TOKEN_FILE}")
  if [[ -z "$token" ]]; then
    log_message "Error: ntfy token file is empty"; return 1;
  fi
  curl -s -f -H "Authorization: Bearer ${token}" -H "Title: ${title}" -H "Priority: ${priority}" -H "Tags: ${tags}" -d "${message}" "${NTFY_URL}/${NTFY_TOPIC}" > /dev/null
  return $?
}

# --- Main Backup Logic ---
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
rsync_exit_code=0
/usr/bin/rsync -avz --delete --log-file="${LOG_FILE}" -e "ssh -p ${SSH_PORT} -i ${SSH_KEY_PATH}" "${SOURCE_DIR}/" "${HETZNER_USER}@${HETZNER_HOST}:${HETZNER_TARGET_DIR}/" || rsync_exit_code=$?

# 4. Restart Registry Service
log_message "Starting registry service (${REGISTRY_SERVICE})..."
docker compose -f "${COMPOSE_FILE}" start "${REGISTRY_SERVICE}"
log_message "Registry service start command issued."

log_message "Waiting 5 seconds for the service to stabilize..."
sleep 5

# 5. Final Status Check and Notification
log_message "Performing robust check on service status..."
service_is_running=false # Default to false

# Get the container ID for the specific service.
CONTAINER_ID=$(docker compose -f "${COMPOSE_FILE}" ps -q "${REGISTRY_SERVICE}" || true)

# Check if the container ID was found and then inspect its state
if [[ -n "$CONTAINER_ID" ]]; then
    STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER_ID")
    log_message "Service '${REGISTRY_SERVICE}' current state is: ${STATUS}"

    if [[ "$STATUS" == "running" ]]; then
        service_is_running=true
    fi
else
    log_message "Could not find a container for service '${REGISTRY_SERVICE}'."
fi

# Send the final notification based on the results
if [ $rsync_exit_code -eq 0 ] && [ "$service_is_running" = true ]; then
  log_message "Rsync finished successfully and service restarted."
  send_ntfy "[Registry Backup] Success" "Backup finished successfully and service is running on ${HOSTNAME}." "2" "tada"
elif [ $rsync_exit_code -eq 0 ] && [ "$service_is_running" = false ]; then
  log_message "Error: Rsync successful, but FAILED to restart registry service."
  send_ntfy "[Registry Backup] WARNING" "Backup was successful, but the registry service FAILED to restart on ${HOSTNAME}!" "high" "warning"
else
  log_message "Rsync FAILED! Exit code: ${rsync_exit_code}"
  error_msg=$(tail -n 10 "${LOG_FILE}")
  send_ntfy "[Registry Backup] FAILED!" "Backup FAILED on ${HOSTNAME} with Rsync Exit code: ${rsync_exit_code}\n\nLog Tail:\n${error_msg}" "high" "x"
fi

log_message "Registry Backup finished."
log_message "--------------------"

exit $rsync_exit_code
