#!/bin/bash

# --- Configuration ---
# Path to the directory backing up
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
HOSTNAME=$(hostname -s)
# Secrets and Logs
SECRETS_DIR="${SOURCE_DIR}/secrets"
LOG_DIR="${SOURCE_DIR}/logs"
# Backup destination details for Hetzner Storage Box
HETZNER_USER=$(<"${SECRETS_DIR}/hetzner_user")
HETZNER_HOST=$(<"${SECRETS_DIR}/hetzner_host")
HETZNER_TARGET_DIR="/home/private-registry"
SSH_PORT="23"
if [[ -n "$SUDO_USER" ]]; then
  EFFECTIVE_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
  EFFECTIVE_HOME="${HOME}"
fi
SSH_KEY_PATH="${EFFECTIVE_HOME}/.ssh/id_hetzner_backup"
# Docker Compose file path
COMPOSE_FILE="${SOURCE_DIR}/docker-compose.yml"
REGISTRY_SERVICE="registry"
# Logs
LOG_FILE="${LOG_DIR}/backup.log"
# Gotify details
GOTIFY_TOKEN_FILE="${SECRETS_DIR}/gotify_token"
GOTIFY_URL=$(<"${SECRETS_DIR}/gotify_url")
# --- End Configuration ---

# Re-run the script with sudo if not already root
if [[ $EUID -ne 0 ]]; then
  echo "Re-running script as root using sudo..."
  exec sudo "$0" "$@"
fi

# Ensure log directory exists
mkdir -p "${LOG_DIR}"

# Function to send Gotify message
send_gotify() {
  local title="$1"; local message="$2"; local priority="$3"
  if [[ ! -f "${GOTIFY_TOKEN_FILE}" ]]; then echo "Error: Gotify token file not found" >&2; return 1; fi
  local token=$(cat "${GOTIFY_TOKEN_FILE}")
  if [[ -z "$token" ]]; then echo "Error: Gotify token file is empty" >&2; return 1; fi
  curl -sf -X POST "${GOTIFY_URL}/message?token=${token}" -F "title=${title}" -F "message=${message}" -F "priority=${priority}"
  return $?
}

# --- Main Backup Logic ---
echo "--------------------" | tee -a "${LOG_FILE}"
echo "Registry Backup started at $(date)" | tee -a "${LOG_FILE}"

send_gotify "[Registry Backup] Start" "Registry backup process started on ${HOSTNAME}" "3" || echo "Warning: Failed to send Gotify start notification." >&2

# 1. Stop Registry Service for consistency
echo "Stopping registry service (${REGISTRY_SERVICE})..." | tee -a "${LOG_FILE}"
docker compose -f "${COMPOSE_FILE}" stop "${REGISTRY_SERVICE}"
stop_exit_code=$?
if [ $stop_exit_code -ne 0 ]; then
  echo "Error: Failed to stop registry service. Aborting backup." | tee -a "${LOG_FILE}"
  send_gotify "[Registry Backup] FAILED!" "Failed to stop registry service (${REGISTRY_SERVICE}). Backup aborted." "8"
  exit 1
fi
echo "Registry service stopped." | tee -a "${LOG_FILE}"

# 2. Perform rsync
# Use sudo because source directory contains root-owned files from volumes
echo "Starting rsync to ${HETZNER_USER}@${HETZNER_HOST}:${HETZNER_TARGET_DIR}..." | tee -a "${LOG_FILE}"
sudo /usr/bin/rsync -avz --delete \
     --log-file="${LOG_FILE}" \
     -e "ssh -p ${SSH_PORT} -i ${SSH_KEY_PATH}" \
     "${SOURCE_DIR}/" \
     "${HETZNER_USER}@${HETZNER_HOST}:${HETZNER_TARGET_DIR}/"
rsync_exit_code=$?

# 3. Restart Registry Service (regardless of rsync outcome)
echo "Starting registry service (${REGISTRY_SERVICE})..." | tee -a "${LOG_FILE}"
docker compose -f "${COMPOSE_FILE}" start "${REGISTRY_SERVICE}"
start_exit_code=$?
if [ $start_exit_code -ne 0 ]; then
    echo "Error: Failed to restart registry service after backup attempt." | tee -a "${LOG_FILE}"
    send_gotify "[Registry Backup] WARNING" "Rsync finished (Code ${rsync_exit_code}) but FAILED to restart registry service (${REGISTRY_SERVICE})!" "7"
fi
echo "Registry service start command issued." | tee -a "${LOG_FILE}"

# 4. Send Final Notification
if [ $rsync_exit_code -eq 0 ]; then
  echo "Rsync finished successfully." | tee -a "${LOG_FILE}"
  # Include tail of log file in success message
  rsync_tail=$(tail -n 10 "${LOG_FILE}")
  send_gotify "[Registry Backup] Success" "Registry backup finished successfully to Hetzner.\n\nRsync Log Tail:\n${rsync_tail}" "5" || echo "Warning: Failed to send Gotify success notification." >&2
else
  echo "Rsync FAILED! Exit code: ${rsync_exit_code}" | tee -a "${LOG_FILE}"
  # Send failure notification with tail of log
  error_msg=$(tail -n 10 "${LOG_FILE}")
  send_gotify "[Registry Backup] FAILED!" "Registry backup FAILED! Rsync Exit code: ${rsync_exit_code}\n\nLog Tail:\n${error_msg}" "8" || echo "Warning: Failed to send Gotify failure notification." >&2
fi

echo "Registry Backup finished at $(date)" | tee -a "${LOG_FILE}"
echo "--------------------" | tee -a "${LOG_FILE}"

exit $rsync_exit_code
