#!/bin/bash

# Sscript to run garbage collection on Private Docker Registry.

set -eo pipefail

# --- Configuration ---
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
SECRETS_DIR="${SCRIPT_DIR}/secrets"
NTFY_URL=$(<"${SECRETS_DIR}/ntfy_url")
NTFY_TOPIC=$(<"${SECRETS_DIR}/ntfy_topic")
NTFY_TOKEN_FILE="${SECRETS_DIR}/ntfy_token"
REGISTRY_CONTAINER="registry" # Name of registry container
REGISTRY_CONFIG="/etc/distribution/config.yml"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/gc_$(date +%Y-%m-%d).log"

# --- Script Arguments ---
GC_ARGS=("--delete-untagged")
DRY_RUN_MSG=""
if [[ "$1" == "--dry-run" ]]; then
  GC_ARGS+=("--dry-run")
  DRY_RUN_MSG=" (Dry Run)"
  echo "--- DRY RUN MODE ENABLED ---"
fi

mkdir -p "${LOG_DIR}"

# Read ntfy token once
if [[ -f "${NTFY_TOKEN_FILE}" ]]; then
  read -r NTFY_TOKEN < "${NTFY_TOKEN_FILE}"
fi

# --- Helper Functions ---
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

get_storage_usage() {
  docker exec "${REGISTRY_CONTAINER}" df -h /var/lib/registry | awk 'END{printf "Total: %s, Used: %s, Avail: %s (%s)", $2, $3, $4, $5}'
}

send_ntfy() {
  local title="$1" message="$2" priority="$3" tags="$4"
  if [[ -z "${NTFY_URL}" || -z "${NTFY_TOPIC}" ]]; then log "Error: NTFY_URL or NTFY_TOPIC is not set."; return 1; fi
  if [[ -z "${NTFY_TOKEN}" ]]; then log "Warning: ntfy token is missing or empty. Skipping notification."; return 1; fi

  curl -sf --connect-timeout 5 --max-time 15 \
    -H "Authorization: Bearer ${NTFY_TOKEN}" \
    -H "Title: ${title}" \
    -H "Priority: ${priority}" \
    -H "Tags: ${tags}" \
    -d "${message}" \
    "${NTFY_URL}/${NTFY_TOPIC}" > /dev/null || log "Warning: Failed to send ntfy notification."
}

# --- Main Script Logic ---
main() {
  cd "${SCRIPT_DIR}"

  log "--------------------"

  local storage_before; storage_before=$(get_storage_usage)
  log "Initial Storage: ${storage_before}"

  log "Registry GC process started.${DRY_RUN_MSG}"

  local start_message; start_message=$(printf "GC process started on %s.\n\n📊 Storage: %s" "$(hostname)" "${storage_before}")
  send_ntfy "[Registry GC] 🚀 Start${DRY_RUN_MSG}" "${start_message}" "3" "information"

  # Pre-flight check
  if ! docker ps -q --filter "name=^/${REGISTRY_CONTAINER}$" --filter "status=running" | grep -q .; then
    log "Error: Registry container '${REGISTRY_CONTAINER}' is not running."
    send_ntfy "[Registry GC] ❌ FAILED${DRY_RUN_MSG}" "GC failed: Registry container '${REGISTRY_CONTAINER}' is not running." "4" "high"
    exit 1
  fi

  log "Running garbage collection against the live registry..."
  local gc_output

  # Execute garbage-collect and capture output
  if ! gc_output=$(docker exec -i "${REGISTRY_CONTAINER}" registry garbage-collect "${REGISTRY_CONFIG}" "${GC_ARGS[@]}" 2>&1); then
    local gc_exit_code=$?
    log "ERROR: The garbage collection command failed with exit code ${gc_exit_code}."
    log "--- Start of Failed Command Output ---"
    printf '%s\n' "${gc_output}" | tee -a "${LOG_FILE}"
    log "--- End of Failed Command Output ---"

    local storage_after_failure; storage_after_failure=$(get_storage_usage)
    local fail_message; fail_message=$(printf "GC run FAILED on %s!\n\nCheck logs for details.\n\n📊 Storage: %s" "$(hostname)" "${storage_after_failure}")
    send_ntfy "[Registry GC] ❌ FAILED${DRY_RUN_MSG}" "${fail_message}" "4" "high"
    exit $gc_exit_code
  fi

  log "Garbage collection command finished successfully."

  local storage_after; storage_after=$(get_storage_usage)
  log "Final Storage: ${storage_after}"

  local final_summary

  final_summary=$(echo "$gc_output" | grep -E 'blob files removed|manifest files removed|blobs marked|manifests eligible' | paste -sd ' | ' -)

  if [ -z "$final_summary" ]; then
    final_summary="No unused items were found to delete."
  else
    if [[ -z "$DRY_RUN_MSG" ]]; then
      echo "--- Cleanup Details ---"
      echo "$gc_output" | grep "Deleting"
      echo "-----------------------"
    fi
  fi

  log "GC Summary: ${final_summary}"
  message_body=$(printf "GC run finished on %s.\n\n%s\n\n📊 Before: %s\n📊 After:  %s" "$(hostname)" "${final_summary}" "${storage_before}" "${storage_after}")
  send_ntfy "[Registry GC] ✅ Success${DRY_RUN_MSG}" "${message_body}" "3" "white_check_mark,information"

  log "Registry GC process finished."
  log "--------------------"
}

# Run the main function
main
