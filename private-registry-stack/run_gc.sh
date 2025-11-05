#!/bin/bash
# Script to run garbage collection on Private Docker Registry.
set -euo pipefail

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

# --- Colours (for terminal output only) ---
if [[ -t 1 ]]; then
    readonly C_RESET='\033[0m'
    readonly C_INFO='\033[0;36m'  # Cyan
    readonly C_WARN='\033[0;33m'  # Yellow
    readonly C_ERR='\033[0;31m'   # Red
    readonly C_OK='\033[0;32m'    # Green
    readonly C_BOLD='\033[1m'
    readonly C_DIM='\033[0;37m'   # Light gray
else
    readonly C_RESET=''
    readonly C_INFO=''
    readonly C_WARN=''
    readonly C_ERR=''
    readonly C_OK=''
    readonly C_BOLD=''
    readonly C_DIM=''
fi

# Default configuration
DRY_RUN=false
QUIET_MODE=false
GC_ARGS=("--delete-untagged")

# --- Helper Functions ---
usage() {
    printf "%b" "Usage: $0 [OPTIONS]\n\nRun garbage collection on Docker Registry container.\n"
    if [[ -t 1 ]]; then
        printf "%b" "\n${C_OK}✓ Safe to run on live registry${C_RESET}\n"
        printf "%b" "${C_WARN}⚠ Always test with --dry-run first${C_RESET}\n"
    fi
    printf "%b" "
OPTIONS:
  --dry-run      Show what would be deleted without actually deleting
  --quiet, -q    Suppress all output except errors
  -h, --help     Show this help message

EXAMPLES:
  $0                 # Run garbage collection
  $0 --dry-run       # Preview what would be deleted
  $0 --quiet         # Quiet mode for cron jobs
"
}

log() {
    if [[ "$QUIET_MODE" == true ]] && [[ "$*" != Error:* ]] && [[ "$*" != Warning:* ]]; then
        return
    fi
    local level_colour="${C_INFO}"
    if [[ "$*" == Error:* ]]; then
        level_colour="${C_ERR}"
    elif [[ "$*" == Warning:* ]]; then
        level_colour="${C_WARN}"
    elif [[ "$*" == *"successfully"* || "$*" == *"finished"* || "$*" == *"Success"* ]]; then
        level_colour="${C_OK}"
    elif [[ "$*" == *"Storage:"* || "$*" == *"GC Summary:"* ]]; then
        level_colour="${C_BOLD}"
    fi
    printf "%b[%s] %s%b\n" "${level_colour}" "$(date +'%Y-%m-%d %H:%M:%S')" "$*" "${C_RESET}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >> "${LOG_FILE}"
}

get_storage_usage() {
    local storage_info
    if storage_info=$(docker exec "${REGISTRY_CONTAINER}" df -h /var/lib/registry 2>/dev/null); then
        echo "$storage_info" | awk 'END{printf "Total: %s, Used: %s, Available: %s (%s used)", $2, $3, $4, $5}'
    else
        echo "Unable to retrieve storage information"
    fi
}

format_storage_info() {
    local storage_info="$1"
    local prefix="$2"
    if [[ -t 1 ]]; then
        printf "%b%s%b %s\n" "${C_BOLD}${C_INFO}" "${prefix}" "${C_RESET}" "${storage_info}"
    else
        printf "%s %s\n" "${prefix}" "${storage_info}"
    fi
}

send_ntfy() {
    local title="$1" message="$2" priority="$3" tags="$4"
    if [[ -z "${NTFY_URL}" || -z "${NTFY_TOPIC}" ]]; then
        log "Error: NTFY_URL or NTFY_TOPIC is not set."
        return 1
    fi
    if [[ -z "${NTFY_TOKEN}" ]]; then
        log "Warning: ntfy token is missing or empty. Skipping notification."
        return 1
    fi
    if ! curl -sf --connect-timeout 5 --max-time 15 \
        -H "Authorization: Bearer ${NTFY_TOKEN}" \
        -H "Title: ${title}" \
        -H "Priority: ${priority}" \
        -H "Tags: ${tags}" \
        -d "${message}" \
        "${NTFY_URL}/${NTFY_TOPIC}" > /dev/null 2>&1; then
        log "Warning: Failed to send ntfy notification."
        return 1
    fi
    return 0
}

format_gc_results() {
    local gc_output="$1"
    local for_notification="$2"  # true/false

    # Extract summary stats
    local blobs_marked blobs_eligible manifests_eligible
    blobs_marked=$(echo "$gc_output" | grep -o '[0-9]\+ blobs marked' | head -1)
    blobs_eligible=$(echo "$gc_output" | grep -o '[0-9]\+ blobs.*eligible' | head -1)
    manifests_eligible=$(echo "$gc_output" | grep -o '[0-9]\+ manifests eligible' | head -1)
    # Build summary
    local summary_parts=()
    [[ -n "$blobs_marked" ]] && summary_parts+=("$blobs_marked")
    if [[ -n "$blobs_eligible" ]] && [[ "$blobs_eligible" != "$blobs_marked" ]]; then
        summary_parts+=("$blobs_eligible")
    fi

    [[ -n "$manifests_eligible" ]] && summary_parts+=("$manifests_eligible")
    local summary
    if [[ ${#summary_parts[@]} -gt 0 ]]; then
        summary=$(IFS=' | '; echo "${summary_parts[*]}")
    else
        summary="No unused items found to delete"
    fi

    # Handle deletion details differently for notifications vs terminal
    local deletions deletion_count
    deletions=$(echo "$gc_output" | grep "Deleting" | head -20)
    deletion_count=$(echo "$gc_output" | grep -c "Deleting" || echo "0")
    if [[ "$for_notification" == "true" ]]; then

        # NOTIFICATION VERSION - Clean and concise
        local details=""
        if [[ "$DRY_RUN" == true ]]; then
            details="Dry run mode: no actual deletions performed"
        elif [[ $deletion_count -eq 0 ]]; then
            details="No files were deleted"
        elif [[ $deletion_count -le 3 ]]; then
            # Show few deletions in notification
            details="Deleted items:"$'\n'"$(echo "$deletions" | sed 's/.*Deleting [^:]*: /• /' | sed 's|/docker/registry/v2/[^/]*/||g')"
        else
            # Summarize many deletions
            details="Successfully deleted $deletion_count items (see logs for full details)"
        fi
        echo "$summary"$'\n\n'"$details"
    else
        if [[ -t 1 ]]; then
            printf "%b📋 GC Results:%b %s\n" "${C_BOLD}${C_OK}" "${C_RESET}" "$summary"
        else
            printf "GC Results: %s\n" "$summary"
        fi

        # Show deletion details in terminal
        if [[ "$DRY_RUN" == false ]] && [[ $deletion_count -gt 0 ]]; then
            if [[ -t 1 ]]; then
                printf "%b🗑️  Deleted %d items:%b\n" "${C_DIM}" "$deletion_count" "${C_RESET}"
                echo "$deletions" | head -10 | while IFS= read -r line; do
                    printf "%b  %s%b\n" "${C_DIM}" "$line" "${C_RESET}"
                done
                [[ $deletion_count -gt 10 ]] && printf "%b  ... and %d more (see log file)%b\n" "${C_DIM}" "$((deletion_count - 10))" "${C_RESET}"
            else
                echo "Deleted $deletion_count items:"
                echo "$deletions" | head -10
                [[ $deletion_count -gt 10 ]] && echo "  ... and $((deletion_count - 10)) more (see log file)"
            fi
        fi
        echo "$summary"
    fi
}

# --- Argument Parsing ---
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                GC_ARGS+=("--dry-run")
                shift
                ;;
            --quiet|-q)
                QUIET_MODE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                printf "%bError: Unknown option '%s'%b\n" "${C_ERR}" "$1" "${C_RESET}" >&2
                echo "Use --help for usage information." >&2
                exit 1
                ;;
        esac
    done
}

# --- Main Logic ---
main() {
    cd "${SCRIPT_DIR}"
    mkdir -p "${LOG_DIR}"

    # Read ntfy token
    if [[ -f "${NTFY_TOKEN_FILE}" ]]; then
        read -r NTFY_TOKEN < "${NTFY_TOKEN_FILE}"
    fi
    local dry_run_msg=""
    if [[ "$DRY_RUN" == true ]]; then
        dry_run_msg=" (Dry Run)"
        if [[ -t 1 ]]; then
            printf "%b--- DRY RUN MODE ENABLED ---%b\n" "${C_WARN}${C_BOLD}" "${C_RESET}"
        else
            echo "--- DRY RUN MODE ENABLED ---"
        fi
    fi
    log "Registry GC process started${dry_run_msg}"
    log "Container: ${REGISTRY_CONTAINER}"

    # Get initial storage
    local storage_before
    storage_before=$(get_storage_usage)
    format_storage_info "$storage_before" "📊 Initial Storage:"

    # Send start notification
    local start_message
    start_message=$(printf "GC process started on %s%s\n\n📊 Storage: %s" "$(hostname)" "$dry_run_msg" "$storage_before")
    send_ntfy "[Registry GC] 🚀 Started${dry_run_msg}" "$start_message" "default" "recycle"

    # Pre-flight checks
    log "Performing pre-flight checks..."
    if ! docker ps -q --filter "name=^/${REGISTRY_CONTAINER}$" --filter "status=running" | grep -q .; then
        log "Error: Registry container '${REGISTRY_CONTAINER}' is not running."
        send_ntfy "[Registry GC] ❌ Failed${dry_run_msg}" "GC failed: Registry container '${REGISTRY_CONTAINER}' is not running on $(hostname)" "high" "warning"
        exit 1
    fi
    log "Running garbage collection..."
    local gc_output gc_exit_code=0

    # Execute garbage collection
    if ! gc_output=$(docker exec -i "${REGISTRY_CONTAINER}" registry garbage-collect "${REGISTRY_CONFIG}" "${GC_ARGS[@]}" 2>&1); then
        gc_exit_code=$?
        log "Error: Garbage collection failed with exit code ${gc_exit_code}"

        # Log detailed error output
        log "--- Failed Command Output ---"
        printf '%s\n' "$gc_output" | tee -a "${LOG_FILE}"
        log "--- End Error Output ---"
        local storage_after_failure
        storage_after_failure=$(get_storage_usage)
        local fail_message
        fail_message=$(printf "GC FAILED on %s%s\n\nExit code: %d\nCheck logs for details.\n\n📊 Storage: %s" "$(hostname)" "$dry_run_msg" "$gc_exit_code" "$storage_after_failure")
        send_ntfy "[Registry GC] ❌ Failed${dry_run_msg}" "$fail_message" "high" "warning"
        exit $gc_exit_code
    fi
    log "Garbage collection completed successfully"

    # Get final storage
    local storage_after
    storage_after=$(get_storage_usage)
    format_storage_info "$storage_after" "📊 Final Storage:"

    # Display detailed results in terminal and logs
    local terminal_summary
    terminal_summary=$(format_gc_results "$gc_output" "false")
    log "GC Summary: $terminal_summary"

    # Send concise notification
    local notification_summary
    notification_summary=$(format_gc_results "$gc_output" "true")
    local message_body
    message_body=$(printf "GC completed successfully on %s%s\n\n%s\n\n📊 Before: %s\n📊 After:  %s" \
        "$(hostname)" "$dry_run_msg" "$notification_summary" "$storage_before" "$storage_after")
    send_ntfy "[Registry GC] ✅ Completed${dry_run_msg}" "$message_body" "default" "white_check_mark"
    log "Registry GC process finished"
    return 0
}

# --- Execution ---
parse_arguments "$@"
main
