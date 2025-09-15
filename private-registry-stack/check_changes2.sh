#!/bin/bash
# This script checks any changes to registry and reports via ntfy.
set -euo pipefail

# --- Configuration ---
PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
SECRETS_DIR="${PROJECT_DIR}/secrets"
REGCTL_CMD="/usr/local/bin/regctl"
REGISTRY_HOST=$(<"${SECRETS_DIR}/registry_host")
LOG_DIR="${PROJECT_DIR}/logs"
STATE_FILE="${LOG_DIR}/.check_changes_state"
TEMP_FILE="${LOG_DIR}/registry_state_detailed.tmp"
SCRIPT_LOG_FILE="${LOG_DIR}/check_changes.log"
NTFY_URL=$(<"${SECRETS_DIR}/ntfy_url")
NTFY_TOPIC=$(<"${SECRETS_DIR}/ntfy_topic")
NTFY_TOKEN=$(<"${SECRETS_DIR}/ntfy_token")
HOSTNAME=$(hostname -s)

# --- Colours (for terminal output only) ---
if [[ -t 1 ]]; then
    readonly C_RESET='\033[0m'
    readonly C_INFO='\033[0;36m'  # Cyan
    readonly C_WARN='\033[0;33m'  # Yellow
    readonly C_ERR='\033[0;31m'   # Red
    readonly C_OK='\033[0;32m'    # Green
    readonly C_BOLD='\033[1m'
else
    readonly C_RESET=''
    readonly C_INFO=''
    readonly C_WARN=''
    readonly C_ERR=''
    readonly C_OK=''
    readonly C_BOLD=''
fi

# Default configuration
MESSAGE_STYLE="detailed"
QUIET_MODE=false

# --- Helper Functions ---
usage() {
    printf "%b" "Usage: $0 [OPTIONS]\n\nMonitor container registry for changes and send notifications via ntfy.\n"
    if [[ -t 1 ]]; then
        printf "%b" "\n${C_OK}+ New repositories${C_RESET}\n"
        printf "%b" "${C_ERR}- Removed repositories${C_RESET}\n"
        printf "%b" "${C_WARN}~ Updated repositories${C_RESET}\n"
    fi
    printf "%b" "
OPTIONS:
  --detailed     Send detailed change information (default)
  --summary      Send summary of changes only
  --mini         Send minimal notification
  --minimal      Same as --mini
  --quiet, -q    Suppress all output except errors
  -h, --help     Show this help message
EXAMPLES:
  $0                 # Default detailed notifications
  $0 --summary       # Summary notifications only
  $0 --mini          # Minimal notifications
  $0 --quiet         # Quiet mode, only errors are logged
"
}

log() {
    # Skip logging in quiet mode unless it's an error
    if [[ "$QUIET_MODE" == true ]] && [[ "$*" != Error:* ]]; then
        return
    fi
    local level_colour="${C_INFO}"
    if [[ "$*" == Error:* ]]; then
        level_colour="${C_ERR}"
    elif [[ "$*" == Change\ detected* || "$*" == No\ previous\ state\ file\ found.* ]]; then
        level_colour="${C_WARN}"
    elif [[ "$*" == No\ changes\ detected.* || "$*" == Check\ complete.* ]]; then
        level_colour="${C_OK}"
    fi
    printf "%b[%s] %s%b\n" "${level_colour}" "$(date +'%Y-%m-%d %H:%M:%S')" "$*" "${C_RESET}"
}

send_ntfy() {
    local title="$1" message="$2" priority="$3" tags="$4"
    local auth_header=()
    if [[ -n "${NTFY_TOKEN}" ]]; then
        auth_header=(-H "Authorization: Bearer ${NTFY_TOKEN}")
    fi
    if ! curl -sf --connect-timeout 5 --max-time 10 \
        "${auth_header[@]}" \
        -H "Title: ${title}" \
        -H "Priority: ${priority}" \
        -H "Tags: ${tags}" \
        -d "${message}" \
        "${NTFY_URL}/${NTFY_TOPIC}"; then
        log "Error: Failed to send ntfy notification to ${NTFY_URL}/${NTFY_TOPIC}"
        return 1
    fi
    return 0
}

generate_detailed_state() {
    local output_file="$1"
    local repos
    if ! repos=$("${REGCTL_CMD}" repo ls "${REGISTRY_HOST}" 2>/dev/null); then
        log "Error: Failed to list repositories from ${REGISTRY_HOST}."
        return 1
    fi
    local -a state_lines
    mapfile -t state_lines < <(
        echo "$repos" | while IFS= read -r repo; do
            [[ -z "$repo" ]] && continue
            "${REGCTL_CMD}" tag ls "${REGISTRY_HOST}/${repo}" 2>/dev/null | while IFS= read -r tag; do
                [[ -z "$tag" ]] && continue
                local digest
                digest=$("${REGCTL_CMD}" image digest "${REGISTRY_HOST}/${repo}:${tag}" 2>/dev/null)
                [[ -z "$digest" ]] && continue
                echo "${repo}:${tag} ${digest}"
            done
        done
    )
    if [[ "${PIPESTATUS[0]}" -ne 0 ]]; then
        return 1
    fi
    printf "%s\n" "${state_lines[@]}" | sort > "${output_file}"
    return "${PIPESTATUS[1]}"
}

format_diff_changes() {
    local diff_output="$1"
    local added_lines removed_lines
    added_lines=$(echo "$diff_output" | grep --color=never '^>' | sed 's/> //')
    removed_lines=$(echo "$diff_output" | grep --color=never '^<' | sed 's/< //')
    local changed_repos_list
    changed_repos_list=$( (echo "$added_lines"; echo "$removed_lines") | grep --color=never ':' | sed 's/:.*//' | sort -u)
    local changed_repos=()
    readarray -t changed_repos < <(printf '%s\n' "${changed_repos_list}")
    local new_repos=()
    local removed_repos=()
    local updated_repos=()
    local repo
    for repo in "${changed_repos[@]}"; do
        [[ -z "$repo" ]] && continue
        if echo "$added_lines" | grep -q "^${repo}:" && ! echo "$removed_lines" | grep -q "^${repo}:"; then
            new_repos+=("$repo")
        elif ! echo "$added_lines" | grep -q "^${repo}:" && echo "$removed_lines" | grep -q "^${repo}:"; then
            removed_repos+=("$repo")
        else
            updated_repos+=("$repo")
        fi
    done
    local message="Registry Changes on ${HOSTNAME}

SUMMARY:
New: ${#new_repos[@]} repos
Removed: ${#removed_repos[@]} repos
Updated: ${#updated_repos[@]} repos"
    if [ ${#new_repos[@]} -gt 0 ]; then
        message+="

NEW REPOS:"
        for repo in "${new_repos[@]}"; do
            message+="
+ ${repo}"
        done
    fi
    if [ ${#removed_repos[@]} -gt 0 ]; then
        message+="

REMOVED REPOS:"
        for repo in "${removed_repos[@]}"; do
            message+="
- ${repo}"
        done
    fi
    if [ ${#updated_repos[@]} -gt 0 ]; then
        message+="

UPDATED REPOS:"
        for repo in "${updated_repos[@]}"; do
            local added_count=$(echo "$added_lines" | grep -c "^${repo}:" || true)
            local removed_count=$(echo "$removed_lines" | grep -c "^${repo}:" || true)
            message+="
~ ${repo} (+${added_count}/-${removed_count} tags)"
        done
    fi
    printf "%s" "$message"
}

format_summary_only() {
    local diff_output="$1"
    local added_lines removed_lines
    added_lines=$(echo "$diff_output" | grep --color=never '^>' | sed 's/> //')
    removed_lines=$(echo "$diff_output" | grep --color=never '^<' | sed 's/< //')
    local changed_repos_count
    changed_repos_count=$( (echo "$added_lines"; echo "$removed_lines") | grep --color=never ':' | sed 's/:.*//' | sort -u | wc -l)
    local total_tag_changes=$(( $(echo "$added_lines" | wc -l) + $(echo "$removed_lines" | wc -l) ))
    printf "Registry Update on %s\n\n%d repositories changed\n%d total tag changes" \
        "$HOSTNAME" "$changed_repos_count" "$total_tag_changes"
}

format_minimal() {
    local diff_output="$1"
    local added_lines removed_lines
    added_lines=$(echo "$diff_output" | grep --color=never '^>' | sed 's/> //')
    removed_lines=$(echo "$diff_output" | grep --color=never '^<' | sed 's/< //')
    local changed_repos_count
    changed_repos_count=$( (echo "$added_lines"; echo "$removed_lines") | grep --color=never ':' | sed 's/:.*//' | sort -u | wc -l)
    printf "Registry changes on %s: %d repos updated" "$HOSTNAME" "$changed_repos_count"
}

# --- Argument Parsing ---
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --detailed)
                MESSAGE_STYLE="detailed"
                shift
                ;;
            --summary)
                MESSAGE_STYLE="summary"
                shift
                ;;
            --mini|--minimal)
                MESSAGE_STYLE="minimal"
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
    log "Starting detailed registry check (mode: ${MESSAGE_STYLE})..."
    trap 'rm -f "$TEMP_FILE"' EXIT
    if ! generate_detailed_state "$TEMP_FILE"; then
        log "Error: Failed to generate detailed repository state."
        send_ntfy "Registry Error on ${HOSTNAME}" "Failed to check ${REGISTRY_HOST} on ${HOSTNAME}" "urgent" "warning"
        return 1
    fi
    if [ -f "$STATE_FILE" ]; then
        if ! diff_output=$(diff --color=never "$STATE_FILE" "$TEMP_FILE" 2>/dev/null); then
            log "Change detected in registry repositories!"
            local formatted_message
            case "${MESSAGE_STYLE}" in
                "summary")
                    formatted_message=$(format_summary_only "$diff_output")
                    ;;
                "minimal")
                    formatted_message=$(format_minimal "$diff_output")
                    ;;
                *)
                    formatted_message=$(format_diff_changes "$diff_output")
                    ;;
            esac
            local coloured_output
            coloured_output=$(printf "%s" "$formatted_message" | sed -e "s/^+ /${C_OK}+ /" -e "s/^- /${C_ERR}- /" -e "s/^~ /${C_WARN}~ /" -e "s/$/${C_RESET}/")
            printf "Registry content changed:\n%b\n" "${coloured_output}"
            send_ntfy "Registry Changes on ${HOSTNAME}" "${formatted_message}" "high" "package"
            mv "$TEMP_FILE" "$STATE_FILE"
        else
            log "No changes detected."
        fi
    else
        log "No previous state file found. Saving current state."
        mv "$TEMP_FILE" "$STATE_FILE"
        send_ntfy "Registry Init" "Started monitoring ${REGISTRY_HOST} on ${HOSTNAME}" "default" "rocket"
    fi
    log "Check complete."
    return 0
}

# --- Execution ---
parse_arguments "$@"
mkdir -p "${LOG_DIR}"
main 2>&1 | tee -a "${SCRIPT_LOG_FILE}"
exit "${PIPESTATUS[0]}"
