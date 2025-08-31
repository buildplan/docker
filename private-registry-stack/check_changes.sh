#!/bin/bash

# This script checks any changes to registry and reports via ntfy.

set -euo pipefail

# --- Configuration ---
PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
SECRETS_DIR="${PROJECT_DIR}/secrets"
REGCTL_CMD="/usr/local/bin/regctl"
REGISTRY_HOST=$(<"${SECRETS_DIR}/registry_host")
LOG_DIR="${PROJECT_DIR}/logs"
STATE_FILE="${LOG_DIR}/registry_state_detailed.txt"
TEMP_FILE="${LOG_DIR}/registry_state_detailed.tmp"
SCRIPT_LOG_FILE="${LOG_DIR}/check_registry_changes.log"
NTFY_URL=$(<"${SECRETS_DIR}/ntfy_url")
NTFY_TOPIC=$(<"${SECRETS_DIR}/ntfy_topic")
NTFY_TOKEN==$(<"${SECRETS_DIR}/ntfy_token")
HOSTNAME=$(hostname -s)

# --- Helper Functions ---
log() {
    printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*"
}
send_ntfy() {
    local title="$1" message="$2" priority="$3" tags="$4"
    local auth_header=()
    if [[ -f "${NTFY_TOKEN}" ]]; then
        local token
        read -r token < "${NTFY_TOKEN}"
        if [[ -n "$token" ]]; then
            auth_header=(-H "Authorization: Bearer ${token}")
        fi
    fi
    curl -sf --connect-timeout 5 --max-time 10 \
        "${auth_header[@]}" \
        -H "Title: ${title}" \
        -H "Priority: ${priority}" \
        -H "Tags: ${tags}" \
        -H "Markdown: yes" \
        -d "${message}" \
        "${NTFY_URL}/${NTFY_TOPIC}"
}
generate_detailed_state() {
    local output_file="$1"
    local repos
    if ! repos=$("${REGCTL_CMD}" repo ls "${REGISTRY_HOST}" 2>/dev/null); then
        log "Error: Failed to list repositories from ${REGISTRY_HOST}."
        return 1
    fi
    echo "$repos" | while IFS= read -r repo; do
        [[ -z "$repo" ]] && continue
        "${REGCTL_CMD}" tag ls "${REGISTRY_HOST}/${repo}" 2>/dev/null | while IFS= read -r tag; do
            [[ -z "$tag" ]] && continue
            local digest
            digest=$("${REGCTL_CMD}" image digest "${REGISTRY_HOST}/${repo}:${tag}" 2>/dev/null)
            [[ -z "$digest" ]] && continue
            echo "${repo}:${tag} ${digest}"
        done
    done | sort > "${output_file}"
    return "${PIPESTATUS[0]}"
}
format_diff_changes() {
    local diff_output="$1"
    local added_lines
    added_lines=$(echo "$diff_output" | grep '^>' | sed 's/> //')
    local removed_lines
    removed_lines=$(echo "$diff_output" | grep '^<' | sed 's/< //')
    local changed_repos
    changed_repos=$( (echo "$added_lines"; echo "$removed_lines") | grep ':' | sed 's/:.*//' | sort -u)
    local new_repos=()
    local removed_repos=()
    local updated_repos=()
    local updated_details=""
    local repo
    for repo in $changed_repos; do
        [[ -z "$repo" ]] && continue
        if echo "$added_lines" | grep -q "^${repo}:" && ! echo "$removed_lines" | grep -q "^${repo}:"; then
            new_repos+=("$repo")
        elif ! echo "$added_lines" | grep -q "^${repo}:" && echo "$removed_lines" | grep -q "^${repo}:"; then
            removed_repos+=("$repo")
        else
            updated_repos+=("$repo")
            updated_details+="* **${repo}**\n\`\`\`diff\n"
            repo_added_tags=$(echo "$added_lines" | grep "^${repo}:" | sed "s/^${repo}:/+/g")
            repo_removed_tags=$(echo "$removed_lines" | grep "^${repo}:" | sed "s/^${repo}:/-/g")
            updated_details+="${repo_added_tags}\n"
            updated_details+="${repo_removed_tags}\n"
            updated_details+="\`\`\`\n"
        fi
    done
    local message
    message=$(printf "*Summary of changes on %s:*\n" "$HOSTNAME")
    message+=$(printf "* 🚀 **New:** %s repos\n" "${#new_repos[@]}")
    message+=$(printf "* 🗑️ **Removed:** %s repos\n" "${#removed_repos[@]}")
    message+=$(printf "* ✨ **Updated:** %s repos\n" "${#updated_repos[@]}")
    if [ ${#new_repos[@]} -gt 0 ]; then
        message+="\n\n### 🚀 New Repositories\n\`\`\`diff\n"
        for repo in "${new_repos[@]}"; do
            message+="+ ${repo}\n"
        done
        message+="\`\`\`"
    fi
    if [ ${#removed_repos[@]} -gt 0 ]; then
        message+="\n\n### 🗑️ Removed Repositories\n\`\`\`diff\n"
        for repo in "${removed_repos[@]}"; do
            message+="- ${repo}\n"
        done
        message+="\`\`\`"
    fi
    if [ ${#updated_repos[@]} -gt 0 ]; then
        message+="\n\n### ✨ Updated Repositories\n${updated_details}"
    fi
    printf "%b" "$message"
}
# --- Main Logic ---
main() {
    log "Starting detailed registry check..."
    trap 'rm -f "$TEMP_FILE"' EXIT

    if ! generate_detailed_state "$TEMP_FILE"; then
        log "Error: Failed to generate detailed repository state."
        send_ntfy "[Registry Check] ERROR" "Failed to generate detailed state from ${REGISTRY_HOST} on ${HOSTNAME}." "urgent" "x"
        return 1
    fi
    if [ -f "$STATE_FILE" ]; then
        if ! diff_output=$(diff "$STATE_FILE" "$TEMP_FILE" 2>/dev/null); then
            log "Change detected in registry repositories!"
            local formatted_message
            formatted_message=$(format_diff_changes "$diff_output")
            printf "Registry content changed:\n%s\n" "${formatted_message}"
            send_ntfy "[Registry] Repos Changed" "${formatted_message}" "high" "package"
            mv "$TEMP_FILE" "$STATE_FILE"
        else
            log "No changes detected."
        fi
    else
        log "No previous state file found. Saving current state."
        mv "$TEMP_FILE" "$STATE_FILE"
        send_ntfy "[Registry Check] Initialized" "Initial detailed repository state saved for ${HOSTNAME}." "default" "rocket"
    fi
    log "Check complete."
    return 0
}
# --- Execution ---
mkdir -p "${LOG_DIR}"
main "$@" 2>&1 | tee -a "${SCRIPT_LOG_FILE}"
exit "${PIPESTATUS[0]}"
