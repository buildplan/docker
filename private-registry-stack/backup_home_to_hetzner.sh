### save this in /usr/local/sbin/
### create a cron job like: 5 2,14 * * * /usr/local/sbin/backup_home_to_hetzner.sh

#!/bin/bash
set -euo pipefail # Exit on error, undefined variable, or pipe failure

# --- Script Configuration ---
LOG_FILE="/var/log/hetzner_backup.log"
REMOTE_USER="u444444-sub4"
REMOTE_HOST="u444444.your-storagebox.de"
REMOTE_BASE_PATH="/home/user" # Base path on your Hetzner storage box
SSH_PORT="23"
SSH_KEY_PATH="/root/.ssh/id_ed25519" # Path to root's private key for Hetzner

# --- NTFY Configuration ---
NTFY_SERVER_URL="https://ntfy.alisufyan.cloud"
NTFY_TOPIC="my_registry"
NTFY_ACCESS_TOKEN="tk_xxxxxxxxxxxxxxxxxxxxx" # <<< IMPORTANT: REPLACE THIS!
# --- End NTFY Configuration ---

# Ensure log file exists and has secure permissions (should be run as root)
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
# Optional: Rotate log file (simple rotation for last 5 logs)
mv "${LOG_FILE}.4" "${LOG_FILE}.5" 2>/dev/null || true
mv "${LOG_FILE}.3" "${LOG_FILE}.4" 2>/dev/null || true
mv "${LOG_FILE}.2" "${LOG_FILE}.3" 2>/dev/null || true
mv "${LOG_FILE}.1" "${LOG_FILE}.2" 2>/dev/null || true
mv "${LOG_FILE}" "${LOG_FILE}.1" 2>/dev/null || true
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

# --- Logging Function ---
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE" # Output to console and logfile
}

# --- NTFY Notification Function ---
# Usage: send_ntfy "priority" "Title" "Message" "Optional_Comma_Separated_Tags"
send_ntfy() {
    local ntfy_priority="$1"
    local ntfy_title="$2"
    local ntfy_message="$3"
    local ntfy_tags_csv="$4" # Optional comma-separated tags

    if [ -z "$NTFY_ACCESS_TOKEN" ] || [ "$NTFY_ACCESS_TOKEN" == "YOUR_ACTUAL_NTFY_ACCESS_TOKEN_HERE" ]; then
        log_message "WARNING: NTFY_ACCESS_TOKEN is not set or is default. Skipping ntfy notification."
        return
    fi

    if ! command -v curl &> /dev/null; then
        log_message "ERROR: curl command not found. Cannot send ntfy notification."
        return
    fi

    local ntfy_full_url="${NTFY_SERVER_URL}/${NTFY_TOPIC}"
    
    # Construct curl command
    local curl_cmd=(
        curl
        -sS # Silent but show errors
        -X POST
        -H "Authorization: Bearer $NTFY_ACCESS_TOKEN"
        -H "Title: $ntfy_title"
        -H "Priority: $ntfy_priority"
    )

    if [ -n "$ntfy_tags_csv" ]; then
        IFS=',' read -ra TAG_ARRAY <<< "$ntfy_tags_csv"
        for tag in "${TAG_ARRAY[@]}"; do
            # Trim whitespace (though unlikely needed if calling function correctly)
            trimmed_tag=$(echo "$tag" | xargs) 
            if [ -n "$trimmed_tag" ]; then
                curl_cmd+=(-H "Tags: $trimmed_tag")
            fi
        done
    fi

    curl_cmd+=(-d "$ntfy_message" "$ntfy_full_url")

    log_message "Attempting to send ntfy notification: Title='$ntfy_title', Priority='$ntfy_priority', Tags='$ntfy_tags_csv'"
    
    if "${curl_cmd[@]}"; then
        log_message "Ntfy notification sent successfully."
    else
        log_message "ERROR: Failed to send ntfy notification. Curl exit code: $?. Check curl output if any."
    fi
}
# --- End NTFY Notification Function ---

# --- Main Backup Logic ---
log_message "===== Starting Hetzner backup run ====="
send_ntfy "default" "Backup Started: user" "Automated backup to Hetzner Storage Box has commenced." "hourglass_flowing_sand"

overall_backup_status="SUCCESS" # Assume success initially
error_details=""

# --- Part 1: Backup n2ali's general home directory files ---
HOME_EXCLUDES=(
    --exclude '.ssh/'
    --exclude '.docker/'
    --exclude '.cache/'
    --exclude '.config/pulse/'
    --exclude '.dbus/'
    --exclude '.gradle/caches/'
    --exclude '.local/share/Trash/'
    --exclude '.npm/'
    --exclude '.nv/'
    --exclude '.wget-hsts'
    --exclude '*~'
    --exclude '*.bak'
    --exclude '*.swp'
    --exclude 'snap/'
    # Exclude root-owned Docker volume data from this rsync pass; they'll be handled in Part 2.
    --exclude 'private-registry-setup/docker-registry/data/'
    --exclude 'private-registry-setup/caddy/data/'
    --exclude 'private-registry-setup/caddy/config/'
    --exclude 'private-registry-setup/prometheus/prometheus_data/'
    --exclude 'private-registry-setup/grafana/grafana-data/'
    --exclude 'private-registry-setup/crowdsec/data/'
    --exclude 'private-registry-setup/crowdsec/config/'
    --exclude 'private-registry-setup/portainer_data/'
    # Exclude the main backup log file from this specific rsync to avoid recursion if it's in /home/n2ali
    # This script logs to /var/log/hetzner_backup.log so this isn't strictly needed here for that,
    # but good if n2ali had a user-level log of the same name.
    # --exclude '/home/n2ali/hetzner_backup.log' # Better to use absolute path if script is always in same place
)

log_message "Backing up /home/n2ali/ (general files)..."
if rsync -a --delete --partial --checksum \
    "${HOME_EXCLUDES[@]}" \
    -e "ssh -p $SSH_PORT -i $SSH_KEY_PATH" \
    /home/n2ali/ "$REMOTE_USER@$REMOTE_HOST:$REMOTE_BASE_PATH/n2ali_home_general/" >> "$LOG_FILE" 2>&1; then
    log_message "General /home/n2ali/ backup completed successfully."
else
    rsync_exit_code=$?
    log_message "ERROR: General /home/n2ali/ backup failed with rsync exit code $rsync_exit_code."
    overall_backup_status="FAILED"
    error_details+="General /home/n2ali/ backup failed (exit code $rsync_exit_code).\n"
fi

# --- Part 2: Backup specific Docker application data directories ---
APP_DATA_BASE_PATH="/home/n2ali/private-registry-setup"
APP_DATA_DIRS=(
    "docker-registry/data"
    "caddy/data"
    "caddy/config"
    "prometheus/prometheus_data"
    "grafana/grafana-data"
    "crowdsec/config"
    "crowdsec/data"
    "portainer_data"
)

log_message "Backing up specific Docker application data directories..."
for app_data_dir in "${APP_DATA_DIRS[@]}"; do
    SOURCE_PATH="$APP_DATA_BASE_PATH/$app_data_dir"
    REMOTE_DIR_NAME=$(echo "$app_data_dir" | tr '/' '_')

    if [ -d "$SOURCE_PATH" ]; then
        log_message "Backing up $SOURCE_PATH..."
        if rsync -a --delete --partial --checksum \
            -e "ssh -p $SSH_PORT -i $SSH_KEY_PATH" \
            "$SOURCE_PATH/" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_BASE_PATH/private_registry_app_data/$REMOTE_DIR_NAME/" >> "$LOG_FILE" 2>&1; then
            log_message "Backup of $SOURCE_PATH completed successfully."
        else
            rsync_exit_code=$?
            log_message "ERROR: Backup of $SOURCE_PATH failed with rsync exit code $rsync_exit_code."
            overall_backup_status="FAILED"
            error_details+="Backup of $SOURCE_PATH failed (exit code $rsync_exit_code).\n"
        fi
    else
        log_message "WARNING: Application data path $SOURCE_PATH does not exist. Skipping."
        # You might want to consider this a failure or send a specific warning notification
        # overall_backup_status="FAILED" 
        # error_details+="Path $SOURCE_PATH not found.\n"
    fi
done

# --- Final Notification ---
if [ "$overall_backup_status" == "SUCCESS" ]; then
    log_message "Hetzner backup run finished successfully."
    send_ntfy "default" "Backup SUCCESS: user" "Automated backup to Hetzner Storage Box completed successfully." "white_check_mark,rocket"
else
    log_message "Hetzner backup run finished with ERRORS. See details above."
    send_ntfy "urgent" "Backup FAILED: user" "$(echo -e "One or more parts of the user backup failed.\nDetails:\n$error_details\nCheck $LOG_FILE on user for full logs.")" "x,siren"
fi

log_message "===== Hetzner backup run ended ====="
echo "" >> "$LOG_FILE" # Add a blank line for readability between runs

exit 0
