#!/bin/bash
#
# GeoLite2 Database Auto-Updater
#
# Description: This script checks for updates to the GeoLite2-Country database from
# the node-geolite2-redist GitHub repository, downloads it if it's newer,
# places it in a specified directory, and sends notifications on success/failure.
#
# Requirements: curl, tar, find, sha256sum, chown, chmod, mv, jq
# Usage: Configure the DEST_DIR variable and notification settings, then run the script.
#
# Setup a cron job for periodic execution.
# For example, (Wed/Sat 06:30 to align with upstream release schedule:
# 30 6 * * 3,6 /path/to/geolite2-update.sh

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

# --- Configuration ---
DEST_DIR="/path/to/your/config/" # <-- Change this to actual config directory.
DB_FILENAME="GeoLite2-Country.mmdb" # Final db name.
DOWNLOAD_URL="https://github.com/GitSquared/node-geolite2-redist/raw/refs/heads/master/redist/GeoLite2-Country.tar.gz"
LOG_FILE="/var/log/geolite2-update.log" # Log file path
LOG_MAX_LINES="500"

# ntfy
NTFY_ENABLED=false
NTFY_TOPIC="your_ntfy_topic_here" # <-- Change this
NTFY_SERVER="https://ntfy.sh"     # Default server
NTFY_TOKEN=""                     # <-- Add token

# Discord
DISCORD_ENABLED=false
DISCORD_WEBHOOK_URL="your_webhook_url_here" # <-- Change this

# --- Functions ---
IONICE=$(command -v ionice || true)
NICE=$(command -v nice || true)

run_io() {
    if [ -n "$IONICE" ]; then
        ionice -c2 -n7 "$@"
    else
        "$@"
    fi
}

run_cpu() {
    if [ -n "$NICE" ]; then
        nice -n 10 "$@"
    else
        "$@"
    fi
}

log_message() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] - $message" | tee -a "$LOG_FILE"

    if command -v systemd-cat > /dev/null 2>&1; then
        echo "$message" | systemd-cat -t "geolite2-update" -p "${level,,}"
    fi
}

send_notification_ntfy() {
    local title="$1"
    local message="$2"
    local priority="${3:-3}" # Default=3

    if [ "$NTFY_ENABLED" != true ]; then
        return
    fi

    if [ "$NTFY_TOPIC" == "your_ntfy_topic_here" ] || [ -z "$NTFY_TOPIC" ]; then
        log_message "WARNING" "ntfy notification enabled but NTFY_TOPIC is not set."
        return
    fi

    local auth_args=()
    if [ -n "$NTFY_TOKEN" ]; then
        auth_args=(-H "Authorization: Bearer $NTFY_TOKEN")
    fi

    log_message "INFO" "Sending ntfy notification to $NTFY_TOPIC..."

    if ! curl -LsSf \
        -H "Title: $title" \
        -H "Tags: database" \
        -H "Priority: $priority" \
        "${auth_args[@]}" \
        -d "$message (Host: $(hostname))" \
        "$NTFY_SERVER/$NTFY_TOPIC" &>/dev/null; then
        log_message "WARNING" "Failed to send ntfy notification."
    fi
}

send_notification_discord() {
    local title="$1"
    local description="$2"
    local color="${3:-3066993}" # Green by default

    if [ "$DISCORD_ENABLED" != true ]; then
        return
    fi

    if [ "$DISCORD_WEBHOOK_URL" == "your_webhook_url_here" ] || [ -z "$DISCORD_WEBHOOK_URL" ]; then
        log_message "WARNING" "Discord notification enabled but DISCORD_WEBHOOK_URL is not set."
        return
    fi

    log_message "INFO" "Sending Discord notification..."
    local server_name timestamp
    server_name=$(hostname)
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # --- UPDATED: Create JSON payload safely using jq ---
    JSON_PAYLOAD=$(jq -n \
                      --arg title "$title" \
                      --arg description "$description" \
                      --arg color "$color" \
                      --arg server_name "$server_name" \
                      --arg timestamp "$timestamp" \
                      '{
                          "username": "GeoLite2 Updater",
                          "avatar_url": "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/geo-guessr.png",
                          "embeds": [
                            {
                              "title": $title,
                              "description": $description,
                              "color": ($color | tonumber),
                              "footer": {
                                "text": ("Host: " + $server_name)
                              },
                              "timestamp": $timestamp
                            }
                          ]
                        }')
    
    # Fallback in case jq fails
    if [ -z "$JSON_PAYLOAD" ]; then
        log_message "WARNING" "Failed to generate Discord JSON payload with jq."
        return
    fi
    # --- End update ---

    if ! curl -LsSf -H "Content-Type: application/json" -d "$JSON_PAYLOAD" "$DISCORD_WEBHOOK_URL" &>/dev/null; then
        log_message "WARNING" "Failed to send Discord notification."
    fi
}

send_failure_notification() {
    local message="$1"
    local title="GeoLite2 Update FAILED"
    local discord_color=15158332 # Red

    send_notification_ntfy "$title" "$message" 4
    send_notification_discord "$title" "$message" "$discord_color"
}

send_success_notification() {
    local message="$1"
    local title="GeoLite2 DB Updated"
    local discord_color=3066993 # Green

    send_notification_ntfy "$title" "$message" 3
    send_notification_discord "$title" "$message" "$discord_color"
}

send_checkin_notification() {
    local message="$1"
    local title="GeoLite2 Check Complete"
    local discord_color=9807270 # Gray

    send_notification_ntfy "$title" "$message" 2
    send_notification_discord "$title" "$message" "$discord_color"
}

# shellcheck disable=SC2329
cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
        log_message "INFO" "Cleaned up temporary directory: $TMP_DIR"
    fi
}

# --- Execution ---
if [ -f "$LOG_FILE" ] && [ "$(wc -l < "$LOG_FILE")" -gt "$LOG_MAX_LINES" ]; then
    tail -n "$LOG_MAX_LINES" "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] - Log file truncated to last $LOG_MAX_LINES lines." >> "$LOG_FILE"
fi

trap cleanup EXIT

log_message "INFO" "Starting GeoLite2 database update script."

# 1. Validate Configuration and Prerequisites
if [ "$NTFY_ENABLED" = true ]; then
    if [ "$NTFY_TOPIC" == "your_ntfy_topic_here" ] || [ -z "$NTFY_TOPIC" ]; then
        err_msg="ntfy is enabled but NTFY_TOPIC is not configured. Disabling ntfy for this run."
        log_message "WARNING" "$err_msg"
        NTFY_ENABLED=false
    elif [[ ! "$NTFY_TOPIC" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        err_msg="NTFY_TOPIC contains invalid characters. Disabling ntfy for this run."
        log_message "WARNING" "$err_msg"
        NTFY_ENABLED=false
    else
        log_message "INFO" "ntfy notification validated: topic=$NTFY_TOPIC"
    fi
fi

if [ "$DISCORD_ENABLED" = true ]; then
    if [ "$DISCORD_WEBHOOK_URL" == "your_webhook_url_here" ] || [ -z "$DISCORD_WEBHOOK_URL" ]; then
        err_msg="Discord is enabled but DISCORD_WEBHOOK_URL is not configured. Disabling Discord for this run."
        log_message "WARNING" "$err_msg"
        DISCORD_ENABLED=false
    elif [[ ! "$DISCORD_WEBHOOK_URL" =~ ^https://discord(app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+$ ]]; then
        err_msg="DISCORD_WEBHOOK_URL does not appear to be a valid Discord webhook URL. Disabling Discord for this run."
        log_message "WARNING" "$err_msg"
        DISCORD_ENABLED=false
    else
        log_message "INFO" "Discord notification validated."
    fi
fi

if [[ "$DEST_DIR" == "/path/to/your/config/" ]]; then
    err_msg="Configuration needed: Set DEST_DIR variable to your actual config directory."
    log_message "ERROR" "$err_msg"
    send_failure_notification "$err_msg"
    exit 1
fi

[[ "${DEST_DIR}" != */ ]] && DEST_DIR="${DEST_DIR}/"

if [ ! -d "$DEST_DIR" ]; then
    err_msg="Destination directory does not exist: $DEST_DIR"
    log_message "ERROR" "$err_msg"
    send_failure_notification "$err_msg"
    exit 1
fi

if [ ! -w "$DEST_DIR" ]; then
    err_msg="Destination directory is not writable: $DEST_DIR"
    log_message "ERROR" "$err_msg"
    send_failure_notification "$err_msg"
    exit 1
fi

for cmd in curl tar find sha256sum chown chmod mv jq; do
    if ! command -v "$cmd" > /dev/null 2>&1; then
        err_msg="Required command '$cmd' is not installed."
        log_message "ERROR" "$err_msg"
        send_failure_notification "$err_msg"
        exit 1
    fi
done

# 2. Create a temporary directory and check disk space
TMP_DIR=$(mktemp -d)
log_message "INFO" "Created temporary directory at $TMP_DIR"

need_kb=51200
avail_tmp=$(df -kP "$TMP_DIR" | awk 'NR==2{print $4}')
avail_dest=$(df -kP "$DEST_DIR" | awk 'NR==2{print $4}')
if [ "$avail_tmp" -lt "$need_kb" ] || [ "$avail_dest" -lt "$need_kb" ]; then
  err_msg="Insufficient free space (need ~${need_kb} KB) in TMP or DEST"
  log_message "ERROR" "$err_msg"
  send_failure_notification "$err_msg"
  exit 1
fi

# 3. Download the db and verify size
ARCHIVE_PATH="$TMP_DIR/GeoLite2-Country.tar.gz"
log_message "INFO" "Downloading database from $DOWNLOAD_URL"
if ! curl -LsSf -o "$ARCHIVE_PATH" "$DOWNLOAD_URL"; then
    err_msg="Failed to download the database archive."
    log_message "ERROR" "$err_msg"
    send_failure_notification "$err_msg"
    exit 1
fi

if [ ! -s "$ARCHIVE_PATH" ] || [ "$(stat -c%s "$ARCHIVE_PATH")" -lt 10240 ]; then
    err_msg="Downloaded archive is unexpectedly small or empty: $(stat -c%s "$ARCHIVE_PATH") bytes"
    log_message "ERROR" "$err_msg"
    send_failure_notification "$err_msg"
    exit 1
fi

# 4. Extract the database
log_message "INFO" "Extracting archive..."
if ! run_io tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"; then
    err_msg="Failed to extract the database archive."
    log_message "ERROR" "$err_msg"
    send_failure_notification "$err_msg"
    exit 1
fi

# 5. Find the new database file
NEW_DB_PATH=$(find "$TMP_DIR" -type f -name "$DB_FILENAME")
if [ -z "$NEW_DB_PATH" ]; then
    err_msg="Could not find '$DB_FILENAME' in the extracted archive."
    log_message "ERROR" "$err_msg"
    send_failure_notification "$err_msg"
    exit 1
fi

# 6. Compare with existing database and update if necessary
EXISTING_DB_PATH="$DEST_DIR/$DB_FILENAME"
UPDATE_NEEDED=false

if [ ! -f "$EXISTING_DB_PATH" ]; then
    log_message "INFO" "No existing database found. Proceeding with installation."
    UPDATE_NEEDED=true
else
    log_message "INFO" "Existing database found. Comparing versions..."

    EXISTING_HASH=$(run_cpu sha256sum "$EXISTING_DB_PATH" | awk '{print $1}')
    NEW_HASH=$(run_cpu sha256sum "$NEW_DB_PATH" | awk '{print $1}')

    log_message "INFO" "Existing DB hash: $EXISTING_HASH"
    log_message "INFO" "New DB hash:     $NEW_HASH"

    if [ "$EXISTING_HASH" != "$NEW_HASH" ]; then
        log_message "INFO" "Hashes differ. An update is required."
        UPDATE_NEEDED=true
    else
        log_message "INFO" "Hashes are identical. Database is already up-to-date."
    fi
fi

# 7. Perform the update
if [ "$UPDATE_NEEDED" = true ]; then

    if [ -f "$EXISTING_DB_PATH" ]; then
        log_message "INFO" "Matching permissions and ownership of existing database."
        if ! chown --reference="$EXISTING_DB_PATH" "$NEW_DB_PATH"; then
             log_message "WARNING" "Could not set ownership on new database file. Check script permissions."
        fi
        if ! chmod --reference="$EXISTING_DB_PATH" "$NEW_DB_PATH"; then
             log_message "WARNING" "Could not set permissions on new database file."
        fi
    else
        chmod 644 "$NEW_DB_PATH"
        log_message "INFO" "Set permissions to 644 for new database installation."
    fi

    TEMP_DB_IN_DEST="${EXISTING_DB_PATH}.tmp"
    log_message "INFO" "Staging new database to $TEMP_DB_IN_DEST"
    if ! mv "$NEW_DB_PATH" "$TEMP_DB_IN_DEST"; then
        err_msg="Failed to move the new database to the destination directory."
        log_message "ERROR" "$err_msg"
        send_failure_notification "$err_msg"
        exit 1
    fi

    log_message "INFO" "Atomically replacing old database..."
    if ! mv "$TEMP_DB_IN_DEST" "$EXISTING_DB_PATH"; then
        err_msg="Failed to atomically rename the new database."
        log_message "ERROR" "$err_msg"
        send_failure_notification "$err_msg"
        rm -f "$TEMP_DB_IN_DEST"
        exit 1
    fi

    log_message "SUCCESS" "Database has been successfully updated."
    send_success_notification "The GeoLite2-Country.mmdb database was successfully updated."

    # Optional: If a service needs to be restarted after the update, add here.
    # For example:
    # log_message "INFO" "Restarting Nginx service..."
    # systemctl restart nginx or docker compose restart nginx, etc.
else
    log_message "INFO" "Update check complete. No new version found."
    send_checkin_notification "Database is already up-to-date. No action needed."
fi

exit 0
