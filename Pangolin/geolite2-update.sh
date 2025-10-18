#!/bin/bash
#
# GeoLite2 Database Auto-Updater
#
# Description: This script checks for updates to the GeoLite2-Country database from
# the node-geolite2-redist GitHub repository, downloads it if it's newer,
# places it in a specified directory, and sends notifications on success/failure.

set -euo pipefail

# --- Configuration ---
DEST_DIR="/path/to/your/config/" # <-- Change this to actual config directory.
DB_FILENAME="GeoLite2-Country.mmdb" # Final db name.
DOWNLOAD_URL="https://github.com/GitSquared/node-geolite2-redist/raw/refs/heads/master/redist/GeoLite2-Country.tar.gz"
LOG_FILE="/var/log/geolite2-update.log" # Log file path

# ntfy
NTFY_ENABLED=false
NTFY_TOPIC="your_ntfy_topic_here" # <-- Change this
NTFY_SERVER="https://ntfy.sh"     # Default server
NTFY_TOKEN=""                     # <-- Add token

# Discord
DISCORD_ENABLED=false
DISCORD_WEBHOOK_URL="your_webhook_url_here" # <-- Change this

# --- Functions ---

log_message() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] - $message" | tee -a "$LOG_FILE"

    if command -v systemd-cat > /dev/null 2>&1; then
        echo "$message" | systemd-cat -t "geolite2-update" -p "${level,,}"
    fi
}

# Sends a notification to ntfy
send_notification_ntfy() {
    local title="$1"
    local message="$2"
    local priority="${3:-default}" # Priority can be: low, default, high

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
        "$NTFY_SERVER/$NTFY_TOPIC" 2>/dev/null; then
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
    local server_name=$(hostname)
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Create JSON payload
    JSON_PAYLOAD=$(cat <<EOF
{
  "username": "GeoLite2 Updater",
  "avatar_url": "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/geo-guessr.png",
  "embeds": [
    {
      "title": "$title",
      "description": "$description",
      "color": $color,
      "footer": {
        "text": "Host: $server_name"
      },
      "timestamp": "$timestamp"
    }
  ]
}
EOF
)

    if ! curl -LsSf -H "Content-Type: application/json" -d "$JSON_PAYLOAD" "$DISCORD_WEBHOOK_URL" 2>/dev/null; then
        log_message "WARNING" "Failed to send Discord notification."
    fi
}

send_failure_notification() {
    local message="$1"
    local title="GeoLite2 Update FAILED"
    local discord_color=15158332 # Red

    send_notification_ntfy "$title" "$message" "high"
    send_notification_discord "$title" "$message" "$discord_color"
}

send_success_notification() {
    local message="$1"
    local title="GeoLite2 DB Updated"
    local discord_color=3066993 # Green

    send_notification_ntfy "$title" "$message" "default"
    send_notification_discord "$title" "$message" "$discord_color"
}

send_checkin_notification() {
    local message="$1"
    local title="GeoLite2 Check Complete"
    local discord_color=9807270 # Gray

    send_notification_ntfy "$title" "$message" "low"
    send_notification_discord "$title" "$message" "$discord_color"
}

cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
        log_message "INFO" "Cleaned up temporary directory: $TMP_DIR"
    fi
}

# --- Execution ---

trap cleanup EXIT

log_message "INFO" "Starting GeoLite2 database update script."

# 1. Validate Configuration and Prerequisites
if [[ "$DEST_DIR" == "/path/to/your/config/" ]]; then
    err_msg="Configuration needed: Set DEST_DIR variable to your actual config directory."
    log_message "ERROR" "$err_msg"
    send_failure_notification "$err_msg"
    exit 1
fi

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

for cmd in curl tar find sha256sum; do
    if ! command -v "$cmd" > /dev/null 2>&1; then
        err_msg="Required command '$cmd' is not installed."
        log_message "ERROR" "$err_msg"
        send_failure_notification "$err_msg"
        exit 1
    fi
done

# 2. Create a temporary directory
TMP_DIR=$(mktemp -d)
log_message "INFO" "Created temporary directory at $TMP_DIR"

# 3. Download the database archive
ARCHIVE_PATH="$TMP_DIR/GeoLite2-Country.tar.gz"
log_message "INFO" "Downloading database from $DOWNLOAD_URL"
if ! curl -LsSf -o "$ARCHIVE_PATH" "$DOWNLOAD_URL"; then
    err_msg="Failed to download the database archive."
    log_message "ERROR" "$err_msg"
    send_failure_notification "$err_msg"
    exit 1
fi

# 4. Extract the database
log_message "INFO" "Extracting archive..."
if ! tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"; then
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

    EXISTING_HASH=$(sha256sum "$EXISTING_DB_PATH" | awk '{print $1}')
    NEW_HASH=$(sha256sum "$NEW_DB_PATH" | awk '{print $1}')

    log_message "INFO" "Existing DB hash: $EXISTING_HASH"
    log_message "INFO" "New DB hash:     $NEW_HASH"

    if [ "$EXISTING_HASH" != "$NEW_HASH" ]; then
        log_message "INFO" "Hashes differ. An update is required."
        UPDATE_NEEDED=true
    else
        log_message "INFO" "Hashes are identical. Comparing timestamps as a fallback."
        if [ "$NEW_DB_PATH" -nt "$EXISTING_DB_PATH" ]; then
            log_message "INFO" "Downloaded database is newer based on timestamp. Update is required."
            UPDATE_NEEDED=true
        else
            log_message "INFO" "Database is already up-to-date. No action needed."
        fi
    fi
fi

# 7. Perform the update
if [ "$UPDATE_NEEDED" = true ]; then
    log_message "INFO" "Moving new database to $EXISTING_DB_PATH"
    if ! mv "$NEW_DB_PATH" "$EXISTING_DB_PATH"; then
        err_msg="Failed to move the new database into place."
        log_message "ERROR" "$err_msg"
        send_failure_notification "$err_msg"
        exit 1
    fi
    log_message "SUCCESS" "Database has been successfully updated."
    
    send_success_notification "The GeoLite2-Country.mmdb database was successfully updated."
    
    # Optional: If a service needs to be restarted after the update, add here.
    # For example:
    # log_message "INFO" "Restarting Nginx service..."
    # systemctl restart nginx
else
    log_message "INFO" "Update check complete. No new version found."
    send_checkin_notification "Database is already up-to-date. No action needed."
fi

exit 0
