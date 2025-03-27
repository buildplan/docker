#!/bin/bash

# =================================================================
# This is a modified version of of GitHub user @hhftechnology. Found at:
# https://github.com/hhftechnology/pangolin-monitoring
# =================================================================
# Pangolin Stack Monitoring System 
# A comprehensive monitoring solution for Pangolin containers
# Features:
# - Container monitoring (health, resources, logs, image updates)
# - System health checks (CPU, memory, disk, network)
# - Security monitoring (SSH, network attacks, suspicious activity)
# - Discord notifications via discord.sh
# - Interactive menu for easy management
# =================================================================

# Script directory detection
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"
LOG_DIR="${SCRIPT_DIR}/logs"
DISCORD_SCRIPT="${SCRIPT_DIR}/discord.sh"

# Create necessary directories
mkdir -p "${CONFIG_DIR}" "${LOG_DIR}"

# Global variables
VERSION="1.1_a" 
CONFIG_FILE="${CONFIG_DIR}/pangolin_monitor.conf"
LOG_FILE="${LOG_DIR}/pangolin-monitor.log"

# Terminal colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration values
DEFAULT_CHECK_INTERVAL=3600         # 1hour Seconds between checks
DEFAULT_REPORT_INTERVAL=43200       # 12 hours in seconds
DEFAULT_CONTAINER_NAMES=("pangolin" "gerbil" "traefik" "crowdsec")
DEFAULT_CPU_WARNING=80
DEFAULT_CPU_CRITICAL=90
DEFAULT_MEM_WARNING=80
DEFAULT_MEM_CRITICAL=90
DEFAULT_DISK_WARNING=80
DEFAULT_DISK_CRITICAL=90
DEFAULT_DISCORD_WEBHOOK=""
DEFAULT_NETWORK_THRESHOLD=2500     # Packets per second threshold for attack detection
DEFAULT_SSH_NOTIFY="true"
DEFAULT_LOG_NOTIFY="true"
DEFAULT_ATTACK_NOTIFY="true"
DEFAULT_IMAGE_UPDATE_NOTIFY="true" # New: Control image update checks/notifications
DEFAULT_IMAGE_UPDATE_INTERVAL=$((24 * 3600)) # New: Check images once per day (seconds)
DEFAULT_EMOJI_CHECK="✅"
DEFAULT_EMOJI_CROSS="❌"
DEFAULT_EMOJI_WARNING="⚠️"
DEFAULT_EMOJI_ALERT="🔔"
DEFAULT_EMOJI_SECURITY="🛡️"
DEFAULT_EMOJI_SERVER="🖥️"
DEFAULT_EMOJI_UPDATE="⬆️" # New: Emoji for updates

# ========================
# Utility Functions
# ========================

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "${LOG_FILE}"
    case "$level" in
        "ERROR") echo -e "${RED}[$level] $message${NC}" >&2 ;;
        "WARNING") echo -e "${YELLOW}[$level] $message${NC}" >&2 ;;
        "INFO") echo -e "${CYAN}[$level] $message${NC}" ;;
        "DEBUG") [[ "$DEBUG" == "true" ]] && echo -e "${CYAN}[$level] $message${NC}" ;;
        *) echo "[$level] $message" ;;
    esac
}

# Wait for key press
wait_for_key() {
    echo -e "\n${CYAN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Display status with color
display_status() {
    local status="$1"
    local message="$2"
    case "$status" in
        "OK") echo -e "${GREEN}[✓] $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}[!] $message${NC}" ;;
        "ERROR") echo -e "${RED}[✗] $message${NC}" ;;
        *) echo "[?] $message" ;;
    esac
}

# Load configuration once at startup
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log_message "INFO" "Configuration loaded from $CONFIG_FILE"
    else
        log_message "WARNING" "Configuration file not found, creating default"
        save_default_config
        source "$CONFIG_FILE"
    fi

    # Set defaults for any missing config values
    CONTAINER_NAMES=("${CONTAINER_NAMES[@]:-${DEFAULT_CONTAINER_NAMES[@]}}")
    CHECK_INTERVAL=${CHECK_INTERVAL:-$DEFAULT_CHECK_INTERVAL}
    REPORT_INTERVAL=${REPORT_INTERVAL:-$DEFAULT_REPORT_INTERVAL}
    CPU_WARNING_THRESHOLD=${CPU_WARNING_THRESHOLD:-$DEFAULT_CPU_WARNING}
    CPU_CRITICAL_THRESHOLD=${CPU_CRITICAL_THRESHOLD:-$DEFAULT_CPU_CRITICAL}
    MEM_WARNING_THRESHOLD=${MEM_WARNING_THRESHOLD:-$DEFAULT_MEM_WARNING}
    MEM_CRITICAL_THRESHOLD=${MEM_CRITICAL_THRESHOLD:-$DEFAULT_MEM_CRITICAL}
    DISK_WARNING_THRESHOLD=${DISK_WARNING_THRESHOLD:-$DEFAULT_DISK_WARNING}
    DISK_CRITICAL_THRESHOLD=${DISK_CRITICAL_THRESHOLD:-$DEFAULT_DISK_CRITICAL}
    DISCORD_WEBHOOK=${DISCORD_WEBHOOK:-$DEFAULT_DISCORD_WEBHOOK}
    NETWORK_THRESHOLD=${NETWORK_THRESHOLD:-$DEFAULT_NETWORK_THRESHOLD}
    SSH_NOTIFY=${SSH_NOTIFY:-$DEFAULT_SSH_NOTIFY}
    LOG_NOTIFY=${LOG_NOTIFY:-$DEFAULT_LOG_NOTIFY}
    ATTACK_NOTIFY=${ATTACK_NOTIFY:-$DEFAULT_ATTACK_NOTIFY}
    IMAGE_UPDATE_NOTIFY=${IMAGE_UPDATE_NOTIFY:-$DEFAULT_IMAGE_UPDATE_NOTIFY} # New
    IMAGE_UPDATE_INTERVAL=${IMAGE_UPDATE_INTERVAL:-$DEFAULT_IMAGE_UPDATE_INTERVAL} # New
    DEBUG=${DEBUG:-false}
    EMOJI_CHECK="${EMOJI_CHECK:-$DEFAULT_EMOJI_CHECK}"
    EMOJI_CROSS="${EMOJI_CROSS:-$DEFAULT_EMOJI_CROSS}"
    EMOJI_WARNING="${EMOJI_WARNING:-$DEFAULT_EMOJI_WARNING}"
    EMOJI_ALERT="${EMOJI_ALERT:-$DEFAULT_EMOJI_ALERT}"
    EMOJI_SECURITY="${EMOJI_SECURITY:-$DEFAULT_EMOJI_SECURITY}"
    EMOJI_SERVER="${EMOJI_SERVER:-$DEFAULT_EMOJI_SERVER}"
    EMOJI_UPDATE="${EMOJI_UPDATE:-$DEFAULT_EMOJI_UPDATE}" # New
}

# Save default configuration
save_default_config() {
    cat > "$CONFIG_FILE" << EOL
# Pangolin Stack Monitor Configuration
# Generated on $(date)

# Monitoring Intervals
CHECK_INTERVAL=$DEFAULT_CHECK_INTERVAL
REPORT_INTERVAL=$DEFAULT_REPORT_INTERVAL
IMAGE_UPDATE_INTERVAL=$DEFAULT_IMAGE_UPDATE_INTERVAL # New

# Thresholds
CPU_WARNING_THRESHOLD=$DEFAULT_CPU_WARNING
CPU_CRITICAL_THRESHOLD=$DEFAULT_CPU_CRITICAL
MEM_WARNING_THRESHOLD=$DEFAULT_MEM_WARNING
MEM_CRITICAL_THRESHOLD=$DEFAULT_MEM_CRITICAL
DISK_WARNING_THRESHOLD=$DEFAULT_DISK_WARNING
DISK_CRITICAL_THRESHOLD=$DEFAULT_DISK_CRITICAL
NETWORK_THRESHOLD=$DEFAULT_NETWORK_THRESHOLD

# Container Monitoring
CONTAINER_NAMES=(${DEFAULT_CONTAINER_NAMES[*]})

# Notification Settings
SSH_NOTIFY=$DEFAULT_SSH_NOTIFY
LOG_NOTIFY=$DEFAULT_LOG_NOTIFY
ATTACK_NOTIFY=$DEFAULT_ATTACK_NOTIFY
IMAGE_UPDATE_NOTIFY=$DEFAULT_IMAGE_UPDATE_NOTIFY # New

# Discord Webhook
DISCORD_WEBHOOK="$DEFAULT_DISCORD_WEBHOOK"

# Emoji Settings
EMOJI_CHECK="$DEFAULT_EMOJI_CHECK"
EMOJI_CROSS="$DEFAULT_EMOJI_CROSS"
EMOJI_WARNING="$DEFAULT_EMOJI_WARNING"
EMOJI_ALERT="$DEFAULT_EMOJI_ALERT"
EMOJI_SECURITY="$DEFAULT_EMOJI_SECURITY"
EMOJI_SERVER="$DEFAULT_EMOJI_SERVER"
EMOJI_UPDATE="$DEFAULT_EMOJI_UPDATE" # New

# Debug Mode (true/false)
DEBUG=false
EOL
    chmod 600 "$CONFIG_FILE"
    log_message "INFO" "Default configuration saved to $CONFIG_FILE"
}

# Check if discord.sh exists and is executable
check_discord_script() {
    if [[ ! -f "$DISCORD_SCRIPT" ]]; then
        log_message "ERROR" "discord.sh not found at $DISCORD_SCRIPT"
        echo -e "${RED}Error: discord.sh script not found at $DISCORD_SCRIPT${NC}"
        echo -e "${YELLOW}Please ensure discord.sh is available in the script directory${NC}"
        return 1
    fi

    if [[ ! -x "$DISCORD_SCRIPT" ]]; then
        log_message "WARNING" "discord.sh is not executable, fixing permissions"
        chmod +x "$DISCORD_SCRIPT"
    fi

    log_message "INFO" "discord.sh found and is executable"
    return 0
}

# ========================
# Discord Notification Functions
# ========================

# Validate webhook URL
validate_discord_webhook() {
    local webhook="$1"

    # Check if webhook is empty
    if [[ -z "$webhook" || "$webhook" == "https://discord.com/api/webhooks/" ]]; then
        log_message "ERROR" "Discord webhook URL is empty or default"
        return 1
    fi

    # Basic format validation
    if [[ ! "$webhook" =~ ^https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+$ ]]; then
        log_message "ERROR" "Invalid Discord webhook URL format: $webhook"
        return 1
    fi

    return 0
}

# Function to map emoji shortcodes to actual Unicode emojis
emoji_map() {
    local emoji_code="$1"
    case "$emoji_code" in
        ":check:") echo "${EMOJI_CHECK}" ;;
        ":x:") echo "${EMOJI_CROSS}" ;;
        ":warning:") echo "${EMOJI_WARNING}" ;;
        ":bell:") echo "${EMOJI_ALERT}" ;;
        ":shield:") echo "${EMOJI_SECURITY}" ;;
        ":server:") echo "${EMOJI_SERVER}" ;;
        ":update:") echo "${EMOJI_UPDATE}" ;; # New
        *) echo "$emoji_code" ;; # Return as-is if not found
    esac
}

# Function to replace emoji shortcodes in a string
replace_emojis() {
    local message="$1"
    local result="$message"

    # Replace common emoji shortcodes with their mapped values
    result="${result//:check:/$(emoji_map ':check:')}"
    result="${result//:x:/$(emoji_map ':x:')}"
    result="${result//:warning:/$(emoji_map ':warning:')}"
    result="${result//:bell:/$(emoji_map ':bell:')}"
    result="${result//:shield:/$(emoji_map ':shield:')}"
    result="${result//:server:/$(emoji_map ':server:')}"
    result="${result//:update:/$(emoji_map ':update:')}" # New

    echo "$result"
}

# Send message to Discord using discord.sh
send_discord_message() {
    local title="$1"
    local message="$2"
    local severity="${3:-info}"
    local fields="${4:-}"
    local username="${5:-Pangolin Monitor}"

    # Validate webhook
    if ! validate_discord_webhook "$DISCORD_WEBHOOK"; then
        log_message "ERROR" "Invalid Discord webhook URL, cannot send message"
        return 1
    fi

    # Check if discord.sh exists
    if ! check_discord_script; then
        log_message "ERROR" "discord.sh script not found or is not executable"
        return 1
    fi

    # Set color based on severity
    local color
    case "$severity" in
        "critical") color=15158332 ;;  # Red
        "error") color=16711680 ;;     # Red
        "warning") color=16776960 ;;   # Yellow
        "info") color=5814783 ;;       # Blue
        "success") color=3066993 ;;    # Green
        *) color=8421504 ;;            # Gray
    esac

    # Set emoji prefix based on severity
    local emoji_prefix
    case "$severity" in
        "critical") emoji_prefix=":x:" ;;
        "error") emoji_prefix=":x:" ;;
        "warning") emoji_prefix=":warning:" ;;
        "info") emoji_prefix=":bell:" ;;
        "success") emoji_prefix=":check:" ;;
        *) emoji_prefix=":shield:" ;;
    esac

    # Process emoji shortcodes in title and message
    local processed_title=$(replace_emojis "${emoji_prefix} ${title}")
    local processed_message=$(replace_emojis "$message")

    # Build command
    local cmd=("$DISCORD_SCRIPT" "--webhook-url=$DISCORD_WEBHOOK" "--username=$username" "--title=$processed_title" "--description=$processed_message" "--color=$color" "--timestamp")

    # Add fields if provided
    if [[ -n "$fields" ]]; then
        IFS=';' read -ra field_array <<< "$fields"
        for field in "${field_array[@]}"; do
            cmd+=("--field=$field")
        done
    fi

    # Set footer
    local hostname=$(hostname)
    cmd+=("--footer=Pangolin Monitor v${VERSION} | ${hostname}")

    # Execute command
    if "${cmd[@]}" &>/dev/null; then
        log_message "INFO" "Discord notification sent successfully: $title"
        return 0
    else
        log_message "ERROR" "Failed to send Discord notification: $title"
        return 1
    fi
}

# Function to prepare and send an alert message
send_alert() {
    local alert_type="$1"
    local title="$2"
    local message="$3"
    local severity="$4"
    local fields="$5"

    log_message "INFO" "Sending $alert_type alert: $title"
    send_discord_message "$title" "$message" "$severity" "$fields" "Pangolin Alerts"
}

# ========================
# SSH Notification Functions
# ========================

ssh_login_notification() {
    # Skip if SSH notifications are disabled
    if [[ "$SSH_NOTIFY" != "true" ]]; then
        log_message "DEBUG" "SSH notifications are disabled, skipping"
        return 0
    fi

    log_message "INFO" "SSH login detected, sending notification"

    # Variables
    local BOTNAME="$(hostname)"
    local DATE=$(date +"%d-%m-%Y-%H:%M:%S")
    local TMPFILE=$(mktemp)

    # Get IP information from SSH_CLIENT environment variable
    # Note: This variable is typically only set when the script is run *by* the SSH login process.
    # It might be empty if run as a background service or cron job.
    local IP=$(echo "$SSH_CLIENT" | awk '{ ip = $1 } END { print ip }')

    # Ensure IP was extracted
    if [[ -z "$IP" ]]; then
        log_message "WARNING" "Could not determine client IP from SSH_CLIENT for login notification."
        # Decide if you want to send a basic notification anyway
        # send_discord_message "SSH Login Detected (IP Unknown)" "User: `whoami`, Host: `hostname`, Time: $DATE" "warning" "" "$BOTNAME"
        rm -f "$TMPFILE" # Cleanup temp file even on early exit
        return 1         # Indicate an issue
    fi

    # Try to fetch IP Geo data, fallback to just IP if curl fails or IP is local/invalid
    if command -v curl &>/dev/null; then
        # Use timeout and fail silently on error
        curl -s --connect-timeout 5 "https://ipapi.co/${IP}/json/" > "$TMPFILE" 2>/dev/null
        local curl_exit_code=$?

        if [[ $curl_exit_code -eq 0 ]] && grep -q '"ip":' "$TMPFILE"; then # Check if output looks like valid JSON
            # Extract information using jq if available, otherwise grep
            local ISP CITY COUNTRY
            if command -v jq >/dev/null 2>&1; then
                 ISP=$(jq -r '.org // "Unknown"' "$TMPFILE")
                 COUNTRY=$(jq -r '.country_name // "Unknown"' "$TMPFILE")
                 CITY=$(jq -r '.city // "Unknown"' "$TMPFILE")
            else # Fallback to grep
                 ISP=$(grep -o '"org": "[^"]*' "$TMPFILE" | cut -d'"' -f4 2>/dev/null || echo "Unknown")
                 COUNTRY=$(grep -o '"country_name": "[^"]*' "$TMPFILE" | cut -d'"' -f4 2>/dev/null || echo "Unknown")
                 CITY=$(grep -o '"city": "[^"]*' "$TMPFILE" | cut -d'"' -f4 2>/dev/null || echo "Unknown")
            fi

            # Create message with geo info
            local title="SSH Login Detected"
            local message="**Details**\n • User: \`$(whoami)\` \n • Host: \`$(hostname)\` \n • Time: \`$DATE\` \n\n **Connection IP**\n • IP: \`${IP}\`\n • Location: \`${CITY}, ${COUNTRY}\`\n • ISP: \`${ISP}\`"
        else
            log_message "DEBUG" "curl failed or returned invalid data for IP $IP (Exit: $curl_exit_code). Falling back to IP only."
            # Fallback message with just IP
            local title="SSH Login Detected"
            local message="**Details**\n • User: \`$(whoami)\` \n • Host: \`$(hostname)\` \n • Time: \`$DATE\` \n\n **Connection IP**\n • IP: \`${IP}\`"
        fi
    else
        log_message "DEBUG" "curl command not found. Falling back to IP only for SSH notification."
        # Fallback message with just IP
        local title="SSH Login Detected"
        local message="**Details**\n • User: \`$(whoami)\` \n • Host: \`$(hostname)\` \n • Time: \`$DATE\` \n\n **Connection IP**\n • IP: \`${IP}\`"
    fi

    # Send notification
    send_discord_message "$title" "$message" "warning" "" "$BOTNAME"

    # Cleanup
    rm -f "$TMPFILE"

    return 0
}

# ========================
# System Updates Notification
# ========================

check_system_updates() {
    # Skip if update notifications are disabled (controlled by LOG_NOTIFY in default config)
    if [[ "$LOG_NOTIFY" != "true" ]]; then
        log_message "DEBUG" "System update notifications (via LOG_NOTIFY) are disabled, skipping"
        return 0
    fi

    log_message "INFO" "Checking for system updates"

    local updates_available=false
    local update_count=0
    local updates_list=""
    local package_manager=""

    # Check for apt (Debian/Ubuntu)
    if command -v apt-get &>/dev/null; then
        package_manager="apt"
        log_message "DEBUG" "Using apt for system update check."
        # Update package lists quietly; handle potential errors
        if ! apt-get update -qq &>/dev/null; then
             log_message "WARNING" "apt-get update failed. Cannot check for updates accurately."
             # Optionally send a Discord alert about the failure
             # send_discord_message "Update Check Failed" "apt-get update failed on $(hostname)" "warning"
             return 1 # Exit the function if update fails
        fi
        # Check for upgradable packages
        updates_list=$(apt list --upgradable 2>/dev/null | grep -v "Listing...")
        # Count lines, excluding potential empty lines from the grep output if any
        update_count=$(echo "$updates_list" | grep -c /) # Count lines containing '/' which apt list uses

    # Check for dnf (Fedora/RHEL)
    elif command -v dnf &>/dev/null; then
        package_manager="dnf"
        log_message "DEBUG" "Using dnf for system update check."
        # dnf check-update often doesn't require a refresh beforehand, but can be slow
        updates_list=$(dnf check-update -q --cacheonly 2>/dev/null || dnf check-update -q 2>/dev/null) # Try cache first
        # Count non-empty lines excluding header if any
        update_count=$(echo "$updates_list" | grep -c '.')

    # Check for yum (CentOS)
    elif command -v yum &>/dev/null; then
        package_manager="yum"
        log_message "DEBUG" "Using yum for system update check."
        # yum check-update often doesn't require refresh, but can be slow
        updates_list=$(yum check-update -q --cacheonly 2>/dev/null || yum check-update -q 2>/dev/null) # Try cache first
        # Count non-empty lines excluding header if any
        update_count=$(echo "$updates_list" | grep -c '.')

    else
         log_message "INFO" "No supported package manager (apt, dnf, yum) found for update check."
         return 0 # Not an error, just can't check
    fi

    log_message "DEBUG" "Found $update_count potential updates using $package_manager."

    if [[ $update_count -gt 0 ]]; then
        updates_available=true
    fi

    # If updates are available, send notification
    if [[ "$updates_available" == "true" ]]; then
        log_message "INFO" "System updates available ($update_count), sending notification"

        # Create message
        local title="$(hostname) needs OS updates"
        local message="**${update_count} packages can be updated** using \`$package_manager\`\n\n"
        # Get a snippet of the update list, limit lines and width
        local updates_snippet=$(echo "$updates_list" | head -n 15 | cut -c 1-80)
        message+="Packages (first 15):\n\`\`\`\n${updates_snippet}\n\`\`\`"

        if [[ $update_count -gt 15 ]]; then
            message+="\n\n*...and $(($update_count - 15)) more packages*"
        fi

        message+="\n\nRun the appropriate update command (e.g., \`sudo $package_manager update && sudo $package_manager upgrade\`) to update the system."

        # Send notification
        send_discord_message "$title" "$message" "info" "" "System Updates"
        return 0 # Report success but indicate updates found if needed elsewhere?
    else
        log_message "DEBUG" "No system updates available via $package_manager."
        return 0 # Success, no updates
    fi
}

# ========================
# Network Attack Detection
# ========================

monitor_network_traffic() {
    # Skip if attack notifications are disabled
    if [[ "$ATTACK_NOTIFY" != "true" ]]; then
        log_message "DEBUG" "Attack notifications are disabled, skipping"
        return 0
    fi

    log_message "INFO" "Monitoring network traffic for potential attacks"

    # TODO: Consider making the network interface configurable in pangolin_monitor.conf
    # Auto-detect the first available network interface (excluding loopback 'lo')
    local interface=$(ls /sys/class/net/ 2>/dev/null | grep -v "lo" | head -n 1)

    if [[ -z "$interface" ]]; then
        log_message "WARNING" "No active non-loopback network interfaces detected. Cannot monitor traffic."
        return 1
    fi

    log_message "DEBUG" "Using network interface: $interface for traffic monitoring"
    local threshold=${NETWORK_THRESHOLD:-2500} # Use default if not set

    # Get initial packet count for the specific interface
    local pkt_old=$(grep "$interface:" /proc/net/dev 2>/dev/null | cut -d ':' -f2 | awk '{ print $2 }')
    local bs_old=$(grep "$interface:" /proc/net/dev 2>/dev/null | cut -d ':' -f2 | awk '{ print $1 }') # Bytes received

    if [[ -z "$pkt_old" || -z "$bs_old" ]]; then
        log_message "WARNING" "Unable to read network statistics from /proc/net/dev for interface '$interface'"
        return 1
    fi

    # Wait 1 second to calculate rate
    sleep 1

    # Get new packet count
    local pkt_new=$(grep "$interface:" /proc/net/dev 2>/dev/null | cut -d ':' -f2 | awk '{ print $2 }')
    local bs_new=$(grep "$interface:" /proc/net/dev 2>/dev/null | cut -d ':' -f2 | awk '{ print $1 }') # Bytes received

     if [[ -z "$pkt_new" || -z "$bs_new" ]]; then
        log_message "WARNING" "Unable to read network statistics (second read) for interface '$interface'"
        return 1
    fi

    # Calculate packets per second (PPS) and Megabits per second (Mbps)
    # Check if values are numeric before calculation
    local pkt=0
    local byte=0
    if [[ "$pkt_new" =~ ^[0-9]+$ && "$pkt_old" =~ ^[0-9]+$ && $pkt_new -ge $pkt_old ]]; then
         pkt=$(( pkt_new - pkt_old ))
    fi
     if [[ "$bs_new" =~ ^[0-9]+$ && "$bs_old" =~ ^[0-9]+$ && $bs_new -ge $bs_old ]]; then
         byte=$(( bs_new - bs_old ))
    fi

    # Calculate Mbps (Bytes * 8 bits / 1,000,000) - Use bc for floating point
    local mbps=$(echo "scale=2; $byte * 8 / 1000000" | bc)

    log_message "DEBUG" "Current network traffic: $pkt packets/s, $mbps Mbps on $interface"

    # Check if packet rate is above threshold
    if [[ $pkt -gt $threshold ]]; then
        log_message "WARNING" "Network attack suspected: $pkt packets/s (Threshold: $threshold pps) on interface $interface"

        # Create attack notification
        local title="Potential Network Attack Detected"
        local message="**High network traffic detected on \`$(hostname)\`!**\n\n"
        message+="❗ **Traffic Spike Details:**\n"
        message+="- **Interface:** \`$interface\`\n"
        message+="- **Incoming Packets:** \`${pkt}\` packets per second (Threshold: $threshold)\n"
        message+="- **Bandwidth Usage:** \`${mbps}\` Mbps\n\n"
        message+="This may indicate a network scan or Denial-of-Service attack. CrowdSec or other security measures should be reviewed."

        # Send notification
        send_discord_message "$title" "$message" "critical" "" "Attack Alerts"

        # --- All-Clear Logic ---
        # The original script waited 120s then sent an all-clear.
        # This can be problematic (attack stops/starts).
        # Option 1: Remove all-clear (simpler, relies on user/other tools)
        # Option 2: Implement state tracking (more complex)
        # Let's comment out the original all-clear for now, recommending Option 1.
        log_message "INFO" "Attack detected. Manual verification or other tools (e.g., CrowdSec alerts) should confirm resolution."
        # sleep 120 # Original wait
        # Check if traffic has returned to normal
        # ... (Original all-clear logic omitted) ...

        # Return non-zero to indicate an anomaly was detected during this check
        return 1
    fi

    # If traffic is below threshold
    return 0
}

# ========================
# Container Monitoring
# ========================

check_container_health() {
    local container="$1"
    local inspect_output

    # Check if container exists using inspect (more direct than ps | grep)
    # Redirect stderr to /dev/null to suppress "No such object" errors
    inspect_output=$(docker inspect --format='{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container" 2>/dev/null)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        # If inspect failed, the container likely doesn't exist
        log_message "ERROR" "Container '$container' not found or could not be inspected."
        return 1 # Error: Not found or inaccessible
    fi

    # Parse the output
    local status=$(echo "$inspect_output" | cut -d'|' -f1)
    local health=$(echo "$inspect_output" | cut -d'|' -f2)

    # Check status
    if [[ "$status" != "running" ]]; then
        log_message "ERROR" "Container '$container' is present but not running (Status: $status)."
        return 1 # Error: Not running
    fi

    # Check health (if health check is defined)
    # 'none' means no health check defined, which we treat as OK here.
    if [[ "$health" != "none" && "$health" != "healthy" ]]; then
        log_message "WARNING" "Container '$container' is running but unhealthy (Health: $health)."
        return 2 # Warning: Unhealthy
    fi

    # If running and healthy (or no health check defined)
    log_message "INFO" "Container '$container' is running and healthy (Status: $status, Health: $health)."
    return 0 # OK
}
# ========================
# Container Monitoring (Continued)
# ========================

get_container_stats() {
    local container="$1"

    # Get CPU and memory usage using docker stats
    # --no-stream gets a single reading
    # Redirect stderr to catch errors if container not running/found
    local stats_output=$(docker stats --no-stream --format "{{.CPUPerc}}|{{.MemPerc}}" "$container" 2>/dev/null)
    local exit_code=$?

    # Check if docker stats command succeeded
    if [[ $exit_code -ne 0 || -z "$stats_output" ]]; then
        log_message "ERROR" "Could not get stats for container '$container'. It might not be running or accessible."
        # Return a placeholder or indicate error
        echo "N/A CPU, N/A Memory" # Return placeholder string
        return 1 # Indicate failure
    fi

    # Parse the output
    local cpu_perc=$(echo "$stats_output" | cut -d'|' -f1 | sed 's/%//')
    local mem_perc=$(echo "$stats_output" | cut -d'|' -f2 | sed 's/%//')

    # --- CPU Usage Check ---
    # Check if cpu_perc is a valid number before comparison
    if [[ "$cpu_perc" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        # Use bc for floating point comparison
        if (( $(echo "$cpu_perc > $CPU_CRITICAL_THRESHOLD" | bc -l) )); then
            log_message "ERROR" "Container '$container' CPU usage critical: ${cpu_perc}%"

            # Create alert data
            local title="Container CPU Alert: $container"
            local message="The container **$container** has reported critical CPU usage:\n\n"
            message+="**Current Value**: ${cpu_perc}%\n"
            message+="**Threshold**: ${CPU_CRITICAL_THRESHOLD}%\n\n"
            message+="Please check the container status and logs."

            # Create fields (using inspect - requires container to be inspectable)
            local status_health=$(docker inspect --format='{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container" 2>/dev/null || echo "Unknown|Unknown")
            local started_at=$(docker inspect --format='{{.State.StartedAt}}' "$container" 2>/dev/null | cut -d'.' -f1 | sed 's/T/ /g' || echo "Unknown")
            local fields="Container Status;$(echo $status_health | cut -d'|' -f1);true"
            fields+=";Health;$(echo $status_health | cut -d'|' -f2);true"
            fields+=";Started At;$started_at;false"

            send_alert "container" "$title" "$message" "critical" "$fields"

        elif (( $(echo "$cpu_perc > $CPU_WARNING_THRESHOLD" | bc -l) )); then
            log_message "WARNING" "Container '$container' CPU usage high: ${cpu_perc}%"
            # Warning alerts are currently commented out in the original code
        fi
    else
        log_message "WARNING" "Could not parse CPU percentage '$cpu_perc' for container '$container'."
        cpu_perc="N/A" # Set to N/A if parsing failed
    fi

    # --- Memory Usage Check ---
    # Check if mem_perc is a valid number before comparison
    if [[ "$mem_perc" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
         # Use bc for floating point comparison
        if (( $(echo "$mem_perc > $MEM_CRITICAL_THRESHOLD" | bc -l) )); then
            log_message "ERROR" "Container '$container' memory usage critical: ${mem_perc}%"

            # Create alert data
            local title="Container Memory Alert: $container"
            local message="The container **$container** has reported critical memory usage:\n\n"
            message+="**Current Value**: ${mem_perc}%\n"
            message+="**Threshold**: ${MEM_CRITICAL_THRESHOLD}%\n\n"
            message+="Please check the container status and logs."

            # Create fields (reuse from CPU check if possible, or re-fetch)
            local status_health=$(docker inspect --format='{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container" 2>/dev/null || echo "Unknown|Unknown")
            local started_at=$(docker inspect --format='{{.State.StartedAt}}' "$container" 2>/dev/null | cut -d'.' -f1 | sed 's/T/ /g' || echo "Unknown")
            local fields="Container Status;$(echo $status_health | cut -d'|' -f1);true"
            fields+=";Health;$(echo $status_health | cut -d'|' -f2);true"
            fields+=";Started At;$started_at;false"

            send_alert "container" "$title" "$message" "critical" "$fields"

        elif (( $(echo "$mem_perc > $MEM_WARNING_THRESHOLD" | bc -l) )); then
            log_message "WARNING" "Container '$container' memory usage high: ${mem_perc}%"
            # Warning alerts are currently commented out
        fi
    else
        log_message "WARNING" "Could not parse Memory percentage '$mem_perc' for container '$container'."
        mem_perc="N/A" # Set to N/A if parsing failed
    fi

    # Return formatted stats string for display purposes
    echo "${cpu_perc:-N/A}% CPU, ${mem_perc:-N/A}% Memory"
    return 0 # Indicate success in getting stats (even if alerts were sent)
}
# ========================
# Container Monitoring (Continued)
# ========================

check_container_logs() {
    local container="$1"
    # Default search pattern covers common error keywords
    local search_pattern="${2:-error|exception|fatal|failed|crash|unhealthy}"
    local lines_to_check="${3:-100}" # How many recent lines to search

    # Attempt to get logs and search for errors in one go.
    # Use grep -c to count matches directly.
    # Redirect stderr to capture potential "No such container" errors.
    local error_output
    error_output=$(docker logs --tail "$lines_to_check" "$container" 2>&1)
    local logs_exit_code=$?

    # Check if docker logs command failed (e.g., container not found/running)
    if [[ $logs_exit_code -ne 0 ]]; then
        # Check if the error message indicates the container doesn't exist
        if echo "$error_output" | grep -q -i "No such container"; then
             log_message "ERROR" "Container '$container' not found when trying to check logs."
        else
             log_message "ERROR" "Failed to get logs for container '$container'. May not be running. Error: $error_output"
        fi
        return 1 # Indicate failure to check logs
    fi

    # If logs were retrieved, count the errors
    local error_count=$(echo "$error_output" | grep -c -iE "$search_pattern")

    # Check if errors were found
    if [[ $error_count -gt 0 ]]; then
        # Get the actual error lines (limited number for the alert)
        local error_lines=$(echo "$error_output" | grep -iE "$search_pattern" | tail -n 5) # Get last 5 matching lines

        log_message "WARNING" "Found $error_count potential error(s) in the last $lines_to_check lines of '$container' logs."

        # Decide if the error count warrants a critical alert
        # Adjust this threshold (e.g., 5 or 10) as needed
        local critical_error_threshold=10
        if [[ $error_count -ge $critical_error_threshold && "$LOG_NOTIFY" == "true" ]]; then # Also check notification setting
            local title="High Error Count in Logs: $container"
            # Ensure error_lines doesn't break Discord message formatting (escape backticks etc. if needed)
            local message="Found **$error_count** error messages matching pattern \`$search_pattern\` in the recent logs.\n\n"
            message+="Last 5 matching lines:\n\`\`\`\n${error_lines}\n\`\`\`\n\nPlease check container logs using \`docker logs $container\` for details."

            # Fetch status/health for context in the alert
            local status_health=$(docker inspect --format='{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container" 2>/dev/null || echo "Unknown|Unknown")
            local fields="Container Status;$(echo $status_health | cut -d'|' -f1);true"
            fields+=";Health;$(echo $status_health | cut -d'|' -f2);true"
            fields+=";Error Count;$error_count;false"

            send_alert "container-log" "$title" "$message" "error" "$fields"
            return 2 # Return specific code for high errors found
        fi

        # Return 1 even for low error counts found, but maybe don't alert
        return 1 # Indicate errors were found, but maybe not critical level
    fi

    # If no errors were found
    log_message "INFO" "No errors found matching pattern in recent '$container' logs."
    return 0 # OK
}
# MODIFIED: Use jq for docker inspect
display_container_status() {
    echo -e "${CYAN}=== Container Status ===${NC}"
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}Docker not installed${NC}"
        wait_for_key
        return
    fi
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${RED}jq command not found (required for this view).${NC}"
        echo -e "${YELLOW}Please install jq.${NC}"
        wait_for_key
        return
    fi

    for container in "${CONTAINER_NAMES[@]}"; do
        echo -e "\n${CYAN}$container:${NC}"
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            # Get inspect data once
            local inspect_json=$(docker inspect "$container" 2>/dev/null)

            if [[ -z "$inspect_json" ]]; then
                 display_status "ERROR" "Could not inspect container $container"
                 continue
            fi

            # Extract data using jq
            local status=$(echo "$inspect_json" | jq -r '.[0].State.Status // "N/A"')
            local health=$(echo "$inspect_json" | jq -r '.[0].State.Health.Status // "N/A"') # Use // "N/A" for default
            local created_raw=$(echo "$inspect_json" | jq -r '.[0].Created // "N/A"')
            local started_raw=$(echo "$inspect_json" | jq -r '.[0].State.StartedAt // "N/A"')
            # Format dates (remove nanoseconds and 'T')
            local created=$(echo "$created_raw" | cut -d'.' -f1 | sed 's/T/ /g')
            local started=$(echo "$started_raw" | cut -d'.' -f1 | sed 's/T/ /g')

            # Ports (more complex jq needed)
            local ports=$(echo "$inspect_json" | jq -r '.[0].NetworkSettings.Ports | to_entries | map("\(.key) -> \(.value // [] | map("\(.HostIp):\(.HostPort)") | join(", "))") | join(" ") // "N/A"')
            # Mounts (simpler jq)
            local mounts=$(echo "$inspect_json" | jq -r '.[0].Mounts | map("\(.Type):\(.Source) -> \(.Destination)") | join(" ") // "N/A"')

            # Get stats separately (get_container_stats handles CPU/Mem, let's get Net/Block IO here)
            local stats=$(get_container_stats "$container") # Reuse existing function for CPU/Mem%
            local io_stats=$(docker stats --no-stream --format "{{.NetIO}} / {{.BlockIO}}" "$container" 2>/dev/null || echo "N/A / N/A")
            local network=$(echo "$io_stats" | awk -F' / ' '{print $1}')
            local block_io=$(echo "$io_stats" | awk -F' / ' '{print $2}')

            # Display status with appropriate color
            [[ "$status" == "running" && ("$health" == "healthy" || "$health" == "N/A") ]] && \
                display_status "OK" "Status: $status, Health: $health" || \
                display_status "ERROR" "Status: $status, Health: $health"

            # Display additional information
            echo -e "   ${CYAN}Created:${NC} $created"
            echo -e "   ${CYAN}Started:${NC} $started"
            echo -e "   ${CYAN}Resources:${NC} $stats"
            echo -e "   ${CYAN}Network I/O:${NC} $network"
            echo -e "   ${CYAN}Block I/O:${NC} $block_io"

            if [[ -n "$ports" && "$ports" != "N/A" ]]; then
                echo -e "   ${CYAN}Ports:${NC} $ports"
            fi

            if [[ -n "$mounts" && "$mounts" != "N/A" ]]; then
                echo -e "   ${CYAN}Mounts:${NC} $mounts"
            fi
        else
            display_status "ERROR" "Not found"
        fi
    done
    wait_for_key
}

# ========================
# System Monitoring
# ========================

check_cpu_usage() {
    local cpu_usage="N/A"
    local vmstat_output

    # Check if vmstat command is available
    if ! command -v vmstat >/dev/null 2>&1; then
        log_message "ERROR" "'vmstat' command not found. Cannot check CPU usage accurately. Please install 'procps'."
        return 1 # Return warning state
    fi

    # Get CPU idle percentage averaged over 1 second (2 samples, 1 interval)
    # The second line of output contains the average over the interval
    # The 'id' column is typically the 15th field
    vmstat_output=$(vmstat 1 2 | tail -n 1)
    local exit_code=$?
    local cpu_idle

    if [[ $exit_code -eq 0 && -n "$vmstat_output" ]]; then
        cpu_idle=$(echo "$vmstat_output" | awk '{print $15}')

        # Check if cpu_idle looks like a valid number (0-100)
        if [[ "$cpu_idle" =~ ^[0-9]+$ && "$cpu_idle" -ge 0 && "$cpu_idle" -le 100 ]]; then
            # Calculate usage: 100 - idle. Use bc for calculation.
            cpu_usage=$(echo "scale=1; 100 - $cpu_idle" | bc)

            # Ensure result is non-negative and format
             if (( $(echo "$cpu_usage < 0" | bc -l) )); then cpu_usage="0.0"; fi
             cpu_usage=$(printf "%.1f" "$cpu_usage")
        else
            log_message "WARNING" "Could not parse CPU idle value ($cpu_idle) from vmstat output: $vmstat_output"
            cpu_usage="N/A"
        fi
    else
        log_message "ERROR" "Failed to get CPU usage from vmstat command (Exit code: $exit_code)."
        cpu_usage="N/A"
    fi

    log_message "INFO" "System CPU usage (avg 1s): ${cpu_usage}%"

    # Check against thresholds only if we have a valid numeric value
    if [[ "$cpu_usage" != "N/A" && "$cpu_usage" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        if (( $(echo "$cpu_usage > $CPU_CRITICAL_THRESHOLD" | bc -l) )); then
            log_message "ERROR" "System CPU usage critical: ${cpu_usage}%"

            # Get top processes consuming CPU (ps output is still a snapshot)
            local top_processes=$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6 | tail -n 5)
            local message="❗ System CPU usage critical: **${cpu_usage}%** (Threshold: ${CPU_CRITICAL_THRESHOLD}%)\n\n"
            message+="Top 5 CPU processes (snapshot):\n\`\`\`\n${top_processes}\n\`\`\`"

            # Add a small sleep before alert to potentially help with rate limits
            sleep 2
            send_alert "system-cpu" "CPU Alert" "$message" "critical" ""
            return 2 # Critical
        elif (( $(echo "$cpu_usage > $CPU_WARNING_THRESHOLD" | bc -l) )); then
            log_message "WARNING" "System CPU usage high: ${cpu_usage}%"
            return 1 # Warning
        fi
        # If below warning threshold
        return 0 # OK
    else
        # If cpu_usage is N/A or not numeric
        return 1 # Return warning state if CPU couldn't be determined
    fi
}
# ========================
# System Monitoring (Continued)
# ========================

check_memory_usage() {
    local mem_usage_perc="N/A"
    local free_output

    # Get memory usage using free -m (Megabytes)
    # awk on the second line (NR==2) calculates used/total * 100
    free_output=$(free -m)
    local exit_code=$?

    if [[ $exit_code -eq 0 && -n "$free_output" ]]; then
        # Using awk to calculate percentage: (used / total) * 100
        mem_usage_perc=$(echo "$free_output" | awk 'NR==2 {if ($2 > 0) printf "%.1f", $3*100/$2; else print "0.0"}')

        # Check if awk succeeded and produced a number
        if ! [[ "$mem_usage_perc" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
             log_message "WARNING" "Could not parse memory usage percentage from free -m output."
             mem_usage_perc="N/A"
        fi
    else
        log_message "ERROR" "Failed to get memory usage from free command."
        mem_usage_perc="N/A"
    fi

    log_message "INFO" "System Memory usage: ${mem_usage_perc}%"

    # Check against thresholds only if we have a valid numeric value
    if [[ "$mem_usage_perc" != "N/A" && "$mem_usage_perc" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        if (( $(echo "$mem_usage_perc > $MEM_CRITICAL_THRESHOLD" | bc -l) )); then
            log_message "ERROR" "System Memory usage critical: ${mem_usage_perc}%"

            # Get top memory processes
            local top_processes=$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 6 | tail -n 5)
            local message="❗ System Memory usage critical: **${mem_usage_perc}%** (Threshold: ${MEM_CRITICAL_THRESHOLD}%)\n\n"
            message+="Top 5 Memory processes:\n\`\`\`\n${top_processes}\n\`\`\`"

            send_alert "system-mem" "Memory Alert" "$message" "critical" ""
            return 2 # Critical
        elif (( $(echo "$mem_usage_perc > $MEM_WARNING_THRESHOLD" | bc -l) )); then
            log_message "WARNING" "System Memory usage high: ${mem_usage_perc}%"
            # Optionally send warning alert
            # local message="⚠️ System Memory usage high: ${mem_usage_perc}% (Threshold: ${MEM_WARNING_THRESHOLD}%)"
            # send_alert "system-mem" "Memory Warning" "$message" "warning" ""
            return 1 # Warning
        fi
        # If below warning threshold
        return 0 # OK
    else
        # If mem_usage_perc is N/A or not numeric
        return 1 # Return warning state if Memory usage couldn't be determined
    fi
}
# MODIFIED: Removed 'du' command for alert details
check_disk_usage() {
    local disk=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    [[ -z "$disk" ]] && disk="N/A"
    log_message "INFO" "Disk usage: ${disk}%"

    if [[ "$disk" != "N/A" ]]; then
        if (( $(echo "$disk > $DISK_CRITICAL_THRESHOLD" | bc -l) )); then
            log_message "ERROR" "Disk usage critical: ${disk}%"

            # MODIFIED: Simplified message, removed 'du' call
            local message="❗ Disk usage critical: ${disk}%\n\nPlease investigate disk usage on the root filesystem."

            send_alert "system" "Disk Alert" "$message" "critical" ""
            return 2
        elif (( $(echo "$disk > $DISK_WARNING_THRESHOLD" | bc -l) )); then
            log_message "WARNING" "Disk usage high: ${disk}%"
            # Optionally send a warning alert here too, if desired
            # local message="⚠️ Disk usage warning: ${disk}%\n\nConsider clearing space on the root filesystem."
            # send_alert "system" "Disk Warning" "$message" "warning" ""
            return 1
        fi
    fi
    return 0
}

# ========================
# System Monitoring (Continued)
# ========================

check_system_load() {
    local load_avg_1min="N/A"
    local core_count="N/A"
    local normalized_load="N/A"
    local uptime_output

    # Get load average and core count
    uptime_output=$(uptime)
    local exit_code_uptime=$?
    core_count=$(nproc 2>/dev/null) # Get number of processing units available
    local exit_code_nproc=$?

    if [[ $exit_code_uptime -eq 0 && -n "$uptime_output" ]]; then
         # Extract the 1-minute load average
         load_avg_1min=$(echo "$uptime_output" | awk -F'[a-z]:' '{print $2}' | sed 's/,//g' | awk '{print $1}')
         # Verify it looks like a number (allowing . or , initially from uptime)
         if ! [[ "$load_avg_1min" =~ ^[0-9]+([.,][0-9]+)?$ ]]; then
              log_message "WARNING" "Could not parse 1-minute load average from uptime output: $uptime_output"
              load_avg_1min="N/A"
         else
              # Ensure load average uses '.' for bc calculation
              load_avg_1min=$(echo "$load_avg_1min" | tr ',' '.')
         fi
    else
         log_message "ERROR" "Failed to get uptime information."
         load_avg_1min="N/A"
    fi

    if [[ $exit_code_nproc -ne 0 || ! "$core_count" =~ ^[1-9][0-9]*$ ]]; then
         log_message "ERROR" "Failed to get valid core count using nproc."
         core_count="N/A"
    fi

    # Calculate normalized load if possible
    if [[ "$load_avg_1min" != "N/A" && "$core_count" != "N/A" ]]; then
        # Force C locale for bc to ensure '.' decimal separator
        normalized_load=$(LC_ALL=C echo "scale=2; $load_avg_1min / $core_count" | bc)

        # ** FIX: Add leading zero if bc output starts with '.' **
        if [[ "$normalized_load" == .* ]]; then
            normalized_load="0$normalized_load"
        fi

        # Verify bc output looks reasonable (should now match N.NN or 0.NN)
        if ! [[ "$normalized_load" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
             log_message "WARNING" "Could not calculate or validate normalized load from bc output (Result after fix attempt: '$normalized_load'). Inputs: Load='$load_avg_1min', Cores='$core_count'."
             normalized_load="N/A"
        fi
    fi

    log_message "INFO" "System load: $load_avg_1min (Cores: $core_count, Normalized: ${normalized_load}x)"

    # Check against thresholds only if we have a valid normalized load
    if [[ "$normalized_load" != "N/A" ]]; then
        # Define load thresholds (e.g., normalized load > 2.0 is critical, > 1.0 is warning)
        local load_critical_threshold="2.0"
        local load_warning_threshold="1.0"

        # Use LC_ALL=C for bc comparisons too for consistency
        if (( $(LC_ALL=C echo "$normalized_load > $load_critical_threshold" | bc -l) )); then
            log_message "ERROR" "System load critical: ${normalized_load}x (Raw: $load_avg_1min, Cores: $core_count)"

            # Get top processes by CPU
            local top_processes=$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6 | tail -n 5)
            local message="❗ System load critical: **${normalized_load}x** (Threshold: > ${load_critical_threshold}x)\n"
            message+="Raw 1-min load: $load_avg_1min, CPU Cores: $core_count\n\n"
            message+="Top 5 CPU processes:\n\`\`\`\n${top_processes}\n\`\`\`"

            # Add a small sleep before alert to potentially help with rate limits
            sleep 2
            send_alert "system-load" "System Load Alert" "$message" "critical" ""
            return 2 # Critical
        elif (( $(LC_ALL=C echo "$normalized_load > $load_warning_threshold" | bc -l) )); then
            log_message "WARNING" "System load high: ${normalized_load}x (Raw: $load_avg_1min, Cores: $core_count)"
            # No immediate alert for warning load by default
            return 1 # Warning
        fi
        # If below warning threshold
        return 0 # OK
    else
        # If normalized_load is N/A
        return 1 # Return warning state if load couldn't be determined/normalized
    fi
}

# ========================
# System Monitoring Display
# ========================

display_system_resources() {
    echo -e "${CYAN}=== System Resources Overview ===${NC}"

    # --- Gather System Information ---
    local hostname=$(hostname)
    local os_name=$(cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2 || echo "Unknown")
    local kernel_ver=$(uname -r)
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -n1 | cut -d':' -f2 | sed 's/^[ \t]*//' || echo "Unknown")
    local core_count=$(nproc 2>/dev/null || echo "N/A")
    local sys_uptime=$(uptime -p 2>/dev/null || uptime || echo "Unknown") # uptime -p might fail

    # --- Gather Resource Usage Metrics ---

    # CPU (using vmstat like in check_cpu_usage)
    local cpu_usage="N/A"
    if command -v vmstat >/dev/null 2>&1; then
        local vmstat_output=$(vmstat 1 2 | tail -n 1)
        local cpu_idle=$(echo "$vmstat_output" | awk '{print $15}')
        if [[ "$cpu_idle" =~ ^[0-9]+$ && "$cpu_idle" -ge 0 && "$cpu_idle" -le 100 ]]; then
            cpu_usage=$(LC_ALL=C printf "%.1f" $(echo "100 - $cpu_idle" | bc))
        fi
    else
         log_message "WARNING" "vmstat not found for CPU usage display."
    fi

    # Memory (using free like in check_memory_usage)
    local mem_usage="N/A"
    local mem_used="N/A"
    local mem_total="N/A"
    local free_output=$(free -m) # Use -m for calculation
    local free_output_h=$(free -h) # Use -h for display
    if [[ -n "$free_output" ]]; then
        mem_usage=$(echo "$free_output" | awk 'NR==2 {if ($2 > 0) printf "%.1f", $3*100/$2; else print "0.0"}')
        mem_used=$(echo "$free_output_h" | awk 'NR==2{print $3}')
        mem_total=$(echo "$free_output_h" | awk 'NR==2{print $2}')
        # Validate mem_usage
        if ! [[ "$mem_usage" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then mem_usage="N/A"; fi
    fi

    # Disk (using df like in check_disk_usage)
    local disk_usage="N/A"
    local disk_used="N/A"
    local disk_total="N/A"
    local df_output=$(df -h /)
     if [[ -n "$df_output" ]]; then
        disk_usage=$(echo "$df_output" | awk 'NR==2 {print $5}') # Includes '%'
        disk_used=$(echo "$df_output" | awk 'NR==2 {print $3}')
        disk_total=$(echo "$df_output" | awk 'NR==2 {print $2}')
        # Validate disk_usage percentage part
        if ! [[ "${disk_usage%%%}" =~ ^[0-9]+$ ]]; then disk_usage="N/A"; fi
    fi

    # Load (using logic from fixed check_system_load)
    local load_avg_1min="N/A"
    local normalized_load="N/A"
    local uptime_output=$(uptime)
    if [[ -n "$uptime_output" ]]; then
         load_avg_1min=$(echo "$uptime_output" | awk -F'[a-z]:' '{print $2}' | sed 's/,//g' | awk '{print $1}')
         if [[ "$load_avg_1min" =~ ^[0-9]+([.,][0-9]+)?$ ]]; then
              load_avg_1min_bc=$(echo "$load_avg_1min" | tr ',' '.') # Ensure '.' for bc
              if [[ "$core_count" != "N/A" ]]; then
                   normalized_load=$(LC_ALL=C echo "scale=2; $load_avg_1min_bc / $core_count" | bc)
                   if [[ "$normalized_load" == .* ]]; then normalized_load="0$normalized_load"; fi
                   if ! [[ "$normalized_load" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then normalized_load="N/A"; fi
              fi
         else
              load_avg_1min="N/A" # Failed parsing uptime
         fi
    fi

    # --- Display System Information ---
    echo -e "${CYAN}System Information:${NC}"
    echo -e "  Hostname:   $hostname"
    echo -e "  OS:         $os_name"
    echo -e "  Kernel:     $kernel_ver"
    echo -e "  CPU:        $cpu_model ($core_count cores)"
    echo -e "  Uptime:     $sys_uptime"

    # --- Display Resource Usage Summary ---
    echo -e "\n${CYAN}Resource Usage Summary:${NC}"
    # CPU
    if [[ "$cpu_usage" != "N/A" ]] && (( $(LC_ALL=C echo "$cpu_usage > $CPU_WARNING_THRESHOLD" | bc -l) )); then
        display_status "WARNING" "CPU Usage: ${cpu_usage}%"
    else
        display_status "OK" "CPU Usage: ${cpu_usage}%"
    fi
    # Memory
    if [[ "$mem_usage" != "N/A" ]] && (( $(LC_ALL=C echo "$mem_usage > $MEM_WARNING_THRESHOLD" | bc -l) )); then
        display_status "WARNING" "Memory Usage: ${mem_usage}% (${mem_used:-N/A} / ${mem_total:-N/A})"
    else
        display_status "OK" "Memory Usage: ${mem_usage}% (${mem_used:-N/A} / ${mem_total:-N/A})"
    fi
    # Disk
    local disk_perc_val="${disk_usage%%%}" # Remove %
    if [[ "$disk_perc_val" =~ ^[0-9]+$ ]] && (( disk_perc_val > $DISK_WARNING_THRESHOLD )); then
        display_status "WARNING" "Disk Usage (/): ${disk_usage} (${disk_used:-N/A} / ${disk_total:-N/A})"
    else
        display_status "OK" "Disk Usage (/): ${disk_usage} (${disk_used:-N/A} / ${disk_total:-N/A})"
    fi
    # Load
    local load_warning_threshold="1.0" # Define threshold for display
    if [[ "$normalized_load" != "N/A" ]] && (( $(LC_ALL=C echo "$normalized_load > $load_warning_threshold" | bc -l) )); then
        display_status "WARNING" "Load Average (1m): $load_avg_1min (Normalized: ${normalized_load}x)"
    else
        display_status "OK" "Load Average (1m): $load_avg_1min (Normalized: ${normalized_load}x)"
    fi

    # --- Display Resource Details ---
    echo -e "\n${CYAN}Memory Details (free -h):${NC}"
    free -h | grep --color=never -v "Swap" || echo "  Error running 'free -h'"

    echo -e "\n${CYAN}Disk Usage (df -h):${NC}"
    # Filter out snap loops, tmpfs, etc. for clarity
    df -h -x squashfs -x tmpfs -x devtmpfs | grep --color=never -E '^/dev/|Filesystem' || echo "  Error running 'df -h'"

    echo -e "\n${CYAN}Top 5 CPU Processes (ps):${NC}"
    ps -eo pid,user,%cpu,cmd --sort=-%cpu --no-headers | head -n 5 || echo "  Error running 'ps'"

    echo -e "\n${CYAN}Top 5 Memory Processes (ps):${NC}"
    ps -eo pid,user,%mem,cmd --sort=-%mem --no-headers | head -n 5 || echo "  Error running 'ps'"

    wait_for_key
}

# ========================
# Security Monitoring
# ========================

check_ssh_attempts() {
    echo -e "${CYAN}=== SSH Login Attempts (Last 24 Hours) ===${NC}"
    local found_logs=false
    local log_source=""

    # --- Try journalctl ---
    if command -v journalctl >/dev/null 2>&1; then
        log_source="journalctl"
        local journal_cmd=""
        # Check primary service names first
        if journalctl --quiet -u ssh -u sshd --since "1 day ago" &>/dev/null; then
             journal_cmd="journalctl -u ssh -u sshd --since \"1 day ago\" --no-pager --output cat" # --output cat avoids extra formatting
             found_logs=true
             log_message "DEBUG" "Found SSH logs via journalctl (ssh/sshd units)."
        # Try alternative service name
        elif journalctl --quiet -u sshd.service --since "1 day ago" &>/dev/null; then
             journal_cmd="journalctl -u sshd.service --since \"1 day ago\" --no-pager --output cat"
             found_logs=true
             log_message "DEBUG" "Found SSH logs via journalctl (sshd.service unit)."
        fi

        if [[ "$found_logs" == "true" ]]; then
            echo -e "\n${CYAN}Log Source:${NC} journalctl"
            echo -e "${CYAN}Failed Attempts:${NC}"
            # Use eval to execute the command string correctly with quotes
            eval "$journal_cmd" 2>/dev/null | grep "Failed password" | tail -n 10 || echo "  None found."

            echo -e "\n${CYAN}Successful Logins:${NC}"
            eval "$journal_cmd" 2>/dev/null | grep "Accepted" | tail -n 5 || echo "  None found."

            # IP statistics for failed logins
            echo -e "\n${CYAN}Failed Login IPs (Top 5):${NC}"
            # Extract IPs using grep -oE, handle potential 'invalid user' lines without IPs
            local failed_ips=$(eval "$journal_cmd" 2>/dev/null | grep "Failed password" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | sort | uniq -c | sort -nr | head -n 5)
            if [[ -n "$failed_ips" ]]; then
                 echo "$failed_ips" | awk '{printf "  %s: %s attempts\n", $2, $1}'
            else
                 echo "  None found."
            fi
        fi
    fi # End journalctl check

    # --- Try /var/log/auth.log (Debian/Ubuntu style) ---
    local auth_log="/var/log/auth.log"
    if [[ "$found_logs" == "false" && -f "$auth_log" && -r "$auth_log" ]]; then
        log_source="$auth_log"
        # Check if the log actually contains recent SSH activity
        if grep -q -E 'sshd.*(Accepted|Failed password)' <(tail -n 500 "$auth_log" 2>/dev/null); then
             found_logs=true
             log_message "DEBUG" "Found SSH logs via $auth_log."
        fi

        if [[ "$found_logs" == "true" ]]; then
            echo -e "\n${CYAN}Log Source:${NC} $auth_log"
            echo -e "${CYAN}Failed Attempts (Recent):${NC}"
            grep "sshd.*Failed password" "$auth_log" 2>/dev/null | tail -n 10 || echo "  None found."

            echo -e "\n${CYAN}Successful Logins (Recent):${NC}"
            grep "sshd.*Accepted" "$auth_log" 2>/dev/null | tail -n 5 || echo "  None found."

            # IP statistics
            echo -e "\n${CYAN}Failed Login IPs (Top 5, Recent):${NC}"
            local failed_ips=$(grep "sshd.*Failed password" "$auth_log" 2>/dev/null | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | sort | uniq -c | sort -nr | head -n 5)
             if [[ -n "$failed_ips" ]]; then
                 echo "$failed_ips" | awk '{printf "  %s: %s attempts\n", $2, $1}'
            else
                 echo "  None found."
            fi
        fi
    fi # End auth.log check

    # --- Try /var/log/secure (RHEL/CentOS style) ---
    local secure_log="/var/log/secure"
     if [[ "$found_logs" == "false" && -f "$secure_log" && -r "$secure_log" ]]; then
        log_source="$secure_log"
        # Check if the log actually contains recent SSH activity
        if grep -q -E 'sshd.*(Accepted|Failed password)' <(tail -n 500 "$secure_log" 2>/dev/null); then
             found_logs=true
             log_message "DEBUG" "Found SSH logs via $secure_log."
        fi

        if [[ "$found_logs" == "true" ]]; then
            echo -e "\n${CYAN}Log Source:${NC} $secure_log"
            echo -e "${CYAN}Failed Attempts (Recent):${NC}"
            grep "sshd.*Failed password" "$secure_log" 2>/dev/null | tail -n 10 || echo "  None found."

            echo -e "\n${CYAN}Successful Logins (Recent):${NC}"
            grep "sshd.*Accepted" "$secure_log" 2>/dev/null | tail -n 5 || echo "  None found."

            # IP statistics
            echo -e "\n${CYAN}Failed Login IPs (Top 5, Recent):${NC}"
            local failed_ips=$(grep "sshd.*Failed password" "$secure_log" 2>/dev/null | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | sort | uniq -c | sort -nr | head -n 5)
             if [[ -n "$failed_ips" ]]; then
                 echo "$failed_ips" | awk '{printf "  %s: %s attempts\n", $2, $1}'
            else
                 echo "  None found."
            fi
        fi
    fi # End secure.log check


    # --- If no logs were found or readable ---
    if [[ "$found_logs" == "false" ]]; then
        echo -e "\n${RED}Could not find or access SSH logs.${NC}"
        echo -e "${YELLOW}Checked common sources: journalctl, $auth_log, $secure_log${NC}"
        echo -e "${YELLOW}Possible reasons:${NC}"
        echo -e "  - SSH service logging to a different location."
        echo -e "  - Insufficient permissions to read log files/journal."
        echo -e "  - No SSH activity recorded recently."
        log_message "WARNING" "Could not find readable SSH logs."
        if [[ $EUID -ne 0 ]]; then
            echo -e "\n${YELLOW}Try running the script with 'sudo' for better log access.${NC}"
        fi
    fi

    wait_for_key
}
# ========================
# Security Monitoring (Continued)
# ========================

check_security_logs() {
    log_message "DEBUG" "Running security log checks..."
    local issues_found=0 # Use descriptive variable name
    local alert_details="" # String to build for potential general alert

    # --- Check SSH Failures and Sudo Usage ---
    local ssh_failure_count=0
    local sudo_command_count=0
    local log_source="Unknown"

    # Decide which log source to use
    if command -v journalctl >/dev/null 2>&1; then
        log_source="journalctl"
        log_message "DEBUG" "Checking journalctl for SSH failures and sudo usage."
        # Use process substitution and check exit codes for reliability
        ssh_failure_count=$(journalctl -u ssh -u sshd --since "1 hour ago" --no-pager --output cat 2>/dev/null | grep -c "Failed password" || echo 0)
        sudo_command_count=$(journalctl --since "1 day ago" --no-pager --output cat 2>/dev/null | grep "sudo:" | grep -c "COMMAND=" || echo 0)

    elif [[ -f "/var/log/auth.log" && -r "/var/log/auth.log" ]]; then
        log_source="/var/log/auth.log"
        log_message "DEBUG" "Checking $log_source for SSH failures and sudo usage."
        ssh_failure_count=$(grep "sshd.*Failed password" "$log_source" 2>/dev/null | wc -l) # Use wc -l, more reliable than grep -c on files sometimes
        sudo_command_count=$(grep "sudo:.*COMMAND=" "$log_source" 2>/dev/null | wc -l)

    elif [[ -f "/var/log/secure" && -r "/var/log/secure" ]]; then
        log_source="/var/log/secure"
        log_message "DEBUG" "Checking $log_source for SSH failures and sudo usage."
        ssh_failure_count=$(grep "sshd.*Failed password" "$log_source" 2>/dev/null | wc -l)
        sudo_command_count=$(grep "sudo:.*COMMAND=" "$log_source" 2>/dev/null | wc -l)
    else
         log_message "WARNING" "Could not find a suitable source for security log checks (journalctl, auth.log, secure)."
    fi

    # Ensure counts are numeric (should be from grep -c or wc -l, but sanitize anyway)
    [[ "$ssh_failure_count" =~ ^[0-9]+$ ]] || ssh_failure_count=0
    [[ "$sudo_command_count" =~ ^[0-9]+$ ]] || sudo_command_count=0

    log_message "DEBUG" "Security Log Check Results - Source: $log_source, SSH Failures (1h): $ssh_failure_count, Sudo Commands (1d): $sudo_command_count"

    # --- Analyze SSH Failures ---
    local ssh_failure_threshold=10
    local ssh_bruteforce_threshold=50 # Higher threshold for specific brute-force alert

    if (( ssh_failure_count > ssh_failure_threshold )); then
        issues_found=1
        alert_details+="\n- $(emoji_map ':warning:') $ssh_failure_count SSH failures in the last hour."
        log_message "WARNING" "$ssh_failure_count SSH failures detected in the last hour (Source: $log_source)."

        # Send specific Brute Force alert if count is very high
        if (( ssh_failure_count > ssh_bruteforce_threshold && "$ATTACK_NOTIFY" == "true" )); then
            log_message "ERROR" "Excessive SSH failures ($ssh_failure_count) detected, potential brute force attack."
            local ip_stats="Could not determine IPs." # Default message

            # Try to get top attacking IPs
            local ip_extract_cmd=""
            if [[ "$log_source" == "journalctl" ]]; then
                 # Command for journalctl IP extraction
                 ip_extract_cmd="journalctl -u ssh -u sshd --since \"1 hour ago\" --no-pager --output cat 2>/dev/null | grep \"Failed password\" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print \$2}' | sort | uniq -c | sort -nr | head -n 5"
            elif [[ "$log_source" == "/var/log/auth.log" || "$log_source" == "/var/log/secure" ]]; then
                 # Command for file log IP extraction
                 ip_extract_cmd="grep \"sshd.*Failed password\" \"$log_source\" 2>/dev/null | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print \$2}' | sort | uniq -c | sort -nr | head -n 5"
            fi

            if [[ -n "$ip_extract_cmd" ]]; then
                 local top_ips=$(eval "$ip_extract_cmd")
                 if [[ -n "$top_ips" ]]; then
                     # Format IPs for the message
                     ip_stats=$(echo "$top_ips" | awk '{printf "  - %s (%s attempts)\n", $2, $1}')
                 fi
            fi

            local message="❗ **Security Alert: Excessive SSH Failures**\n\n"
            message+="Detected **$ssh_failure_count** SSH login failures on \`$(hostname)\` in the last hour (via $log_source).\n\n"
            message+="**Top source IPs:**\n\`\`\`\n$ip_stats\n\`\`\`\n\n"
            message+="This may indicate a brute force attack. Consider checking firewall, fail2ban, or CrowdSec."

            send_alert "security-ssh" "SSH Brute Force Alert" "$message" "critical" "" # Use critical severity
        fi
    fi

    # --- Analyze Sudo Usage ---
    local sudo_usage_threshold=20 # Commands in last 24h

    if (( sudo_command_count > sudo_usage_threshold )); then
        issues_found=1
        alert_details+="\n- $(emoji_map ':warning:') $sudo_command_count sudo commands used in the last day."
        log_message "WARNING" "High sudo usage detected: $sudo_command_count commands in the last day (Source: $log_source)."
        # Consider if a specific alert is needed for very high sudo usage
    fi

    # --- Check for rootkits (Optional) ---
    if command -v chkrootkit >/dev/null 2>&1; then
        log_message "DEBUG" "Running chkrootkit scan..."
        # Run quietly (-q), redirect stderr, filter common "not found/infected" messages
        local rootkit_check_output=$(chkrootkit -q 2>&1 | grep -v -E "not found|nothing found|not infected|Searching|Checking")
        if [[ -n "$rootkit_check_output" ]]; then
            issues_found=1
            # Sanitize output slightly for logging/alerting
            local sanitized_output=$(echo "$rootkit_check_output" | head -n 5 | sed 's/[^a-zA-Z0-9 .,:()/-_]/_/g') # Limit lines and replace odd chars
            alert_details+="\n- $(emoji_map ':x:') Potential rootkit findings: $sanitized_output"
            log_message "CRITICAL" "Potential rootkit detected by chkrootkit! Output: $sanitized_output"

            local message="❗ **CRITICAL Security Alert: Potential Rootkit Detected**\n\n"
            message+="Chkrootkit check on \`$(hostname)\` reported potential issues:\n\`\`\`\n${sanitized_output}\n\`\`\`\n\n"
            message+="**Manual investigation is required immediately!** Check system integrity and logs."

            send_alert "security-rootkit" "Rootkit Alert" "$message" "critical" ""
        else
             log_message "DEBUG" "chkrootkit scan completed, no suspicious findings reported."
        fi
    else
         log_message "DEBUG" "chkrootkit command not found, skipping rootkit check."
    fi

    # --- Send General Security Issues Summary (if minor issues found but no critical alert sent) ---
    # This part was in the original, let's keep it but maybe refine condition
    # Only send if issues were found AND specific critical alerts weren't already sent (needs better state tracking maybe)
    # For now, let's send if issues_found=1, understanding it might duplicate info from specific alerts.
    if [[ $issues_found -eq 1 && "$LOG_NOTIFY" == "true" ]]; then # Also check general notification setting
        # Check if a critical alert was likely sent (simplistic check)
        local critical_alert_sent=false
        if (( ssh_failure_count > ssh_bruteforce_threshold )) || [[ -n "$rootkit_check_output" ]]; then
             critical_alert_sent=true
        fi

        # Only send summary if no critical alert was sent, to avoid noise
        if [[ "$critical_alert_sent" == "false" ]]; then
            log_message "WARNING" "Sending general security issues summary."
            send_alert "security-summary" "Security Issues Summary" "$(emoji_map ':shield:') Minor security issues detected on \`$(hostname)\`:$alert_details" "warning" ""
        fi
    fi

    return $issues_found # 0 if no issues, 1 if minor issues, potentially >1 if we used different codes
}

# ========================
# Traefik Log Analysis
# ========================

analyze_traefik_logs() {
    echo -e "${CYAN}=== Traefik Access Logs Analysis ===${NC}"
    local traefik_container_name="traefik" # Assuming this is the name

    # Check if the container exists and is running using inspect
    local container_status
    container_status=$(docker inspect --format='{{.State.Status}}' "$traefik_container_name" 2>/dev/null)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        echo -e "${RED}Traefik container ('$traefik_container_name') not found.${NC}"
        wait_for_key
        return 1
    fi

    if [[ "$container_status" != "running" ]]; then
        echo -e "${RED}Traefik container ('$traefik_container_name') is not running (Status: $container_status).${NC}"
        wait_for_key
        return 1
    fi

    log_message "DEBUG" "Fetching last 1000 log lines for '$traefik_container_name'."
    # Get recent logs from Traefik container
    # Use timeout in case logs are huge or docker hangs
    local logs=$(timeout 10 docker logs "$traefik_container_name" --tail 1000 2>/dev/null)
    local logs_exit_code=$?

    if [[ $logs_exit_code -ne 0 ]]; then
         echo -e "${RED}Failed to retrieve logs for '$traefik_container_name' (Exit code: $logs_exit_code).${NC}"
         wait_for_key
         return 1
    fi

    if [[ -z "$logs" ]]; then
        echo -e "${YELLOW}No recent logs found for '$traefik_container_name' container.${NC}"
        wait_for_key
        return 0 # Not an error, just no logs to analyze
    fi

    echo -e "\n${CYAN}--- Analysis of last 1000 log entries ---${NC}"

    # --- HTTP Status Code Analysis ---
    # This grep might depend heavily on Traefik's log format (Common Log Format assumed)
    echo -e "\n${CYAN}HTTP Request Methods:${NC}"
    # Count occurrences of common methods found within quotes (e.g., "GET / HTTP/1.1")
    echo "$logs" | grep -oE '"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ' | sort | uniq -c | sort -nr || echo "  No standard methods found."

    echo -e "\n${CYAN}HTTP Status Codes (Summary):${NC}"
    # Extract status codes (e.g., HTTP/1.1" 200)
    echo "$logs" | grep -oE '" [1-5][0-9]{2} ' | awk '{print $1}' | sort | uniq -c | sort -nr || echo "  No status codes found."

    echo -e "\n${CYAN}Client Error Codes (4xx):${NC}"
    echo "$logs" | grep -E '" 4[0-9]{2} ' | awk '{print $NF}' | sort | uniq -c | sort -nr || echo "  None found." # Assuming code is last field after quote space

    echo -e "\n${CYAN}Server Error Codes (5xx):${NC}"
    echo "$logs" | grep -E '" 5[0-9]{2} ' | awk '{print $NF}' | sort | uniq -c | sort -nr || echo "  None found."

    # --- Top Requested URLs (Limited Usefulness without context) ---
    echo -e "\n${CYAN}Top Requested URLs (approx):${NC}"
    # Extracts method and path, might include query strings
    echo "$logs" | grep -oE '"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^"]+"' | awk '{print $1, $2}' | sort | uniq -c | sort -nr | head -n 10 || echo "  None found."

    # --- Top Client IPs ---
    echo -e "\n${CYAN}Top Client IPs:${NC}"
    # Extracts the first valid-looking IPv4 address on each line (usually the client IP in CLF)
    echo "$logs" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1 | sort | uniq -c | sort -nr | head -n 10 || echo "  None found."


    # --- Basic Security Pattern Detection ---
    echo -e "\n${CYAN}Potential Attack Patterns (Basic Scan):${NC}"
    local suspicious_count=0

    # SQL Injection attempts (very basic patterns)
    local sql_injection_count=$(echo "$logs" | grep -c -iE "(select%20|union%20|insert%20|drop%20|%20--|'--|%27--|xp_cmdshell)")
    if (( sql_injection_count > 0 )); then
        echo -e "  ${YELLOW}SQL Injection patterns:${NC} $sql_injection_count"
        suspicious_count=$((suspicious_count + sql_injection_count))
    fi

    # Cross-Site Scripting (XSS) attempts (very basic patterns)
    local xss_count=$(echo "$logs" | grep -c -iE "(<script|%3Cscript|javascript:|alert\(|%22>|%3E%3C)")
    if (( xss_count > 0 )); then
        echo -e "  ${YELLOW}XSS patterns:${NC} $xss_count"
        suspicious_count=$((suspicious_count + xss_count))
    fi

    # Path traversal attempts
    local path_traversal_count=$(echo "$logs" | grep -c -iE "(\.\.\/|\.\.%2f|%2e%2e%2f|etc/passwd|win.ini)")
     if (( path_traversal_count > 0 )); then
        echo -e "  ${YELLOW}Path Traversal patterns:${NC} $path_traversal_count"
        suspicious_count=$((suspicious_count + path_traversal_count))
    fi

    # Common scanner user agents
    local scanner_ua_count=$(echo "$logs" | grep -c -iE "(nmap|sqlmap|nikto|wpscan|gobuster|feroxbuster)")
    if (( scanner_ua_count > 0 )); then
        echo -e "  ${YELLOW}Scanner User-Agents:${NC} $scanner_ua_count"
        suspicious_count=$((suspicious_count + scanner_ua_count))
    fi

    # PHP-related probes (if not expecting PHP)
    local php_probes_count=$(echo "$logs" | grep -c -iE "(\.php |phpmyadmin|wp-login)")
    if (( php_probes_count > 0 )); then
        echo -e "  ${YELLOW}PHP-related probes:${NC} $php_probes_count"
        suspicious_count=$((suspicious_count + php_probes_count))
    fi


    # High volume check (reusing Top Client IPs logic, threshold adjustable)
    local high_volume_threshold=50 # requests per 1000 log lines
    local high_volume_ips=$(echo "$logs" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1 | sort | uniq -c | sort -nr | awk -v threshold="$high_volume_threshold" '$1 > threshold {print $1, $2}')
    if [[ -n "$high_volume_ips" ]]; then
        echo -e "  ${YELLOW}High Volume IPs (> $high_volume_threshold requests):${NC}"
        echo "$high_volume_ips" | while read count ip; do
            echo -e "    - $ip: $count requests"
            suspicious_count=$((suspicious_count + count)) # Add to total suspicious count
        done
    fi

    if (( suspicious_count == 0 )); then
         echo -e "  ${GREEN}No obvious suspicious patterns detected in this sample.${NC}"
    else
         log_message "WARNING" "Found $suspicious_count potential suspicious patterns in Traefik logs."
         # Consider sending a Discord alert if count is high and notifications are enabled
         # if (( suspicious_count > 20 && "$ATTACK_NOTIFY" == "true" )); then ... send_alert ... fi
    fi

    wait_for_key
}

# ========================
# NEW: Container Image Update Check (using skopeo)
# ========================

check_container_image_updates() {
    log_message "INFO" "Checking for container image updates using skopeo"
    echo -e "${CYAN}=== Checking Container Image Updates ===${NC}"

    # Check dependencies
    if ! command -v skopeo >/dev/null 2>&1; then
        log_message "ERROR" "skopeo command not found. Cannot check for image updates."
        echo -e "${RED}skopeo command not found. Please install skopeo.${NC}"
        return 1
    fi
    if ! command -v jq >/dev/null 2>&1; then
        log_message "ERROR" "jq command not found. Cannot process skopeo output."
        echo -e "${RED}jq command not found. Please install jq.${NC}"
        return 1
    fi
    if ! command -v docker >/dev/null 2>&1; then
        log_message "ERROR" "docker command not found. Cannot get local image info."
        echo -e "${RED}docker command not found.${NC}"
        return 1
    fi

    local update_count=0
    local update_details=""

    for container in "${CONTAINER_NAMES[@]}"; do
        printf "   Checking %-15s: " "$container"
        # Check if container exists and is running
        local container_status
        container_status=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null)
        if [[ $? -ne 0 ]]; then
             echo -e "${YELLOW}Not found${NC}"
             continue
        fi
         if [[ "$container_status" != "running" ]]; then
             echo -e "${YELLOW}Not running${NC}"
             continue
        fi

        # Get image name with tag, local digest ID, ARCH, and OS from the running container
        local inspect_data
        inspect_data=$(docker inspect --format='{{.Config.Image}}|{{.Image}}|{{.Platform}}' "$container" 2>/dev/null)
        local image_name_tag=$(echo "$inspect_data" | cut -d'|' -f1)
        local local_digest_id=$(echo "$inspect_data" | cut -d'|' -f2) # Image manifest ID used by container
        local platform=$(echo "$inspect_data" | cut -d'|' -f3) # e.g., linux/amd64 or linux/arm64

        # Extract Arch and OS from platform string
        local container_arch=$(echo "$platform" | cut -d'/' -f2)
        local container_os=$(echo "$platform" | cut -d'/' -f1)


        if [[ -z "$image_name_tag" || -z "$local_digest_id" || -z "$container_arch" || -z "$container_os" ]]; then
            log_message "WARNING" "Could not get image/platform info for container '$container'"
            echo -e "${YELLOW}Info unavailable${NC}"
            continue
        fi

        # Check if image name looks like a digest (no tag to check)
        if [[ "$image_name_tag" == *sha256:* ]]; then
             log_message "DEBUG" "Container '$container' uses image digest '$image_name_tag', skipping remote tag check."
             echo -e "${CYAN}Using digest, skipped${NC}"
             continue
        fi

        # Query remote registry using skopeo FOR THE CONTAINER'S SPECIFIC PLATFORM
        log_message "DEBUG" "Inspecting remote image '$image_name_tag' for platform '$platform'..."
        # Increase timeout, specify platform
        local remote_info
        remote_info=$(timeout 30 skopeo inspect --override-os "$container_os" --override-arch "$container_arch" "docker://$image_name_tag" 2>/dev/null)
        local skopeo_exit_code=$?

        if [[ $skopeo_exit_code -ne 0 || -z "$remote_info" ]]; then
            # Handle common skopeo errors more gracefully
            local error_msg="skopeo failed"
            if [[ $skopeo_exit_code -eq 124 ]]; then error_msg="skopeo timed out"; fi
            # Check if manifest for platform is missing (common with multi-arch tags)
            # Note: Error messages might vary between skopeo versions
            if echo "$remote_info" | grep -q -i "manifest unknown\|not found"; then
                 error_msg="manifest for platform $platform not found in registry"
            fi

            log_message "WARNING" "$error_msg inspecting remote image '$image_name_tag' for container '$container' (Platform: $platform, Exit: $skopeo_exit_code)"
            echo -e "${YELLOW}Remote check failed${NC}"
            continue
        fi

        local remote_digest=$(echo "$remote_info" | jq -r '.Digest // ""')

        if [[ -z "$remote_digest" ]]; then
            log_message "WARNING" "Could not parse remote digest for image '$image_name_tag' (Platform: $platform)."
            echo -e "${YELLOW}Digest parse failed${NC}"
            continue
        fi

        # Compare local running image ID with the remote digest for the tag/platform
        # Both should be in format sha256:xxxx
        if [[ "$local_digest_id" != "$remote_digest" ]]; then
            log_message "INFO" "Update potentially available for '$container' ('$image_name_tag', platform '$platform'). Local ID: $local_digest_id, Remote Digest: $remote_digest"
            echo -e "${GREEN}$(emoji_map ':update:') Update available${NC}"
            update_details+="\n- $(emoji_map ':update:') **$container**: Image \`$image_name_tag\` (Platform: $platform) has an update."
            update_count=$((update_count + 1))
        else
            log_message "DEBUG" "Container '$container' ('$image_name_tag', platform '$platform') is up-to-date."
            echo -e "${GREEN}Up-to-date${NC}"
        fi
    done

    # Send notification if updates found and notifications enabled
    if [[ $update_count -gt 0 && "$IMAGE_UPDATE_NOTIFY" == "true" ]]; then
        log_message "INFO" "$update_count container image updates available, sending notification."
        local title="Container Image Updates Available"
        local message="Found **$update_count** potential container image updates based on tag digests for the running platform:$update_details\n\nConsider running \`docker-compose pull\` or equivalent to update images before recreating containers."
        send_discord_message "$title" "$message" "info" "" "Image Updates"
    elif [[ "$IMAGE_UPDATE_NOTIFY" == "true" ]]; then
         log_message "INFO" "No container image updates found for running platforms."
         echo -e "\n${GREEN}No updates found for running container platforms.${NC}" # Add feedback to console
    fi

    return $update_count # Return number of updates found
}


# ========================
# Health Check
# ========================

run_health_check() {
    log_message "INFO" "Running health check"
    local status=0
    local report=""

    echo -e "${CYAN}=== Health Check ===${NC}"
    report+="=== Health Check ===\n\n"

    echo -e "${CYAN}Containers:${NC}"
    report+="Containers:\n"

    for container in "${CONTAINER_NAMES[@]}"; do
        printf "  %-15s: " "$container"
        report+="  $container: "

        if check_container_health "$container"; then
            echo -e "${GREEN}$(emoji_map ':check:') OK${NC}"
            report+=":check: OK\n"
        else
            echo -e "${RED}$(emoji_map ':x:') FAIL${NC}"
            report+=":x: FAIL\n"
            status=1
        fi
    done

    echo -e "${CYAN}System:${NC}"
    report+="\nSystem:\n"

    # CPU Usage
    printf "  %-15s: " "CPU Usage"
    report+="  CPU Usage: "
    check_cpu_usage >/dev/null
    case $? in
        0) echo -e "${GREEN}$(emoji_map ':check:') OK${NC}"; report+=":check: OK\n" ;;
        1) echo -e "${YELLOW}$(emoji_map ':warning:') WARN${NC}"; report+=":warning: WARN\n"; status=1 ;;
        2) echo -e "${RED}$(emoji_map ':x:') CRIT${NC}"; report+=":x: CRIT\n"; status=1 ;;
    esac

    # Memory
    printf "  %-15s: " "Memory"
    report+="  Memory: "
    check_memory_usage >/dev/null
    case $? in
        0) echo -e "${GREEN}$(emoji_map ':check:') OK${NC}"; report+=":check: OK\n" ;;
        1) echo -e "${YELLOW}$(emoji_map ':warning:') WARN${NC}"; report+=":warning: WARN\n"; status=1 ;;
        2) echo -e "${RED}$(emoji_map ':x:') CRIT${NC}"; report+=":x: CRIT\n"; status=1 ;;
    esac

    # Disk Space
    printf "  %-15s: " "Disk Space"
    report+="  Disk Space: "
    check_disk_usage >/dev/null
    case $? in
        0) echo -e "${GREEN}$(emoji_map ':check:') OK${NC}"; report+=":check: OK\n" ;;
        1) echo -e "${YELLOW}$(emoji_map ':warning:') WARN${NC}"; report+=":warning: WARN\n"; status=1 ;;
        2) echo -e "${RED}$(emoji_map ':x:') CRIT${NC}"; report+=":x: CRIT\n"; status=1 ;;
    esac

    # Load
    printf "  %-15s: " "Load"
    report+="  Load: "
    check_system_load >/dev/null
    case $? in
        0) echo -e "${GREEN}$(emoji_map ':check:') OK${NC}"; report+=":check: OK\n" ;;
        1) echo -e "${YELLOW}$(emoji_map ':warning:') WARN${NC}"; report+=":warning: WARN\n"; status=1 ;;
        2) echo -e "${RED}$(emoji_map ':x:') CRIT${NC}"; report+=":x: CRIT\n"; status=1 ;;
    esac

    echo -e "${CYAN}Security:${NC}"
    report+="\nSecurity:\n"

    # Logs
    printf "  %-15s: " "Logs"
    report+="  Logs: "
    if check_security_logs >/dev/null; then
        echo -e "${GREEN}$(emoji_map ':check:') OK${NC}"
        report+=":check: OK\n"
    else
        echo -e "${YELLOW}$(emoji_map ':warning:') ISSUES${NC}"
        report+=":warning: ISSUES\n"
        status=1
    fi

    # Network
    printf "  %-15s: " "Network"
    report+="  Network: "
    if monitor_network_traffic >/dev/null; then
        echo -e "${GREEN}$(emoji_map ':check:') OK${NC}"
        report+=":check: OK\n"
    else
        # Network issues (attacks) are typically notified immediately,
        # but we can flag the health check report too.
        echo -e "${YELLOW}$(emoji_map ':warning:') TRAFFIC SPIKE${NC}"
        report+=":warning: TRAFFIC SPIKE\n"
        # Don't necessarily set status=1 unless the spike is persistent or causes other issues
    fi

    echo -e "${CYAN}Discord Integration:${NC}"
    report+="\nDiscord Integration:\n"

    # discord.sh
    printf "  %-15s: " "discord.sh"
    report+="  discord.sh: "
    if check_discord_script >/dev/null; then
        echo -e "${GREEN}$(emoji_map ':check:') OK${NC}"
        report+=":check: OK\n"
    else
        echo -e "${RED}$(emoji_map ':x:') FAIL${NC}"
        report+=":x: FAIL\n"
        status=1
    fi

    # Webhook
    printf "  %-15s: " "Webhook"
    report+="  Webhook: "
    if validate_discord_webhook "$DISCORD_WEBHOOK" >/dev/null; then
        echo -e "${GREEN}$(emoji_map ':check:') OK${NC}"
        report+=":check: OK\n"
    else
        echo -e "${RED}$(emoji_map ':x:') FAIL${NC}"
        report+=":x: FAIL\n"
        status=1
    fi

    # Send health report to Discord if configured
    # Only send if webhook is valid
    if [[ -n "$DISCORD_WEBHOOK" ]] && validate_discord_webhook "$DISCORD_WEBHOOK" >/dev/null; then
        local severity="success"
        [[ "$status" -ne 0 ]] && severity="warning" # If status is non-zero, report is warning
        local title="Health Check Report"
        # Append a note if health status failed
        if [[ "$status" -ne 0 ]]; then
             report+="\n\n:warning: One or more critical health checks failed."
        else
             report+="\n\n:check: All health checks passed."
        fi
        send_discord_message "$title" "$report" "$severity" "" "Pangolin Health"
    fi

    return $status
}

# ========================
# Generate Reports
# ========================

generate_security_report() {
    local title="$(emoji_map ':shield:') Pangolin Security Report"
    local report=""
    local severity="info" # Default severity, upgrade to warning if issues found

    log_message "INFO" "Generating security report..."

    # --- System Information ---
    report+="**System Information:**\n"
    report+="* Hostname: \`$(hostname)\`\n"
    report+="* OS: \`$(cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2 || echo "Unknown")\`\n"
    report+="* Kernel: \`$(uname -r)\`\n"
    report+="* Uptime: \`$(uptime -p)\`\n\n"

    # --- System Resources ---
    report+="**System Resources:**\n"
    # Reuse check functions to get current values (note: doesn't use historical data)
    local cpu_usage=$(top -bn1 | grep '%Cpu(s)' | sed -n 's/.*, *\([0-9.]*\)%* id.*/\1/p' | awk '{print 100 - $1}' | printf "%.1f")
    local mem_usage=$(free -m | awk 'NR==2 {if ($2>0) printf "%.1f", $3*100/$2; else print "0.0"}')
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    local load_raw=$(uptime | awk -F'load average: ' '{print $2}' | cut -d',' -f1) # 1-min load avg
    local cores=$(nproc 2>/dev/null || echo 1) # Default to 1 core if nproc fails
    local load_norm="N/A"
    if [[ "$load_raw" =~ ^[0-9]+(\.[0-9]+)?$ && "$cores" =~ ^[1-9][0-9]*$ ]]; then
         load_norm=$(echo "scale=2; $load_raw / $cores" | bc)
    fi

    report+="* CPU Usage: \`${cpu_usage:-N/A}%\`\n"
    report+="* Memory Usage: \`${mem_usage:-N/A}%\`\n"
    report+="* Disk Usage (/): \`${disk_usage:-N/A}\`\n"
    report+="* Load (1m avg): \`${load_raw:-N/A}\` (Normalized: \`${load_norm:-N/A}x\`)\n\n"

    # Check thresholds and update severity if needed
    if [[ "$cpu_usage" =~ ^[0-9.]+$ ]] && (( $(echo "$cpu_usage > $CPU_WARNING_THRESHOLD" | bc -l) )); then severity="warning"; fi
    if [[ "$mem_usage" =~ ^[0-9.]+$ ]] && (( $(echo "$mem_usage > $MEM_WARNING_THRESHOLD" | bc -l) )); then severity="warning"; fi
    if [[ "${disk_usage%%%}" =~ ^[0-9]+$ ]] && (( ${disk_usage%%%} > $DISK_WARNING_THRESHOLD )); then severity="warning"; fi # Remove % for comparison
    if [[ "$load_norm" != "N/A" ]] && (( $(echo "$load_norm > 1.0" | bc -l) )); then severity="warning"; fi # Warn if norm load > 1.0


    # --- Network Status ---
    report+="**Network Status:**\n"
    local interface=$(ls /sys/class/net/ 2>/dev/null | grep -v "lo" | head -n 1)
    if [[ -n "$interface" ]]; then
        # Get packet rate (similar to monitor_network_traffic but simplified for report)
        local pkt=0
        local pkt_old=$(grep "$interface:" /proc/net/dev 2>/dev/null | cut -d ':' -f2 | awk '{ print $2 }')
        sleep 1 # Short sleep for rate calculation
        local pkt_new=$(grep "$interface:" /proc/net/dev 2>/dev/null | cut -d ':' -f2 | awk '{ print $2 }')

        if [[ "$pkt_new" =~ ^[0-9]+$ && "$pkt_old" =~ ^[0-9]+$ && $pkt_new -ge $pkt_old ]]; then
             pkt=$(( pkt_new - pkt_old ))
        fi
        report+="* Interface: \`$interface\`\n"
        report+="* Current Traffic: \`$pkt\` packets/sec\n"

        # Check threshold
        if [[ $pkt -gt $NETWORK_THRESHOLD ]]; then
            report+="* $(emoji_map ':warning:') **Warning:** Traffic above threshold (${NETWORK_THRESHOLD} packets/s)\n"
            severity="warning"
        else
            report+="* Traffic within normal parameters.\n"
        fi
    else
        report+="* Could not determine primary network interface.\n"
    fi
    report+="\n"


    # --- SSH Activity (Last 24h) ---
    report+="**SSH Activity (Last 24h):**\n"
    local ssh_failures=0
    local ssh_success=0

    # Check common log sources (simplified check just for counts)
    if command -v journalctl >/dev/null 2>&1; then
        ssh_failures=$(journalctl -u ssh -u sshd --since "1 day ago" --no-pager --output cat 2>/dev/null | grep -c "Failed password" || echo 0)
        ssh_success=$(journalctl -u ssh -u sshd --since "1 day ago" --no-pager --output cat 2>/dev/null | grep -c "Accepted" || echo 0)
    elif [[ -f "/var/log/auth.log" && -r "/var/log/auth.log" ]]; then
        ssh_failures=$(grep "sshd.*Failed password" "/var/log/auth.log" 2>/dev/null | wc -l)
        ssh_success=$(grep "sshd.*Accepted" "/var/log/auth.log" 2>/dev/null | wc -l)
    elif [[ -f "/var/log/secure" && -r "/var/log/secure" ]]; then
        ssh_failures=$(grep "sshd.*Failed password" "/var/log/secure" 2>/dev/null | wc -l)
        ssh_success=$(grep "sshd.*Accepted" "/var/log/secure" 2>/dev/null | wc -l)
    fi

    report+="* Failed login attempts: \`$ssh_failures\`\n"
    report+="* Successful logins: \`$ssh_success\`\n"
    if (( ssh_failures > 10 )); then # Highlight if failures seem high
         report+="* $(emoji_map ':warning:') High number of failed login attempts noted.\n"
         severity="warning"
    fi
    report+="\n"


    # --- Container Status ---
    report+="**Container Status:**\n"
    local all_containers_ok=true
    for container in "${CONTAINER_NAMES[@]}"; do
        local inspect_output
        inspect_output=$(docker inspect --format='{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}|{{.Config.Image}}' "$container" 2>/dev/null)
        local exit_code=$?

        if [[ $exit_code -ne 0 ]]; then
            report+="* $(emoji_map ':x:') \`$container\`: Not found or inspect failed.\n"
            all_containers_ok=false
            continue
        fi

        local status=$(echo "$inspect_output" | cut -d'|' -f1)
        local health=$(echo "$inspect_output" | cut -d'|' -f2)
        local image=$(echo "$inspect_output" | cut -d'|' -f3)

        if [[ "$status" == "running" && ("$health" == "healthy" || "$health" == "N/A") ]]; then
            report+="* $(emoji_map ':check:') \`$container\` (\`${image##*/}\`): Running (Health: $health)\n" # Show image name only
        else
            report+="* $(emoji_map ':warning:') \`$container\` (\`${image##*/}\`): Status **$status** (Health: $health)\n"
            all_containers_ok=false
        fi
    done
    if [[ "$all_containers_ok" == "false" ]]; then
         severity="warning" # If any container has issues, report is warning
    fi


    # --- Send report to Discord ---
    # Only send if webhook is valid
    if validate_discord_webhook "$DISCORD_WEBHOOK" >/dev/null; then
        send_discord_message "$title" "$report" "$severity" "" "Pangolin Security"
        log_message "INFO" "Security report generated and sent to Discord (Severity: $severity)"
    else
        log_message "ERROR" "Cannot send security report: Discord webhook is invalid or not configured."
    fi
}

# ========================
# Monitoring Functions
# ========================

# MODIFIED: Added periodic image update check
start_monitoring_foreground() {
    echo -e "${CYAN}=== Starting Monitoring in Foreground ===${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"

    # Trap Ctrl+C
    trap 'echo -e "\n${GREEN}Monitoring stopped${NC}"; exit 0' INT TERM

    local cycle_count=0
    local last_report_time=$(date +%s)
    local last_image_check_time=$(date +%s) # New: Track image check time

    while true; do
        cycle_count=$((cycle_count + 1))
        local current_time=$(date +%s)

        echo -e "\n${CYAN}[$(date)] Running health check (cycle #${cycle_count})${NC}"
        run_health_check

        # Check for system updates (less frequently)
        # Example: every 6 hours (adjust as needed)
        local system_update_check_interval=$(( 6 * 60 * 60 / CHECK_INTERVAL )) # Approx cycles for 6 hours
        if [[ $cycle_count -eq 1 || $(( cycle_count % system_update_check_interval )) -eq 0 ]]; then
            echo -e "\n${CYAN}Checking for system updates...${NC}"
            check_system_updates
        fi

        # Check for container image updates periodically
        if [[ "$IMAGE_UPDATE_NOTIFY" == "true" ]] && (( current_time - last_image_check_time >= IMAGE_UPDATE_INTERVAL )); then
             echo -e "\n${CYAN}Checking for container image updates...${NC}"
             check_container_image_updates
             last_image_check_time=$current_time
        fi

        # Monitor network for attacks (runs every cycle)
        # echo -e "\n${CYAN}Monitoring network traffic...${NC}" # Maybe too verbose every cycle
        monitor_network_traffic

        # Check for SSH login events if SSH_CLIENT is set (on each cycle)
        # Note: This still only works if script is triggered by login. See previous review notes.
        if [[ -n "$SSH_CLIENT" && "$SSH_NOTIFY" == "true" ]]; then
            echo -e "\n${CYAN}New SSH connection detected, sending notification...${NC}"
            ssh_login_notification
        fi

        # Send heartbeat to Discord less frequently (e.g., every hour)
        local heartbeat_interval=$(( 60 * 60 / CHECK_INTERVAL )) # Approx cycles per hour
        if [[ $cycle_count -eq 1 || $(( cycle_count % heartbeat_interval )) -eq 0 ]]; then
            echo -e "\n${CYAN}Sending heartbeat message...${NC}"
            send_discord_message "Heartbeat" ":yellow_circle: Heartbeat: Pangolin Monitor is running" "info"
        fi

        # Generate security report according to schedule
        if (( current_time - last_report_time >= REPORT_INTERVAL )); then
            echo -e "\n${CYAN}Generating security report...${NC}"
            generate_security_report
            last_report_time=$current_time
        fi

        echo -e "\n${YELLOW}Waiting ${CHECK_INTERVAL} seconds until next check...${NC}"
        sleep $CHECK_INTERVAL
    done
}

# MODIFIED: Added periodic image update check
start_service_mode() {
    log_message "INFO" "Starting in service mode"

    # Trap signals
    trap 'log_message "INFO" "Service stopping"; send_discord_message "Service Stopped" ":red_circle: Pangolin Monitor service stopped" "warning"; exit 0' INT TERM

    local cycle_count=0
    local last_report_time=$(date +%s)
    local last_image_check_time=$(date +%s) # New

    send_discord_message "Service Started" ":green_circle: Pangolin Monitor service started" "success"

    while true; do
        cycle_count=$((cycle_count + 1))
        local current_time=$(date +%s)

        # Run health check silently
        if ! run_health_check >/dev/null 2>&1; then
            log_message "WARNING" "Health check found issues"
            # Note: run_health_check already sends a Discord message on failure/success
        else
            log_message "INFO" "Health check completed successfully"
        fi

        # Check for system updates (less frequently)
        local system_update_check_interval=$(( 6 * 60 * 60 / CHECK_INTERVAL )) # Approx cycles for 6 hours
        if [[ $cycle_count -eq 1 || $(( cycle_count % system_update_check_interval )) -eq 0 ]]; then
            log_message "INFO" "Checking for system updates"
            check_system_updates >/dev/null 2>&1
        fi

        # Check for container image updates periodically
        if [[ "$IMAGE_UPDATE_NOTIFY" == "true" ]] && (( current_time - last_image_check_time >= IMAGE_UPDATE_INTERVAL )); then
             log_message "INFO" "Checking for container image updates"
             check_container_image_updates # Sends its own discord msg if needed
             last_image_check_time=$current_time
        fi

        # Monitor network for attacks
        monitor_network_traffic >/dev/null 2>&1

        # Check for SSH login events if SSH_CLIENT is set
        # Note: Unlikely to trigger in service mode.
        if [[ -n "$SSH_CLIENT" && "$SSH_NOTIFY" == "true" ]]; then
            log_message "INFO" "New SSH connection detected (unusual in service mode)"
            ssh_login_notification >/dev/null 2>&1
        fi

        # Send heartbeat every hour
        local heartbeat_interval=$(( 60 * 60 / CHECK_INTERVAL )) # Approx cycles per hour
        if [[ $cycle_count -eq 1 || $(( cycle_count % heartbeat_interval )) -eq 0 ]]; then
            log_message "INFO" "Sending hourly heartbeat"
            send_discord_message "Heartbeat" ":yellow_circle: Hourly System Heartbeat\n\nSystem is operational and monitoring services." "info"
        fi

        # Generate security report according to schedule
        if (( current_time - last_report_time >= REPORT_INTERVAL )); then
            log_message "INFO" "Generating scheduled security report"
            generate_security_report
            last_report_time=$current_time
        fi

        sleep $CHECK_INTERVAL
    done
}

# ========================
# Systemd Service Setup
# ========================

install_systemd_service() {
    echo -e "${CYAN}=== Install as Systemd Service ===${NC}"

    # Check if running as root/sudo
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This operation requires root privileges.${NC}"
        echo -e "${YELLOW}Please run the command again using 'sudo':${NC}"
        # Construct the command the user should run
        local current_cmd
        current_cmd=$(basename "$0")
        # Check if script was called with full path
        [[ "$0" == /* ]] && current_cmd="$0"
        echo "  sudo $current_cmd --install-service"
        wait_for_key
        return 1
    fi

    # --- Proceed with Installation (as root) ---
    local SERVICE_NAME="pangolin-monitor"
    local SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    # Use absolute path for ExecStart if SCRIPT_DIR is absolute
    local exec_start_path="${SCRIPT_DIR}/$(basename "$0")"
    if [[ "$SCRIPT_DIR" != /* ]]; then
         # If SCRIPT_DIR is relative, try to make it absolute
         local abs_script_dir
         abs_script_dir=$(cd "$SCRIPT_DIR" && pwd)
         if [[ -n "$abs_script_dir" ]]; then
             exec_start_path="${abs_script_dir}/$(basename "$0")"
         else
             echo -e "${RED}Error: Could not determine absolute path for the script. Service file may be incorrect.${NC}"
             # Still proceed, but path might be relative
         fi
    fi


    echo "Creating systemd service file at $SERVICE_FILE..."

    # Use cat with explicit EOF marker
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Pangolin Stack Monitoring Service
Documentation=https://github.com/YOUR_REPO # Add your repo URL if applicable
After=docker.service network-online.target # Wait for docker and network
Wants=docker.service network-online.target

[Service]
Type=simple
# Consider running as a non-root user if possible, but ensure permissions
# User=pangolinmon
# Group=pangolinmon
User=root # Current configuration
WorkingDirectory=${SCRIPT_DIR} # Set working directory to script dir
ExecStart=${exec_start_path} --service
Restart=on-failure
RestartSec=15s # Slightly longer restart delay
TimeoutStopSec=30s # Time to allow for graceful stop

[Install]
WantedBy=multi-user.target
EOF

    # Set secure permissions for the service file
    chmod 644 "$SERVICE_FILE"
    echo "Service file created."

    # Reload systemd, enable and start service
    echo "Reloading systemd daemon..."
    if ! systemctl daemon-reload; then
         echo -e "${RED}Error: Failed to reload systemd daemon.${NC}"
         return 1
    fi

    echo "Enabling $SERVICE_NAME service to start on boot..."
     if ! systemctl enable "$SERVICE_NAME"; then
         echo -e "${RED}Error: Failed to enable $SERVICE_NAME service.${NC}"
         # Continue to try starting it anyway
    fi

    echo "Starting $SERVICE_NAME service..."
    if ! systemctl start "$SERVICE_NAME"; then
         echo -e "${RED}Error: Failed to start $SERVICE_NAME service immediately.${NC}"
         echo -e "${YELLOW}Please check service status and logs manually.${NC}"
         # Fall through to status check
    fi

    # Check status after a brief pause
    echo "Waiting a few seconds for service to initialize..."
    sleep 3
    echo "Checking service status..."
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}Service '$SERVICE_NAME' installed and is active (running).${NC}"
        echo -e "To check status: ${CYAN}systemctl status $SERVICE_NAME${NC}"
        echo -e "To view logs:    ${CYAN}journalctl -u $SERVICE_NAME -f${NC}"
        echo -e "To stop service: ${CYAN}sudo systemctl stop $SERVICE_NAME${NC}"
        echo -e "To disable service: ${CYAN}sudo systemctl disable $SERVICE_NAME${NC}"
    else
        echo -e "${RED}Service '$SERVICE_NAME' installed but failed to activate or is not running.${NC}"
        echo -e "${YELLOW}Please check the service status and logs for errors:${NC}"
        echo -e "  Status: ${CYAN}systemctl status $SERVICE_NAME${NC}"
        echo -e "  Logs:   ${CYAN}journalctl -u $SERVICE_NAME${NC}"
        return 1 # Indicate installation completed but service failed
    fi

    wait_for_key
    return 0 # Success
}

# ========================
# Menu Functions
# ========================

show_header() {
    clear
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}                  PANGOLIN STACK MONITORING SYSTEM v${VERSION}${NC}" # Uses static VERSION
    echo -e "${CYAN}======================================================================${NC}"
    echo ""
}

# MODIFIED: Added option 10
main_menu() {
    while true; do
        show_header
        echo "Main Menu:"
        echo "1. Run Health Check"
        echo "2. Start Monitoring (Foreground)"
        echo "3. Install as Systemd Service"
        echo "4. View Container Status"
        echo "5. View System Resources"
        echo "6. View SSH Login Attempts"
        echo "7. Analyze Traefik Logs"
        echo "8. Check for Container Image Updates" # New Option
        echo "9. Generate Security Report"
        echo "C. Configuration"
        echo "0. Exit"
        echo ""
        read -p "Enter your choice [0-9, C]: " choice

        case $choice in
            1) run_health_check; wait_for_key ;;
            2) start_monitoring_foreground ;;
            3) install_systemd_service ;;
            4) display_container_status ;;
            5) display_system_resources ;;
            6) check_ssh_attempts ;;
            7) analyze_traefik_logs ;;
            8) check_container_image_updates; wait_for_key ;; # New Action
            9) generate_security_report; echo -e "${GREEN}Report generated and sent to Discord${NC}"; wait_for_key ;;
            C|c) configuration_menu ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; wait_for_key ;;
        esac
    done
}

# MODIFIED: Option 6 Notification Settings includes image updates
configuration_menu() {
    while true; do
        show_header
        echo "Configuration Menu:"
        echo "1. View Current Configuration"
        echo "2. Edit Configuration File"
        echo "3. Configure Discord Webhook"
        echo "4. Configure Monitoring Thresholds"
        echo "5. Configure Containers to Monitor"
        echo "6. Configure Notification & Interval Settings" # Renamed
        echo "7. Reset to Default Configuration"
        echo "8. Toggle Debug Mode"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Enter your choice [0-8]: " choice

        case $choice in
            1) cat "$CONFIG_FILE" | grep -v "^#"; wait_for_key ;;
            2) edit_configuration ;;
            3) configure_discord_webhook ;;
            4) configure_thresholds ;;
            5) configure_containers ;;
            6) configure_notification_settings ;; # Calls updated function
            7) save_default_config; echo -e "${GREEN}Configuration reset to defaults${NC}"; wait_for_key ;;
            8) toggle_debug_mode ;;
            0) return ;;
            *) echo -e "${RED}Invalid option${NC}"; wait_for_key ;;
        esac
    done
}

# Configuration editing functions
edit_configuration() {
    local editor_to_use=""

    # Check for preferred editors (nano first, then vim)
    if command -v nano >/dev/null 2>&1; then
        editor_to_use="nano"
    elif command -v vim >/dev/null 2>&1; then
        editor_to_use="vim"
    elif command -v vi >/dev/null 2>&1; then # Add vi as another fallback
         editor_to_use="vi"
    else
        echo -e "${RED}Error: No suitable text editor (nano, vim, vi) found.${NC}"
        echo -e "${YELLOW}Please install one of these editors or edit '$CONFIG_FILE' manually.${NC}"
        wait_for_key
        return 1
    fi

    echo "Launching '$editor_to_use' to edit '$CONFIG_FILE'..."
    # Wait briefly to allow user to see the message
    sleep 1

    # Execute the chosen editor
    if "$editor_to_use" "$CONFIG_FILE"; then
        echo -e "\n${GREEN}Editor closed. Reloading configuration...${NC}"
        # Reload config after successful edit
        load_config
        echo -e "${GREEN}Configuration may have been updated and was reloaded.${NC}"
    else
        local edit_exit_code=$?
        echo -e "\n${RED}Editor exited with an error (Code: $edit_exit_code).${NC}"
        echo -e "${YELLOW}Configuration might not have been saved. Reloading previous configuration.${NC}"
        # Reload config anyway to ensure consistency, even if edits failed
        load_config
        wait_for_key
        return 1 # Indicate editing likely failed
    fi

    wait_for_key
    return 0 # Success
}

# Configuration editing functions (Continued)

configure_discord_webhook() {
    show_header
    echo -e "${CYAN}=== Discord Webhook Configuration ===${NC}"
    echo -e "Current webhook URL:"
    if [[ -n "$DISCORD_WEBHOOK" && "$DISCORD_WEBHOOK" != "$DEFAULT_DISCORD_WEBHOOK" ]]; then
         echo -e "  ${YELLOW}${DISCORD_WEBHOOK}${NC}"
    else
         echo -e "  ${YELLOW}Not configured or using default empty value.${NC}"
    fi
    echo ""
    echo -e "${CYAN}Enter the new Discord webhook URL (or press Enter to keep current):${NC}"
    # Use -p for prompt, -r to handle backslashes literally
    read -p "> " -r new_webhook

    # If user pressed Enter, do nothing
    if [[ -z "$new_webhook" ]]; then
        echo -e "${YELLOW}No change made.${NC}"
        wait_for_key
        return 0
    fi

    # Validate the entered webhook format
    if ! validate_discord_webhook "$new_webhook"; then
        echo -e "${RED}Invalid webhook URL format entered.${NC}"
        echo -e "${YELLOW}Format should be: https://discord.com/api/webhooks/NUMBER/STRING${NC}"
        wait_for_key
        return 1
    fi

    echo "Updating configuration file..."
    # Update config file using sed - create a backup (.bak) just in case
    if sed -i.bak "s|^DISCORD_WEBHOOK=.*|DISCORD_WEBHOOK=\"$new_webhook\"|" "$CONFIG_FILE"; then
         echo "Configuration file updated."
    else
         echo -e "${RED}Error: Failed to update configuration file '$CONFIG_FILE' with sed.${NC}"
         wait_for_key
         return 1
    fi

    # Reload config to reflect the change immediately
    echo "Reloading configuration..."
    load_config

    # Test the newly configured webhook
    echo -e "${YELLOW}Sending a test message to the new webhook...${NC}"
    # Temporarily override global DISCORD_WEBHOOK for the test function call
    # to ensure we test the *new* one even if load_config failed somehow
    if send_discord_message "Webhook Test" "Pangolin Monitor webhook test from $(hostname) was successful! $(emoji_map ':check:')" "success" "" "" "$new_webhook"; then
        echo -e "${GREEN}Webhook configured and test message sent successfully.${NC}"
    else
        echo -e "${RED}Webhook test message failed to send.${NC}"
        echo -e "${YELLOW}Please double-check the webhook URL in Discord and the script configuration.${NC}"
        # Consider reverting the change or warning the user more strongly?
        # For now, the invalid URL remains saved.
    fi

    wait_for_key
    return 0 # Return success even if test failed, as config was updated
}

# Configuration editing functions (Continued)

configure_thresholds() {
    show_header
    echo -e "${CYAN}=== Threshold Configuration ===${NC}"
    echo -e "Current thresholds (Enter new value or leave blank to keep current):"
    echo -e "-------------------------------------------------------------------"
    echo -e "  CPU       Warning: ${YELLOW}${CPU_WARNING_THRESHOLD}%${NC}, Critical: ${RED}${CPU_CRITICAL_THRESHOLD}%${NC}"
    echo -e "  Memory    Warning: ${YELLOW}${MEM_WARNING_THRESHOLD}%${NC}, Critical: ${RED}${MEM_CRITICAL_THRESHOLD}%${NC}"
    echo -e "  Disk      Warning: ${YELLOW}${DISK_WARNING_THRESHOLD}%${NC}, Critical: ${RED}${DISK_CRITICAL_THRESHOLD}%${NC}"
    echo -e "  Network   Attack threshold: ${RED}${NETWORK_THRESHOLD}${NC} packets/second"
    echo -e "-------------------------------------------------------------------"
    echo ""

    local config_updated=false # Flag to track if any changes were made

    # --- Helper function for reading and validating threshold input ---
    read_and_update_threshold() {
        local current_value="$1"
        local config_variable_name="$2"
        local prompt_text="$3"
        local new_value

        # Prompt user, showing current value
        read -p "$prompt_text ($current_value%): " new_value

        # Check if input is not empty and contains only digits
        if [[ -n "$new_value" ]]; then
             if [[ "$new_value" =~ ^[0-9]+$ ]]; then
                 # Validate range (0-100 for percentages)
                 if (( new_value >= 0 && new_value <= 100 )); then
                     # Update config file using sed (with backup)
                     if sed -i.bak "s|^${config_variable_name}=.*|${config_variable_name}=${new_value}|" "$CONFIG_FILE"; then
                          echo -e "  ${GREEN}Set $config_variable_name to $new_value%${NC}"
                          config_updated=true
                     else
                          echo -e "  ${RED}Error updating $config_variable_name in config file.${NC}"
                     fi
                 else
                      echo -e "  ${RED}Invalid input: '$new_value'. Percentage must be between 0 and 100.${NC}"
                 fi
             else
                  echo -e "  ${RED}Invalid input: '$new_value'. Please enter numbers only.${NC}"
             fi
        else
             echo "  Skipped." # User left blank
        fi
        echo "" # Add a blank line after each prompt
    }
    # --- End helper function ---


    # --- Update CPU thresholds ---
    read_and_update_threshold "$CPU_WARNING_THRESHOLD" "CPU_WARNING_THRESHOLD" "Enter new CPU Warning Threshold"
    read_and_update_threshold "$CPU_CRITICAL_THRESHOLD" "CPU_CRITICAL_THRESHOLD" "Enter new CPU Critical Threshold"

    # --- Update Memory thresholds ---
    read_and_update_threshold "$MEM_WARNING_THRESHOLD" "MEM_WARNING_THRESHOLD" "Enter new Memory Warning Threshold"
    read_and_update_threshold "$MEM_CRITICAL_THRESHOLD" "MEM_CRITICAL_THRESHOLD" "Enter new Memory Critical Threshold"

    # --- Update Disk thresholds ---
    read_and_update_threshold "$DISK_WARNING_THRESHOLD" "DISK_WARNING_THRESHOLD" "Enter new Disk Warning Threshold"
    read_and_update_threshold "$DISK_CRITICAL_THRESHOLD" "DISK_CRITICAL_THRESHOLD" "Enter new Disk Critical Threshold"

    # --- Update Network threshold (no percentage validation) ---
    local new_network_threshold
    read -p "Enter new Network Attack Threshold ($NETWORK_THRESHOLD packets/sec): " new_network_threshold
    if [[ -n "$new_network_threshold" ]]; then
         if [[ "$new_network_threshold" =~ ^[0-9]+$ ]]; then
             if (( new_network_threshold >= 0 )); then
                  # Update config file using sed (with backup)
                  if sed -i.bak "s|^NETWORK_THRESHOLD=.*|NETWORK_THRESHOLD=${new_network_threshold}|" "$CONFIG_FILE"; then
                       echo -e "  ${GREEN}Set NETWORK_THRESHOLD to $new_network_threshold packets/sec${NC}"
                       config_updated=true
                  else
                       echo -e "  ${RED}Error updating NETWORK_THRESHOLD in config file.${NC}"
                  fi
             else
                  echo -e "  ${RED}Invalid input: '$new_network_threshold'. Must be zero or positive.${NC}"
             fi
         else
             echo -e "  ${RED}Invalid input: '$new_network_threshold'. Please enter numbers only.${NC}"
         fi
    else
         echo "  Skipped." # User left blank
    fi
    echo ""


    # --- Final Steps ---
    if [[ "$config_updated" == "true" ]]; then
        echo "Configuration updated. Reloading..."
        load_config # Reload config if changes were made
        echo -e "${GREEN}Thresholds updated and configuration reloaded.${NC}"
    else
         echo -e "${YELLOW}No thresholds were changed.${NC}"
    fi

    wait_for_key
    return 0
}

# Configuration editing functions (Continued)

configure_containers() {
    show_header
    echo -e "${CYAN}=== Container Monitoring Configuration ===${NC}"
    echo -e "Current monitored containers:"
    if [[ ${#CONTAINER_NAMES[@]} -gt 0 ]]; then
         echo -e "  ${YELLOW}${CONTAINER_NAMES[*]}${NC}"
    else
         echo -e "  ${YELLOW}None.${NC}"
    fi
    echo ""

    # --- Get Available Running Containers ---
    echo -e "${CYAN}Available Docker containers (running):${NC}"
    # Initialize as empty array
    local available_containers=()
    if command -v docker >/dev/null 2>&1; then
        # Use mapfile (readarray) to read lines safely into the array
        mapfile -t available_containers < <(docker ps --format '{{.Names}}' 2>/dev/null)
        local docker_ps_exit_code=$?

        if [[ $docker_ps_exit_code -ne 0 ]]; then
             echo -e "  ${RED}Error running 'docker ps'. Cannot list containers.${NC}"
             available_containers=() # Ensure array is empty on error
        elif [[ ${#available_containers[@]} -eq 0 ]]; then
             echo -e "  ${YELLOW}No running Docker containers found.${NC}"
        else
             # List available containers with index and status
             for i in "${!available_containers[@]}"; do
                 local container="${available_containers[$i]}"
                 local status
                 # Get status quickly
                 status=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "InspectErr")

                 # Check if currently monitored
                 local is_monitored=false
                 for monitored_container in "${CONTAINER_NAMES[@]}"; do
                      # Use precise string comparison
                      if [[ "$container" == "$monitored_container" ]]; then
                          is_monitored=true
                          break # Found it, no need to check further
                      fi
                 done

                 # Display with appropriate color/tag
                 if [[ "$is_monitored" == "true" ]]; then
                     echo -e "  ${GREEN}[$i] $container ($status) [MONITORED]${NC}"
                 else
                     echo -e "  ${YELLOW}[$i] $container ($status)${NC}"
                 fi
             done
         fi
    else
        echo -e "  ${RED}Docker command not found or not running.${NC}"
    fi
    # --- End Listing Containers ---

    echo ""
    echo "Options:"
    echo "1. Add a running container to monitoring"
    echo "2. Remove a container from monitoring"
    echo "3. Set full list of containers manually"
    echo "0. Back"
    echo ""
    read -p "Enter your choice [0-3]: " choice

    local config_updated=false # Flag to track if changes need saving

    case $choice in
        1) # --- Add Container ---
            if [[ ${#available_containers[@]} -eq 0 ]]; then
                echo -e "${RED}No running containers available to add.${NC}"
            else
                read -p "Enter container number to add (from list above): " container_idx
                # Validate index is numeric and within bounds
                if [[ "$container_idx" =~ ^[0-9]+$ && $container_idx -ge 0 && $container_idx -lt ${#available_containers[@]} ]]; then
                    local container_to_add="${available_containers[$container_idx]}"

                    # Check if it's already in the monitored list
                    local already_monitored=false
                    for monitored_container in "${CONTAINER_NAMES[@]}"; do
                         if [[ "$container_to_add" == "$monitored_container" ]]; then
                             already_monitored=true
                             break
                         fi
                    done

                    if [[ "$already_monitored" == "false" ]]; then
                        CONTAINER_NAMES+=("$container_to_add") # Append to the array
                        config_updated=true
                        echo -e "${GREEN}Added '$container_to_add' to monitoring list.${NC}"
                    else
                        echo -e "${YELLOW}Container '$container_to_add' is already being monitored.${NC}"
                    fi
                else
                    echo -e "${RED}Invalid container number entered.${NC}"
                fi
            fi
            ;; # End Add Container

        2) # --- Remove Container ---
            if [[ ${#CONTAINER_NAMES[@]} -eq 0 ]]; then
                echo -e "${RED}No containers are currently being monitored to remove.${NC}"
            else
                echo -e "Select container number to remove from monitoring:"
                # List currently monitored containers with index
                for i in "${!CONTAINER_NAMES[@]}"; do
                    echo -e "  ${YELLOW}[$i] ${CONTAINER_NAMES[$i]}${NC}"
                done

                read -p "Enter container number to remove: " container_idx
                # Validate index is numeric and within bounds
                if [[ "$container_idx" =~ ^[0-9]+$ && $container_idx -ge 0 && $container_idx -lt ${#CONTAINER_NAMES[@]} ]]; then
                    local container_to_remove="${CONTAINER_NAMES[$container_idx]}"

                    # Remove element from array by rebuilding it (safest method)
                    local temp_array=()
                    for i in "${!CONTAINER_NAMES[@]}"; do
                         if [[ $i -ne $container_idx ]]; then
                              # Add elements except the one at the specified index
                              temp_array+=("${CONTAINER_NAMES[$i]}")
                         fi
                    done
                    # Assign the new array back
                    CONTAINER_NAMES=("${temp_array[@]}")

                    config_updated=true
                    echo -e "${GREEN}Removed '$container_to_remove' from monitoring list.${NC}"
                else
                    echo -e "${RED}Invalid container number entered.${NC}"
                fi
            fi
            ;; # End Remove Container

        3) # --- Set List Manually ---
            echo -e "Enter the full list of container names to monitor, separated by spaces:"
            echo -e "${YELLOW}(This will replace the current list entirely)${NC}"
            read -p "> " -r new_containers_str
            # Read the input string into the array, splitting by spaces
            read -a CONTAINER_NAMES <<< "$new_containers_str"
            config_updated=true
            echo -e "${GREEN}Monitoring list updated manually.${NC}"
            echo -e "Now monitoring: ${CONTAINER_NAMES[*]}"
            ;; # End Set Manually

        0) return ;; # Back to previous menu

        *) echo -e "${RED}Invalid option selected.${NC}" ;;
    esac # End Case statement

    # --- Update Config File if necessary ---
    if [[ "$config_updated" == "true" ]]; then
         echo "Updating configuration file..."
         # Format the array for the config file: ( name1 name2 name3 )
         # Ensure spaces around the list inside parentheses
         local container_list_str="${CONTAINER_NAMES[*]}" # Simple space separation
         if sed -i.bak "s|^CONTAINER_NAMES=.*|CONTAINER_NAMES=( $container_list_str )|" "$CONFIG_FILE"; then
              echo "Configuration file updated."
              # Reload config to ensure script uses the new list
              load_config
              echo -e "${GREEN}Container list saved and configuration reloaded.${NC}"
         else
              echo -e "${RED}Error updating CONTAINER_NAMES in config file '$CONFIG_FILE'.${NC}"
              # Config wasn't saved, but array in memory was changed. Reload to be safe?
              load_config # Reload old config if save failed
         fi
    fi # End Config Update Check

    wait_for_key
    return 0
}

# MODIFIED: Renamed and added image update options
configure_notification_settings() {
    show_header
    echo -e "${CYAN}=== Notification & Interval Settings ===${NC}"
    echo -e "Current settings:"
    echo -e "  Notifications:"
    echo -e "    SSH Login:        ${SSH_NOTIFY}"
    echo -e "    System Update:    ${LOG_NOTIFY}" # Note: LOG_NOTIFY used for system updates
    echo -e "    Network Attack:   ${ATTACK_NOTIFY}"
    echo -e "    Image Update:     ${IMAGE_UPDATE_NOTIFY}" # New
    echo -e "  Intervals:"
    echo -e "    Health Check:     ${CHECK_INTERVAL} seconds"
    echo -e "    Security Report:  ${REPORT_INTERVAL} seconds ($(( REPORT_INTERVAL / 3600 )) hours)"
    echo -e "    Image Update Chk: ${IMAGE_UPDATE_INTERVAL} seconds ($(( IMAGE_UPDATE_INTERVAL / 3600 )) hours)" # New
    echo ""

    echo "Options:"
    echo "  Notifications:"
    echo "    1. Toggle SSH Notifications"
    echo "    2. Toggle System Update Notifications"
    echo "    3. Toggle Network Attack Notifications"
    echo "    4. Toggle Image Update Notifications" # New
    echo "  Intervals:"
    echo "    5. Change Health Check Interval"
    echo "    6. Change Security Report Interval"
    echo "    7. Change Image Update Check Interval" # New
    echo "    0. Back"
    echo ""
    read -p "Enter your choice [0-7]: " choice

    case $choice in
        1)
            if [[ "$SSH_NOTIFY" == "true" ]]; then
                sed -i "s/SSH_NOTIFY=.*/SSH_NOTIFY=false/" "$CONFIG_FILE"
                echo -e "${YELLOW}SSH notifications disabled.${NC}"
            else
                sed -i "s/SSH_NOTIFY=.*/SSH_NOTIFY=true/" "$CONFIG_FILE"
                echo -e "${GREEN}SSH notifications enabled.${NC}"
            fi
            ;;
        2)
            if [[ "$LOG_NOTIFY" == "true" ]]; then
                sed -i "s/LOG_NOTIFY=.*/LOG_NOTIFY=false/" "$CONFIG_FILE"
                echo -e "${YELLOW}System update notifications disabled.${NC}"
            else
                sed -i "s/LOG_NOTIFY=.*/LOG_NOTIFY=true/" "$CONFIG_FILE"
                echo -e "${GREEN}System update notifications enabled.${NC}"
            fi
            ;;
        3)
            if [[ "$ATTACK_NOTIFY" == "true" ]]; then
                sed -i "s/ATTACK_NOTIFY=.*/ATTACK_NOTIFY=false/" "$CONFIG_FILE"
                echo -e "${YELLOW}Attack notifications disabled.${NC}"
            else
                sed -i "s/ATTACK_NOTIFY=.*/ATTACK_NOTIFY=true/" "$CONFIG_FILE"
                echo -e "${GREEN}Attack notifications enabled.${NC}"
            fi
            ;;
        4) # New
             if [[ "$IMAGE_UPDATE_NOTIFY" == "true" ]]; then
                 sed -i "s/IMAGE_UPDATE_NOTIFY=.*/IMAGE_UPDATE_NOTIFY=false/" "$CONFIG_FILE"
                 echo -e "${YELLOW}Image update notifications disabled.${NC}"
             else
                 sed -i "s/IMAGE_UPDATE_NOTIFY=.*/IMAGE_UPDATE_NOTIFY=true/" "$CONFIG_FILE"
                 echo -e "${GREEN}Image update notifications enabled.${NC}"
             fi
             ;;
        5)
            echo -e "Enter new health check interval in seconds (current: ${CHECK_INTERVAL}):"
            read -r new_interval
            if [[ -n "$new_interval" && "$new_interval" =~ ^[0-9]+$ && $new_interval -ge 10 ]]; then
                sed -i "s/CHECK_INTERVAL=.*/CHECK_INTERVAL=$new_interval/" "$CONFIG_FILE"
                echo -e "${GREEN}Health check interval updated to $new_interval seconds.${NC}"
            else
                echo -e "${RED}Invalid interval. Must be a number >= 10.${NC}"
            fi
            ;;
        6)
            echo -e "Enter new security report interval in hours (current: $(( REPORT_INTERVAL / 3600 ))):"
            read -r new_hours
            if [[ -n "$new_hours" && "$new_hours" =~ ^[0-9]+$ && $new_hours -ge 1 ]]; then
                local new_interval=$(( new_hours * 3600 ))
                sed -i "s/REPORT_INTERVAL=.*/REPORT_INTERVAL=$new_interval/" "$CONFIG_FILE"
                echo -e "${GREEN}Security report interval updated to $new_hours hours.${NC}"
            else
                echo -e "${RED}Invalid interval. Must be a number >= 1.${NC}"
            fi
            ;;
        7) # New
             echo -e "Enter new image update check interval in hours (current: $(( IMAGE_UPDATE_INTERVAL / 3600 ))):"
             read -r new_hours
             if [[ -n "$new_hours" && "$new_hours" =~ ^[0-9]+$ && $new_hours -ge 1 ]]; then
                 local new_interval=$(( new_hours * 3600 ))
                 sed -i "s/IMAGE_UPDATE_INTERVAL=.*/IMAGE_UPDATE_INTERVAL=$new_interval/" "$CONFIG_FILE"
                 echo -e "${GREEN}Image update check interval updated to $new_hours hours.${NC}"
             else
                 echo -e "${RED}Invalid interval. Must be a number >= 1.${NC}"
             fi
             ;;
        0) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac

    # Reload config
    load_config

    wait_for_key
}

# Configuration editing functions (Continued)

toggle_debug_mode() {
    show_header
    echo -e "${CYAN}=== Debug Mode Configuration ===${NC}"

    local config_updated=false # Flag to see if change was made
    local current_status_text=""
    local action_prompt=""
    local target_value=""
    local success_message=""

    # Determine current state and prompts based on it
    if [[ "$DEBUG" == "true" ]]; then
        current_status_text="${GREEN}ENABLED${NC}"
        action_prompt="disable"
        target_value="false"
        success_message="${GREEN}Debug mode disabled.${NC}"
    else
        current_status_text="${RED}DISABLED${NC}"
        action_prompt="enable"
        target_value="true"
        success_message="${GREEN}Debug mode enabled.${NC}"
    fi

    echo -e "Debug mode is currently ${current_status_text}"
    echo -e "Debug mode provides more verbose logging in: ${LOG_FILE}"
    echo ""
    echo -e "${YELLOW}Would you like to ${action_prompt} debug mode? (y/n)${NC}"
    read -p "> " -n 1 -r response # Read single character
    echo "" # Move to next line after input

    if [[ "$response" =~ ^[Yy]$ ]]; then
         echo "Updating configuration file..."
         # Update config file using sed (with backup)
         # Use | as separator in sed to avoid issues if value contains /
         if sed -i.bak "s|^DEBUG=.*|DEBUG=${target_value}|" "$CONFIG_FILE"; then
              echo "Configuration file updated."
              config_updated=true
              echo -e "$success_message"
         else
              echo -e "${RED}Error updating DEBUG setting in config file '$CONFIG_FILE'.${NC}"
         fi
    else
        echo -e "${YELLOW}No change made.${NC}"
    fi

    # Reload config only if updated successfully
    if [[ "$config_updated" == "true" ]]; then
        echo "Reloading configuration..."
        load_config
        echo "Configuration reloaded."
    fi

    wait_for_key
    return 0
}

# ========================
# Dependency Management
# ========================

# MODIFIED: Added skopeo dependency
check_dependencies() {
    log_message "INFO" "Checking dependencies..."
    local missing=()
    local recommendations=()

    # Essential dependencies for core functionality + jq (for display_container_status) + skopeo
    for dep in jq bc curl docker skopeo; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
            log_message "WARNING" "$dep not found"
        fi
    done

    # Optional dependencies with fallbacks
    if ! command -v column >/dev/null 2>&1; then
        log_message "WARNING" "column not found, some formatting may be limited"
        recommendations+=("util-linux (provides column)") # Package name varies
    fi
    if ! command -v chkrootkit >/dev/null 2>&1; then
        log_message "WARNING" "chkrootkit not found, rootkit check will be skipped"
        recommendations+=("chkrootkit")
    fi


    # Handle missing dependencies
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_message "ERROR" "Missing essential dependencies: ${missing[*]}"

        echo -e "${RED}Missing required dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}These are required for full functionality (including image checks and efficient display).${NC}"
        if [[ ${#recommendations[@]} -gt 0 ]]; then
             echo -e "${YELLOW}Optional recommendations: ${recommendations[*]}${NC}"
        fi
        echo -e "${YELLOW}Would you like to attempt to install the required dependencies? (y/n)${NC}"
        read -r install_deps

        if [[ "$install_deps" =~ ^[Yy]$ ]]; then
             # Try to install *only* the missing essential ones
            if ! install_dependencies "${missing[@]}"; then
                 echo -e "${RED}Failed to install dependencies. Some features may not work.${NC}"
                 wait_for_key
                 # Decide if we should exit or continue with reduced functionality
                 # For now, let's allow continuing but log the error.
                 log_message "ERROR" "Continuing despite failed dependency installation."
                 # return 1 # Uncomment to force exit on failed install
            else
                # Re-check after install attempt
                 local still_missing=()
                 for dep in "${missing[@]}"; do
                     if ! command -v "$dep" >/dev/null 2>&1; then
                         still_missing+=("$dep")
                     fi
                 done
                 if [[ ${#still_missing[@]} -gt 0 ]]; then
                      echo -e "${RED}Still missing dependencies after install attempt: ${still_missing[*]}.${NC}"
                      log_message "ERROR" "Still missing dependencies: ${still_missing[*]}"
                      wait_for_key
                      # return 1 # Uncomment to force exit
                 fi
            fi
        else
            echo -e "${RED}Missing dependencies may cause issues with monitoring.${NC}"
            wait_for_key
            # return 1 # Uncomment to force exit if user declines install
        fi
    fi

    # Check for discord.sh (already handled in send_discord_message, but good to check early)
    if ! check_discord_script; then
        # Message already printed by check_discord_script
        # We can continue, but notifications won't work.
        log_message "ERROR" "discord.sh script has issues, notifications will fail."
        # return 1 # Uncomment to make discord.sh mandatory
    fi

    log_message "INFO" "Dependency check complete."
    return 0 # Allow script to run even if some deps missing, with warnings/errors logged
}

# MODIFIED: Takes specific packages to install
install_dependencies() {
    local packages_to_install=("$@")
    if [[ ${#packages_to_install[@]} -eq 0 ]]; then
        log_message "INFO" "No specific dependencies requested for installation."
        return 0
    fi

    log_message "INFO" "Attempting to install missing dependencies: ${packages_to_install[*]}"

    # Check for root privileges
    if [[ "$EUID" -ne 0 ]]; then
        log_message "ERROR" "Root privileges required to install dependencies"
        echo -e "${RED}Error: Root privileges required to install dependencies${NC}"
        echo "Please run with sudo or manually install: ${packages_to_install[*]}"
        return 1
    fi

    # Detect package manager and install dependencies
    local package_manager=""

    if command -v apt-get >/dev/null 2>&1; then
        package_manager="apt-get"
    elif command -v yum >/dev/null 2>&1; then
        package_manager="yum"
    elif command -v dnf >/dev/null 2>&1; then
        package_manager="dnf"
    elif command -v apk >/dev/null 2>&1; then
        package_manager="apk"
    else
        log_message "ERROR" "Unsupported package manager"
        echo -e "${RED}Error: Unsupported package manager.${NC}"
        echo "Please install the following packages manually: ${packages_to_install[*]}"
        return 1
    fi

    echo -e "${YELLOW}Installing dependencies using $package_manager: ${packages_to_install[*]}...${NC}"

    local install_cmd=()
    case "$package_manager" in
        apt-get)
            echo "Running apt-get update..."
            apt-get update -qq || log_message "WARNING" "apt-get update failed"
            install_cmd=(apt-get install -y "${packages_to_install[@]}")
            ;;
        yum)
            # yum usually doesn't need an update beforehand for install
            install_cmd=(yum install -y "${packages_to_install[@]}")
            ;;
        dnf)
             # dnf usually doesn't need an update beforehand for install
            install_cmd=(dnf install -y "${packages_to_install[@]}")
            ;;
        apk)
            # apk add needs package names directly
            install_cmd=(apk add --no-cache "${packages_to_install[@]}")
            ;;
    esac

    # Execute install command
    "${install_cmd[@]}"
    local install_exit_code=$?

    if [[ $install_exit_code -ne 0 ]]; then
        log_message "ERROR" "Failed to install dependencies (${packages_to_install[*]}). Exit code: $install_exit_code"
        echo -e "${RED}Error: Failed to install dependencies.${NC}"
        return 1
    fi

    log_message "INFO" "Dependencies (${packages_to_install[*]}) installed successfully"
    echo -e "${GREEN}Dependencies (${packages_to_install[*]}) installed successfully.${NC}"
    return 0
}


# ========================
# Main Script Execution
# ========================

main() {
    # Load configuration FIRST
    load_config

    # Check dependencies AFTER loading config
    # Continue even if check returns non-zero, but log errors
    check_dependencies || log_message "ERROR" "Dependency check reported issues, continuing..."


    # Process command line arguments
    case "$1" in
        --service)
            # Running in service mode
            start_service_mode
            exit 0
            ;;
        --check)
            # Just run a health check and exit
            run_health_check
            exit $?
            ;;
        --report)
            # Generate a report and exit
            generate_security_report
            exit 0
            ;;
        --install-service)
            # Install as systemd service
            install_systemd_service
            exit $?
            ;;
       --check-images) # New flag
            # Check images and exit
            check_container_image_updates
            exit $?
            ;;
        --help|-h)
            echo "Pangolin Stack Monitoring System v${VERSION}" # Uses static version
            echo ""
            echo "Usage: $(basename "$0") [options]"
            echo ""
            echo "Options:"
            echo "  --help, -h         Show this help message"
            echo "  --service          Run in service mode (for systemd)"
            echo "  --check            Run a single health check and exit"
            echo "  --report           Generate a security report and exit"
            echo "  --install-service  Install as systemd service"
            echo "  --check-images     Check for container image updates and exit" # New
            echo "  --version, -v      Display version information (currently static)"
            echo ""
            echo "Without options, the script runs in interactive menu mode."
            exit 0
            ;;
        --version|-v)
            echo "Pangolin Stack Monitoring System v${VERSION}" # Uses static version
            exit 0
            ;;
    esac

    # Start main menu if no action argument was given
    main_menu
}

# Call main function
main "$@"
