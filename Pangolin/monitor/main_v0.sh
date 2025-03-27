#!/bin/bash

# =================================================================
# Pangolin Stack Monitoring System
# A comprehensive monitoring solution for Pangolin containers
# Features:
# - Container monitoring (health, resources, logs)
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
VERSION="1.0.0"
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
DEFAULT_CHECK_INTERVAL=60          # Seconds between checks
DEFAULT_REPORT_INTERVAL=43200      # 12 hours in seconds
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
DEFAULT_EMOJI_CHECK="✅"
DEFAULT_EMOJI_CROSS="❌"
DEFAULT_EMOJI_WARNING="⚠️"
DEFAULT_EMOJI_ALERT="🔔"
DEFAULT_EMOJI_SECURITY="🛡️"
DEFAULT_EMOJI_SERVER="🖥️"

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
    DEBUG=${DEBUG:-false}
    EMOJI_CHECK="${EMOJI_CHECK:-$DEFAULT_EMOJI_CHECK}"
    EMOJI_CROSS="${EMOJI_CROSS:-$DEFAULT_EMOJI_CROSS}"
    EMOJI_WARNING="${EMOJI_WARNING:-$DEFAULT_EMOJI_WARNING}"
    EMOJI_ALERT="${EMOJI_ALERT:-$DEFAULT_EMOJI_ALERT}"
    EMOJI_SECURITY="${EMOJI_SECURITY:-$DEFAULT_EMOJI_SECURITY}"
    EMOJI_SERVER="${EMOJI_SERVER:-$DEFAULT_EMOJI_SERVER}"
}

# Save default configuration
save_default_config() {
    cat > "$CONFIG_FILE" << EOL
# Pangolin Stack Monitor Configuration
# Generated on $(date)

# Monitoring Intervals
CHECK_INTERVAL=$DEFAULT_CHECK_INTERVAL
REPORT_INTERVAL=$DEFAULT_REPORT_INTERVAL

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

# Discord Webhook
DISCORD_WEBHOOK="$DEFAULT_DISCORD_WEBHOOK"

# Emoji Settings
EMOJI_CHECK="$DEFAULT_EMOJI_CHECK"
EMOJI_CROSS="$DEFAULT_EMOJI_CROSS"
EMOJI_WARNING="$DEFAULT_EMOJI_WARNING"
EMOJI_ALERT="$DEFAULT_EMOJI_ALERT"
EMOJI_SECURITY="$DEFAULT_EMOJI_SECURITY"
EMOJI_SERVER="$DEFAULT_EMOJI_SERVER"

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
    
    # Get IP information
    local IP=`echo $SSH_CLIENT | awk '{ ip = $1 } END { print ip }'`
    
    # Try to fetch IP data, fallback to just IP if curl fails
    if command -v curl &>/dev/null; then
        curl -s "https://ipapi.co/${IP}/json/" > $TMPFILE 2>/dev/null
        
        # Extract information
        local ISP=$(cat $TMPFILE | grep -o '"org": "[^"]*' | cut -d'"' -f4 2>/dev/null || echo "Unknown")
        local COUNTRY=$(cat $TMPFILE | grep -o '"country_name": "[^"]*' | cut -d'"' -f4 2>/dev/null || echo "Unknown")
        local CITY=$(cat $TMPFILE | grep -o '"city": "[^"]*' | cut -d'"' -f4 2>/dev/null || echo "Unknown")
        
        # Create message
        local title="SSH Login Detected"
        local message="**Details**\n • User: \`$(whoami)\` \n • Host: \`$(hostname)\` \n • Time: \`$DATE\` \n\n **Connection IP**\n • IP: \`${IP}\`\n • Location: \`${CITY}, ${COUNTRY}\`\n • ISP: \`${ISP}\`"
    else
        # Fallback message with just IP
        local title="SSH Login Detected"
        local message="**Details**\n • User: \`$(whoami)\` \n • Host: \`$(hostname)\` \n • Time: \`$DATE\` \n\n **Connection IP**\n • IP: \`${IP}\`"
    fi
    
    # Send notification
    send_discord_message "$title" "$message" "warning" "" "$BOTNAME"
    
    # Cleanup
    rm -f $TMPFILE
    
    return 0
}

# ========================
# System Updates Notification
# ========================

check_system_updates() {
    # Skip if update notifications are disabled
    if [[ "$LOG_NOTIFY" != "true" ]]; then
        log_message "DEBUG" "Update notifications are disabled, skipping"
        return 0
    fi
    
    log_message "INFO" "Checking for system updates"
    
    local updates_available=false
    local update_count=0
    local updates_list=""
    
    # Check for apt (Debian/Ubuntu)
    if command -v apt-get &>/dev/null; then
        # Update package lists quietly
        apt-get update -qq &>/dev/null
        
        # Check for upgradable packages
        updates_list=$(apt list --upgradable 2>/dev/null | grep -v "Listing...")
        update_count=$(echo "$updates_list" | wc -l)
        
        if [[ $update_count -gt 0 ]]; then
            updates_available=true
        fi
    # Check for dnf (Fedora/RHEL)
    elif command -v dnf &>/dev/null; then
        # Check for updates
        updates_list=$(dnf check-update -q 2>/dev/null)
        update_count=$(echo "$updates_list" | wc -l)
        
        if [[ $update_count -gt 0 ]]; then
            updates_available=true
        fi
    # Check for yum (CentOS)
    elif command -v yum &>/dev/null; then
        # Check for updates
        updates_list=$(yum check-update -q 2>/dev/null)
        update_count=$(echo "$updates_list" | wc -l)
        
        if [[ $update_count -gt 0 ]]; then
            updates_available=true
        fi
    fi
    
    # If updates are available, send notification
    if [[ "$updates_available" == "true" && $update_count -gt 0 ]]; then
        log_message "INFO" "System updates available, sending notification"
        
        # Create message
        local title="$(hostname) needs OS updates"
        local message="**${update_count} packages can be updated**\n\n\`\`\`\n$(echo "$updates_list" | head -n 15)\n\`\`\`"
        
        if [[ $update_count -gt 15 ]]; then
            message+="\n\n*...and $(($update_count - 15)) more packages*"
        fi
        
        message+="\n\nRun the appropriate update command to update the system."
        
        # Send notification
        send_discord_message "$title" "$message" "info" "" "System Updates"
    else
        log_message "DEBUG" "No system updates available"
    fi
    
    return 0
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
    
    log_message "INFO" "Monitoring network traffic for attacks"
    
    # Auto-detect available network interfaces (excluding lo)
    local interface=$(ls /sys/class/net/ | grep -v "lo" | head -1)
    
    if [[ -z "$interface" ]]; then
        log_message "WARNING" "No active network interfaces detected"
        return 1
    fi
    
    log_message "DEBUG" "Using network interface: $interface"
    local threshold=$NETWORK_THRESHOLD
    
    # Get current packet count
    local pkt_old=$(grep $interface: /proc/net/dev 2>/dev/null | cut -d : -f2 | awk '{ print $2 }')
    
    if [[ -z "$pkt_old" ]]; then
        log_message "WARNING" "Unable to read network statistics for $interface"
        return 1
    fi
    
    sleep 1
    local pkt_new=$(grep $interface: /proc/net/dev 2>/dev/null | cut -d : -f2 | awk '{ print $2 }')
    
    # Calculate packets per second
    local pkt=$(( $pkt_new - $pkt_old ))
    log_message "DEBUG" "Current network traffic: $pkt packets/s on $interface"
    
    # Check if above threshold
    if [ $pkt -gt $threshold ]; then
        log_message "WARNING" "Network attack detected: $pkt packets/s"
        
        # Get bandwidth info
        local old_bs=$(grep $interface: /proc/net/dev | cut -d : -f2 | awk '{ print $1 }')
        sleep 1
        local new_bs=$(grep $interface: /proc/net/dev | cut -d : -f2 | awk '{ print $1 }')
        local byte=$(( $new_bs - $old_bs ))
        local mbps=$(( $byte/1024/1024 ))
        
        # Create attack notification
        local title="Attack Detected"
        local message="**Network attack detected!**\n\n"
        message+="❗ **Traffic Spike Details:**\n"
        message+="- **Incoming Packets:** ${pkt} packets per second\n"
        message+="- **Bandwidth Usage:** ${mbps} MB/s\n"
        message+="- **Interface:** ${interface}\n\n"
        message+="The system is monitoring the attack. Automatic mitigation may be in progress."
        
        # Send notification
        send_discord_message "$title" "$message" "critical" "" "Attack Alerts"
        
        # Wait for attack to subside before sending all-clear
        log_message "INFO" "Monitoring attack, will send all-clear when traffic normalizes"
        sleep 120
        
        # Check if traffic has returned to normal
        pkt_old=$(grep $interface: /proc/net/dev | cut -d : -f2 | awk '{ print $2 }')
        sleep 1
        pkt_new=$(grep $interface: /proc/net/dev | cut -d : -f2 | awk '{ print $2 }')
        pkt=$(( $pkt_new - $pkt_old ))
        
        if [ $pkt -lt $threshold ]; then
            log_message "INFO" "Attack traffic has subsided, sending all-clear"
            
            # Create all-clear notification
            local title="Attack Ended"
            local message="**Network attack has ended**\n\n"
            message+="✅ **Current status:**\n"
            message+="- **Current Traffic:** ${pkt} packets per second\n"
            message+="- **System Status:** Normal\n\n"
            message+="Traffic has returned to normal levels. The system should be stable now."
            
            # Send notification
            send_discord_message "$title" "$message" "success" "" "Attack Alerts"
        fi
        
        return 1
    fi
    
    return 0
}

# ========================
# Container Monitoring
# ========================

check_container_health() {
    local container="$1"
    
    if ! docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
        log_message "ERROR" "Container $container not found"
        return 1
    fi

    local status=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null)
    local health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container" 2>/dev/null)

    if [[ "$status" != "running" ]]; then
        log_message "ERROR" "Container $container is $status"
        return 1
    fi
    if [[ "$health" != "none" && "$health" != "healthy" ]]; then
        log_message "WARNING" "Container $container health: $health"
        return 2
    fi
    
    log_message "INFO" "Container $container is healthy"
    return 0
}

get_container_stats() {
    local container="$1"
    
    if ! docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
        log_message "ERROR" "Container $container not found"
        return 1
    fi

    # Get CPU and memory usage
    local stats=$(docker stats --no-stream --format "{{.CPUPerc}} {{.MemPerc}}" "$container")
    local cpu=$(echo "$stats" | awk '{print $1}' | sed 's/%//')
    local mem=$(echo "$stats" | awk '{print $2}' | sed 's/%//')

    # Check CPU usage against thresholds
    if [[ -n "$cpu" && "$cpu" =~ ^[0-9.]+$ ]]; then
        local cpu_numeric=$(echo "$cpu" | awk '{printf "%d", $1}')
        
        if (( cpu_numeric > CPU_CRITICAL_THRESHOLD )); then
            log_message "ERROR" "$container CPU critical: ${cpu}%"
            
            # Create alert data
            local title="Container Alert: $container"
            local message="The container **$container** has reported high CPU usage:\n\n"
            message+="**Current Value**: $cpu%\n"
            message+="**Threshold**: ${CPU_CRITICAL_THRESHOLD}%\n\n"
            message+="Please check the container status and logs for more information."
            
            # Create fields
            local fields="Container Status;$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "Unknown");true"
            fields+=";Health;$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container" 2>/dev/null || echo "Unknown");true"
            fields+=";Started At;$(docker inspect --format='{{.State.StartedAt}}' "$container" 2>/dev/null | cut -d'.' -f1 | sed 's/T/ /g' || echo "Unknown");false"
            
            send_alert "container" "$title" "$message" "critical" "$fields"
            
        elif (( cpu_numeric > CPU_WARNING_THRESHOLD )); then
            log_message "WARNING" "$container CPU high: ${cpu}%"
            
            # Skip alert for warning level to reduce notification spam
            # Uncomment below code if you want warning alerts too
            # local title="Container Alert: $container"
            # local message="The container **$container** has reported moderately high CPU usage:\n\n"
            # message+="**Current Value**: $cpu%\n"
            # message+="**Threshold**: ${CPU_WARNING_THRESHOLD}%\n\n"
            # message+="Please monitor the container if this persists."
            
            # local fields="Container Status;$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "Unknown");true"
            # fields+=";Health;$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container" 2>/dev/null || echo "Unknown");true"
            # fields+=";Started At;$(docker inspect --format='{{.State.StartedAt}}' "$container" 2>/dev/null | cut -d'.' -f1 | sed 's/T/ /g' || echo "Unknown");false"
            
            # send_alert "container" "$title" "$message" "warning" "$fields"
        fi
    fi

    # Check memory usage against thresholds
    if [[ -n "$mem" && "$mem" =~ ^[0-9.]+$ ]]; then
        local mem_numeric=$(echo "$mem" | awk '{printf "%d", $1}')
        
        if (( mem_numeric > MEM_CRITICAL_THRESHOLD )); then
            log_message "ERROR" "$container memory critical: ${mem}%"
            
            # Create alert data
            local title="Container Alert: $container"
            local message="The container **$container** has reported high memory usage:\n\n"
            message+="**Current Value**: $mem%\n"
            message+="**Threshold**: ${MEM_CRITICAL_THRESHOLD}%\n\n"
            message+="Please check the container status and logs for more information."
            
            # Create fields
            local fields="Container Status;$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "Unknown");true"
            fields+=";Health;$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container" 2>/dev/null || echo "Unknown");true"
            fields+=";Started At;$(docker inspect --format='{{.State.StartedAt}}' "$container" 2>/dev/null | cut -d'.' -f1 | sed 's/T/ /g' || echo "Unknown");false"
            
            send_alert "container" "$title" "$message" "critical" "$fields"
            
        elif (( mem_numeric > MEM_WARNING_THRESHOLD )); then
            log_message "WARNING" "$container memory high: ${mem}%"
            
            # Skip alert for warning level to reduce notification spam
        fi
    fi

    # Return formatted stats
    echo "${cpu:-N/A}% CPU, ${mem:-N/A}% Memory"
}

check_container_logs() {
    local container="$1"
    local search_pattern="${2:-error|exception|fatal|failed|crash}"
    local lines="${3:-100}"
    
    if ! docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
        log_message "ERROR" "Container $container not found"
        return 1
    fi
    
    # Search for errors in logs
    local error_count=$(docker logs --tail "$lines" "$container" 2>&1 | grep -iE "$search_pattern" | wc -l)
    
    if [[ $error_count -gt 0 ]]; then
        local errors=$(docker logs --tail "$lines" "$container" 2>&1 | grep -iE "$search_pattern" | head -n 5)
        log_message "WARNING" "Found $error_count errors in $container logs"
        
        if [[ $error_count -gt 10 ]]; then
            # Serious error situation
            local title="Container Log Errors: $container"
            local message="Found **$error_count** errors in container logs.\n\nRecent errors:\n\`\`\`\n$errors\n\`\`\`\n\nPlease check container logs for details."
            
            local fields="Container Status;$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "Unknown");true"
            fields+=";Health;$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container" 2>/dev/null || echo "Unknown");true"
            fields+=";Error Count;$error_count;false"
            
            send_alert "container" "$title" "$message" "error" "$fields"
        fi
        
        return 1
    fi
    
    log_message "INFO" "No errors found in $container logs"
    return 0
}

display_container_status() {
    echo -e "${CYAN}=== Container Status ===${NC}"
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}Docker not installed${NC}"
        wait_for_key
        return
    fi

    for container in "${CONTAINER_NAMES[@]}"; do
        echo -e "\n${CYAN}$container:${NC}"
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            local status=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null)
            local health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container" 2>/dev/null)
            local stats=$(get_container_stats "$container")
            local network=$(docker stats --no-stream --format "{{.NetIO}}" "$container" 2>/dev/null || echo "N/A")
            local block_io=$(docker stats --no-stream --format "{{.BlockIO}}" "$container" 2>/dev/null || echo "N/A")
            local created=$(docker inspect --format='{{.Created}}' "$container" 2>/dev/null | cut -d'.' -f1 | sed 's/T/ /g' || echo "N/A")
            local started=$(docker inspect --format='{{.State.StartedAt}}' "$container" 2>/dev/null | cut -d'.' -f1 | sed 's/T/ /g' || echo "N/A")
            
            # Display status with appropriate color
            [[ "$status" == "running" && ("$health" == "healthy" || "$health" == "N/A") ]] && \
                display_status "OK" "Status: $status, Health: $health" || \
                display_status "ERROR" "Status: $status, Health: $health"
            
            # Display additional information
            echo -e "  ${CYAN}Created:${NC} $created"
            echo -e "  ${CYAN}Started:${NC} $started"
            echo -e "  ${CYAN}Resources:${NC} $stats"
            echo -e "  ${CYAN}Network I/O:${NC} $network"
            echo -e "  ${CYAN}Block I/O:${NC} $block_io"
            
            # Display ports
            local ports=$(docker inspect --format='{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} -> {{range $conf}}{{.HostIp}}:{{.HostPort}}{{end}} {{end}}' "$container" 2>/dev/null)
            if [[ -n "$ports" ]]; then
                echo -e "  ${CYAN}Ports:${NC} $ports"
            fi
            
            # Display mounts if any
            local mounts=$(docker inspect --format='{{range .Mounts}}{{.Type}}:{{.Source}} -> {{.Destination}} {{end}}' "$container" 2>/dev/null)
            if [[ -n "$mounts" ]]; then
                echo -e "  ${CYAN}Mounts:${NC} $mounts"
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
    local cpu=$(top -bn1 | grep "Cpu(s)" | \
                sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | \
                awk '{print 100 - $1}')
    [[ -z "$cpu" ]] && cpu="N/A"
    
    # Ensure value is numeric and format with one decimal place
    if [[ "$cpu" != "N/A" ]]; then
        cpu=$(printf "%.1f" $cpu)
    fi
    
    log_message "INFO" "CPU usage: ${cpu}%"

    if [[ "$cpu" != "N/A" ]]; then
        if (( $(echo "$cpu > $CPU_CRITICAL_THRESHOLD" | bc -l) )); then
            log_message "ERROR" "CPU usage critical: ${cpu}%"
            
            # Get top processes
            local top_processes=$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6 | tail -n 5)
            local message="❗ CPU usage critical: ${cpu}%\n\nTop CPU processes:\n\`\`\`\n$top_processes\n\`\`\`"
            
            send_alert "system" "CPU Alert" "$message" "critical" ""
            return 2
        elif (( $(echo "$cpu > $CPU_WARNING_THRESHOLD" | bc -l) )); then
            log_message "WARNING" "CPU usage high: ${cpu}%"
            return 1
        fi
    fi
    return 0
}

check_memory_usage() {
    local mem=$(free -m | awk 'NR==2{printf "%.1f", $3*100/$2}')
    [[ -z "$mem" ]] && mem="N/A"
    log_message "INFO" "Memory usage: ${mem}%"

    if [[ "$mem" != "N/A" ]]; then
        if (( $(echo "$mem > $MEM_CRITICAL_THRESHOLD" | bc -l) )); then
            log_message "ERROR" "Memory usage critical: ${mem}%"
            
            # Get top memory processes
            local top_processes=$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 6 | tail -n 5)
            local message="❗ Memory usage critical: ${mem}%\n\nTop memory processes:\n\`\`\`\n$top_processes\n\`\`\`"
            
            send_alert "system" "Memory Alert" "$message" "critical" ""
            return 2
        elif (( $(echo "$mem > $MEM_WARNING_THRESHOLD" | bc -l) )); then
            log_message "WARNING" "Memory usage high: ${mem}%"
            return 1
        fi
    fi
    return 0
}

check_disk_usage() {
    local disk=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    [[ -z "$disk" ]] && disk="N/A"
    log_message "INFO" "Disk usage: ${disk}%"

    if [[ "$disk" != "N/A" ]]; then
        if (( $(echo "$disk > $DISK_CRITICAL_THRESHOLD" | bc -l) )); then
            log_message "ERROR" "Disk usage critical: ${disk}%"
            
            # Get largest directories
            local large_dirs=$(du -h --max-depth=1 / 2>/dev/null | sort -hr | head -n 10)
            local message="❗ Disk usage critical: ${disk}%\n\nLargest directories:\n\`\`\`\n$large_dirs\n\`\`\`"
            
            send_alert "system" "Disk Alert" "$message" "critical" ""
            return 2
        elif (( $(echo "$disk > $DISK_WARNING_THRESHOLD" | bc -l) )); then
            log_message "WARNING" "Disk usage high: ${disk}%"
            return 1
        fi
    fi
    return 0
}

check_system_load() {
    local load=$(uptime | awk -F'[a-z]:' '{print $2}' | sed 's/,//g' | awk '{print $1}')
    local cores=$(nproc)
    local norm_load=$(echo "scale=2; $load / $cores" | bc)
    log_message "INFO" "System load: $load (normalized: ${norm_load}x)"

    if [[ "$norm_load" != "N/A" ]]; then
        if (( $(echo "$norm_load > 2.0" | bc -l) )); then
            log_message "ERROR" "System load critical: ${norm_load}x"
            
            # Get top processes by CPU
            local top_processes=$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6 | tail -n 5)
            local message="❗ System load critical: ${norm_load}x (raw: $load, cores: $cores)\n\nTop processes:\n\`\`\`\n$top_processes\n\`\`\`"
            
            send_alert "system" "System Load Alert" "$message" "critical" ""
            return 2
        elif (( $(echo "$norm_load > 1.0" | bc -l) )); then
            log_message "WARNING" "System load high: ${norm_load}x"
            return 1
        fi
    fi
    return 0
}

display_system_resources() {
    echo -e "${CYAN}=== System Resources ===${NC}"
    
    # Get system information
    local hostname=$(hostname)
    local os=$(cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2 || echo "Unknown")
    local kernel=$(uname -r)
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -n1 | cut -d':' -f2 | sed 's/^[ \t]*//' || echo "Unknown")
    local cpu_cores=$(nproc)
    
    # Get usage metrics
    local cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | awk '{printf "%.1f", $1}')
    local mem=$(free -m | awk 'NR==2{printf "%.1f", $3*100/$2}')
    local mem_used=$(free -h | awk 'NR==2{print $3}')
    local mem_total=$(free -h | awk 'NR==2{print $2}')
    local disk=$(df -h / | awk 'NR==2{print $5}')
    local disk_used=$(df -h / | awk 'NR==2{print $3}')
    local disk_total=$(df -h / | awk 'NR==2{print $2}')
    local load=$(uptime | awk -F'[a-z]:' '{print $2}' | sed 's/,//g' | awk '{print $1}')
    local norm_load=$(echo "scale=2; $load / $cpu_cores" | bc)
    local uptime=$(uptime -p)
    
    # Display system information
    echo -e "${CYAN}System Information:${NC}"
    echo -e "  Hostname:   $hostname"
    echo -e "  OS:         $os"
    echo -e "  Kernel:     $kernel"
    echo -e "  CPU:        $cpu_model ($cpu_cores cores)"
    echo -e "  Uptime:     $uptime"
    
    echo -e "\n${CYAN}Resource Usage:${NC}"
    # Display with color based on thresholds
    [[ "$cpu" =~ ^[0-9.]+$ ]] && (( $(echo "$cpu > $CPU_WARNING_THRESHOLD" | bc -l) )) && \
        display_status "WARNING" "CPU Usage: ${cpu}%" || \
        display_status "OK" "CPU Usage: ${cpu:-N/A}%"
    
    [[ "$mem" =~ ^[0-9.]+$ ]] && (( $(echo "$mem > $MEM_WARNING_THRESHOLD" | bc -l) )) && \
        display_status "WARNING" "Memory Usage: ${mem}% ($mem_used / $mem_total)" || \
        display_status "OK" "Memory Usage: ${mem:-N/A}% ($mem_used / $mem_total)"
    
    [[ "$disk" =~ ^[0-9.]+$ ]] && (( $(echo "${disk%\%} > $DISK_WARNING_THRESHOLD" | bc -l) )) && \
        display_status "WARNING" "Disk Usage: ${disk} ($disk_used / $disk_total)" || \
        display_status "OK" "Disk Usage: ${disk} ($disk_used / $disk_total)"
    
    [[ "$norm_load" =~ ^[0-9.]+$ ]] && (( $(echo "$norm_load > 1.0" | bc -l) )) && \
        display_status "WARNING" "Load Average: $load (normalized: ${norm_load}x)" || \
        display_status "OK" "Load Average: $load (normalized: ${norm_load}x)"
    
    echo -e "\n${CYAN}Memory Details:${NC}"
    free -h | grep -v "Swap"
    
    echo -e "\n${CYAN}Disk Usage:${NC}"
    df -h | grep -v "tmpfs" | grep -v "Use%"
    
    echo -e "\n${CYAN}Top CPU Processes:${NC}"
    ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -n 6
    
    echo -e "\n${CYAN}Top Memory Processes:${NC}"
    ps -eo pid,ppid,cmd,%mem --sort=-%mem | head -n 6
    
    wait_for_key
}

# ========================
# Security Monitoring
# ========================

check_ssh_attempts() {
    echo -e "${CYAN}=== SSH Login Attempts ===${NC}"
    local found_logs=false
    
    # Determine which logs to check
    if command -v journalctl >/dev/null 2>&1; then
        # Check if journalctl has SSH logs
        if journalctl -u ssh -u sshd --since "1 day ago" 2>/dev/null | grep -q .; then
            found_logs=true
            echo -e "${CYAN}Failed Attempts (24h):${NC}"
            journalctl -u ssh -u sshd --since "1 day ago" 2>/dev/null | grep "Failed password" | tail -n 10 || echo "None found"
            
            echo -e "\n${CYAN}Successful Logins (24h):${NC}"
            journalctl -u ssh -u sshd --since "1 day ago" 2>/dev/null | grep "Accepted" | tail -n 5 || echo "None found"
            
            # IP statistics
            echo -e "\n${CYAN}Failed Login IPs (Top 5):${NC}"
            journalctl -u ssh -u sshd --since "1 day ago" 2>/dev/null | grep "Failed password" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -n 5 || echo "None found"
        else
            # Try alternative service names
            if journalctl -u sshd.service --since "1 day ago" 2>/dev/null | grep -q .; then
                found_logs=true
                echo -e "${CYAN}Failed Attempts (24h):${NC}"
                journalctl -u sshd.service --since "1 day ago" 2>/dev/null | grep "Failed password" | tail -n 10 || echo "None found"
                
                echo -e "\n${CYAN}Successful Logins (24h):${NC}"
                journalctl -u sshd.service --since "1 day ago" 2>/dev/null | grep "Accepted" | tail -n 5 || echo "None found"
                
                # IP statistics
                echo -e "\n${CYAN}Failed Login IPs (Top 5):${NC}"
                journalctl -u sshd.service --since "1 day ago" 2>/dev/null | grep "Failed password" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -n 5 || echo "None found"
            fi
        fi
    fi
    
    if [[ "$found_logs" == "false" && -f /var/log/auth.log ]]; then
        found_logs=true
        echo -e "${CYAN}Failed Attempts (24h):${NC}"
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -n 10 || echo "None found"
        
        echo -e "\n${CYAN}Successful Logins (24h):${NC}"
        grep "Accepted" /var/log/auth.log 2>/dev/null | tail -n 5 || echo "None found"
        
        # IP statistics
        echo -e "\n${CYAN}Failed Login IPs (Top 5):${NC}"
        grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -n 5 || echo "None found"
    fi
    
    # Try additional log locations
    if [[ "$found_logs" == "false" && -f /var/log/secure ]]; then
        found_logs=true
        echo -e "${CYAN}Failed Attempts (24h):${NC}"
        grep "Failed password" /var/log/secure 2>/dev/null | tail -n 10 || echo "None found"
        
        echo -e "\n${CYAN}Successful Logins (24h):${NC}"
        grep "Accepted" /var/log/secure 2>/dev/null | tail -n 5 || echo "None found"
        
        # IP statistics
        echo -e "\n${CYAN}Failed Login IPs (Top 5):${NC}"
        grep "Failed password" /var/log/secure 2>/dev/null | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -n 5 || echo "None found"
    fi
    
    # If all methods fail, display a clear message
    if [[ "$found_logs" == "false" ]]; then
        echo -e "${RED}SSH logs unavailable or no SSH activity has been recorded.${NC}"
        echo -e "${YELLOW}Possible reasons:${NC}"
        echo -e "  • SSH service may be using a different name or logging configuration"
        echo -e "  • Current user may not have permissions to read system logs"
        echo -e "  • System might be using a different logging system"
        echo -e "\n${YELLOW}Try running this script with sudo for additional permissions.${NC}"
    fi
    
    wait_for_key
}

check_security_logs() {
    local issues=0
    local log_data=""
    
    # Check for SSH failures
    local ssh_fail=0
    local sudo_use=0
    
    # Use safe command execution with proper error handling
    if command -v journalctl >/dev/null 2>&1; then
        # Using grep -c with || to ensure we get a valid number even if there are no matches
        ssh_fail=$(journalctl -u ssh -u sshd --since "1 hour ago" 2>/dev/null | grep -c "Failed password" 2>/dev/null || echo 0)
        sudo_use=$(journalctl --since "1 day ago" 2>/dev/null | grep "sudo:" | grep -c "COMMAND=" 2>/dev/null || echo 0)
    elif [[ -f /var/log/auth.log ]]; then
        ssh_fail=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
        sudo_use=$(grep "sudo:" /var/log/auth.log 2>/dev/null | grep -c "COMMAND=" 2>/dev/null || echo 0)
    elif [[ -f /var/log/secure ]]; then
        ssh_fail=$(grep -c "Failed password" /var/log/secure 2>/dev/null || echo 0)
        sudo_use=$(grep "sudo:" /var/log/secure 2>/dev/null | grep -c "COMMAND=" 2>/dev/null || echo 0)
    fi
    
    # Remove any whitespace from the variables and ensure they're numeric
    ssh_fail=$(echo "$ssh_fail" | tr -d '[:space:]')
    sudo_use=$(echo "$sudo_use" | tr -d '[:space:]')
    
    # Default to 0 if not a valid number
    [[ "$ssh_fail" =~ ^[0-9]+$ ]] || ssh_fail=0
    [[ "$sudo_use" =~ ^[0-9]+$ ]] || sudo_use=0
    
    log_message "DEBUG" "SSH failures: $ssh_fail, Sudo usage: $sudo_use"
    
    # Check thresholds and prepare alert data
    if (( ssh_fail > 10 )); then
        issues=1
        log_data+="\n- $ssh_fail SSH failures in the last hour"
        log_message "WARNING" "$ssh_fail SSH failures detected"
        
        # If excessive failures, generate more detailed report
        if (( ssh_fail > 50 )); then
            local ip_stats=""
            
            if command -v journalctl >/dev/null 2>&1; then
                ip_stats=$(journalctl -u ssh -u sshd --since "1 hour ago" 2>/dev/null | grep "Failed password" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -n 5)
            elif [[ -f /var/log/auth.log ]]; then
                ip_stats=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -n 5)
            elif [[ -f /var/log/secure ]]; then
                ip_stats=$(grep "Failed password" /var/log/secure 2>/dev/null | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -n 5)
            fi
            
            # Ensure ip_stats isn't empty
            [[ -z "$ip_stats" ]] && ip_stats="No details available"
            
            local message="❗ **Security Alert: Excessive SSH Failures**\n\n"
            message+="Detected **$ssh_fail** SSH login failures in the last hour.\n\n"
            message+="**Top source IPs:**\n\`\`\`\n$ip_stats\n\`\`\`\n\n"
            message+="This may indicate a brute force attack. Consider enabling fail2ban or adding these IPs to CrowdSec."
            
            send_alert "security" "SSH Brute Force Alert" "$message" "warning" ""
        fi
    fi
    
    if (( sudo_use > 20 )); then
        issues=1
        log_data+="\n- $sudo_use sudo commands in the last day"
        log_message "WARNING" "High sudo usage: $sudo_use commands in the last day"
    fi
    
    # Check for rootkits if chkrootkit is available
    if command -v chkrootkit >/dev/null 2>&1; then
        local rootkit_check=$(chkrootkit -q 2>/dev/null | grep -v "not found\|nothing found\|not infected")
        if [[ -n "$rootkit_check" ]]; then
            issues=1
            log_data+="\n- Potential rootkit detected: $rootkit_check"
            log_message "ERROR" "Potential rootkit detected: $rootkit_check"
            
            local message="❗ **Security Alert: Potential Rootkit Detected**\n\n"
            message+="Chkrootkit has detected potential rootkit activity:\n\`\`\`\n$rootkit_check\n\`\`\`\n\n"
            message+="Please investigate immediately as this could indicate a system compromise."
            
            send_alert "security" "Rootkit Alert" "$message" "critical" ""
        fi
    fi
    
    # Send general security alert if issues found
    if (( issues == 1 )); then
        send_alert "security" "Security Issues" "❗ Security issues detected:$log_data" "warning" ""
    fi
    
    return $issues
}

# ========================
# Traefik Log Analysis
# ========================

analyze_traefik_logs() {
    echo -e "${CYAN}=== Traefik Access Logs Analysis ===${NC}"
    
    if ! docker ps | grep -q "traefik"; then
        echo -e "${RED}Traefik container is not running.${NC}"
        wait_for_key
        return 1
    fi
    
    # Get recent logs from Traefik container
    local logs=$(docker logs traefik --tail 1000 2>/dev/null)
    if [[ -z "$logs" ]]; then
        echo -e "${YELLOW}No logs found for Traefik container.${NC}"
        wait_for_key
        return 0
    fi
    
    # Extract HTTP status codes and count occurrences
    echo -e "${CYAN}HTTP Status Code Distribution:${NC}"
    echo "$logs" | grep -oE "\"GET|\"POST" | sort | uniq -c | sort -nr
    
    echo -e "\n${CYAN}HTTP Error Codes (4xx, 5xx):${NC}"
    echo "$logs" | grep -E "HTTP/[0-9.]+ (4|5)[0-9]{2}" | cut -d ' ' -f 9 | sort | uniq -c | sort -nr
    
    # Extract top requested URLs
    echo -e "\n${CYAN}Top Requested URLs:${NC}"
    echo "$logs" | grep -oE 'GET [^"]*|POST [^"]*' | sort | uniq -c | sort -nr | head -10
    
    # Extract top client IPs
    echo -e "\n${CYAN}Top Client IPs:${NC}"
    echo "$logs" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr | head -10
    
    # Detect potential attacks
    echo -e "\n${CYAN}Potential Attack Patterns:${NC}"
    # SQL Injection attempts
    local sql_injection=$(echo "$logs" | grep -iE "select|union|insert|drop|;--|'--" | wc -l)
    echo -e "  SQL Injection attempts: $sql_injection"
    
    # XSS attempts
    local xss=$(echo "$logs" | grep -iE "<script>|javascript:|alert\(" | wc -l)
    echo -e "  XSS attempts: $xss"
    
    # Path traversal attempts
    local path_traversal=$(echo "$logs" | grep -iE "\.\.\/|\.\.%2f|etc/passwd" | wc -l)
    echo -e "  Path traversal attempts: $path_traversal"
    
    # Abnormal request volume from single IP
    local abnormal_ips=$(echo "$logs" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr | awk '$1 > 50 {print $1, $2}')
    if [[ -n "$abnormal_ips" ]]; then
        echo -e "  High volume requests from single IPs:"
        echo "$abnormal_ips" | while read count ip; do
            echo -e "    $ip: $count requests"
        done
    else
        echo -e "  No abnormal request volumes detected."
    fi
    
    wait_for_key
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
        echo -e "${YELLOW}$(emoji_map ':warning:') ISSUES${NC}"
        report+=":warning: ISSUES\n"
        status=1
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
    if [[ -n "$DISCORD_WEBHOOK" ]] && validate_discord_webhook "$DISCORD_WEBHOOK" >/dev/null; then
        local severity="warning"
        [[ "$status" -eq 0 ]] && severity="success"
        local title="Health Check Report"
        send_discord_message "$title" "$report" "$severity" "" "Pangolin Health"
    fi

    return $status
}

# ========================
# Generate Reports
# ========================

generate_security_report() {
    local title=":shield: Pangolin Security Report"
    local report=""
    local severity="info"

    # System information
    report+="**System Information:**\n"
    report+="* Hostname: $(hostname)\n"
    report+="* OS: $(cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2 || echo "Unknown")\n"
    report+="* Kernel: $(uname -r)\n"
    report+="* Uptime: $(uptime -p)\n\n"

    # System resources
    report+="**System Resources:**\n"
    local cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    local mem=$(free -m | awk 'NR==2{printf "%.1f", $3*100/$2}')
    local disk=$(df -h / | awk 'NR==2{print $5}')
    local load=$(uptime | awk -F'[a-z]:' '{print $2}' | sed 's/,//g' | awk '{print $1}')
    local cores=$(nproc)
    local norm_load=$(echo "scale=2; $load / $cores" | bc)

    report+="* CPU Usage: ${cpu}%\n"
    report+="* Memory Usage: ${mem}%\n"
    report+="* Disk Usage: ${disk}\n"
    report+="* Load: $load (normalized: ${norm_load}x)\n\n"

    # Network statistics
    # Auto-detect network interface
    local interface=$(ls /sys/class/net/ | grep -v "lo" | head -1)
    if [[ -n "$interface" ]]; then
        local pkt_old=$(grep $interface: /proc/net/dev 2>/dev/null | cut -d : -f2 | awk '{ print $2 }')
        sleep 1
        local pkt_new=$(grep $interface: /proc/net/dev 2>/dev/null | cut -d : -f2 | awk '{ print $2 }')
        local pkt=$(( $pkt_new - $pkt_old ))
        
        report+="**Network Status:**\n"
        report+="* Current Traffic: $pkt packets/s\n"
        
        if [ $pkt -gt $NETWORK_THRESHOLD ]; then
            report+="* :warning: **Warning:** Traffic above threshold ($NETWORK_THRESHOLD packets/s)\n"
            severity="warning"
        else
            report+="* Traffic within normal parameters\n"
        fi
        report+="\n"
    fi

    # SSH activity
    report+="**SSH Activity (24h):**\n"
    local ssh_failures=0
    local ssh_success=0

    if command -v journalctl >/dev/null 2>&1; then
        ssh_failures=$(journalctl -u ssh -u sshd --since "1 day ago" 2>/dev/null | grep "Failed password" | wc -l)
        ssh_success=$(journalctl -u ssh -u sshd --since "1 day ago" 2>/dev/null | grep "Accepted" | wc -l)
    elif [[ -f /var/log/auth.log ]]; then
        ssh_failures=$(grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l)
        ssh_success=$(grep "Accepted" /var/log/auth.log 2>/dev/null | wc -l)
    elif [[ -f /var/log/secure ]]; then
        ssh_failures=$(grep "Failed password" /var/log/secure 2>/dev/null | wc -l)
        ssh_success=$(grep "Accepted" /var/log/secure 2>/dev/null | wc -l)
    fi

    report+="* Failed login attempts: $ssh_failures\n"
    report+="* Successful logins: $ssh_success\n\n"

    # Container status
    report+="**Container Status:**\n"
    for container in "${CONTAINER_NAMES[@]}"; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            local status=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null)
            local health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container" 2>/dev/null)
            local cpu_mem=$(docker stats --no-stream --format "{{.CPUPerc}} {{.MemPerc}}" "$container" 2>/dev/null)
            local container_cpu=$(echo "$cpu_mem" | awk '{print $1}')
            local container_mem=$(echo "$cpu_mem" | awk '{print $2}')

            if [[ "$status" == "running" && ("$health" == "healthy" || "$health" == "N/A") ]]; then
                report+="* :green_circle: $container: Running (Health: $health, $container_cpu CPU, $container_mem Memory)\n"
            else
                report+="* :yellow_circle: $container: $status (Health: $health)\n"
                severity="warning"
            fi
        else
            report+="* :red_circle: $container: Not found\n"
            severity="warning"
        fi
    done

    # Send report to Discord
    send_discord_message "$title" "$report" "$severity" "" "Pangolin Security"
    log_message "INFO" "Security report generated and sent to Discord"
}

# ========================
# Monitoring Functions
# ========================

start_monitoring_foreground() {
    echo -e "${CYAN}=== Starting Monitoring in Foreground ===${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    
    # Trap Ctrl+C
    trap 'echo -e "\n${GREEN}Monitoring stopped${NC}"; exit 0' INT TERM
    
    local cycle_count=0
    local last_report_time=$(date +%s)
    
    while true; do
        cycle_count=$((cycle_count + 1))
        local current_time=$(date +%s)
        
        echo -e "\n${CYAN}[$(date)] Running health check (cycle #${cycle_count})${NC}"
        run_health_check
        
        # Check for system updates (once every 24 hours)
        if [[ $cycle_count -eq 1 || $(( cycle_count % (24 * 60 / CHECK_INTERVAL) )) -eq 0 ]]; then
            echo -e "\n${CYAN}Checking for system updates...${NC}"
            check_system_updates
        fi
        
        # Monitor network for attacks
        echo -e "\n${CYAN}Monitoring network traffic...${NC}"
        monitor_network_traffic
        
        # Check for SSH login events if SSH_CLIENT is set (on each cycle)
        if [[ -n "$SSH_CLIENT" && "$SSH_NOTIFY" == "true" ]]; then
            echo -e "\n${CYAN}New SSH connection detected, sending notification...${NC}"
            ssh_login_notification
        fi
        
        # Send heartbeat to Discord every 60 cycles
        if [[ $cycle_count -eq 1 || $(( cycle_count % 60 )) -eq 0 ]]; then
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

start_service_mode() {
    log_message "INFO" "Starting in service mode"
    
    # Trap signals
    trap 'log_message "INFO" "Service stopping"; exit 0' INT TERM
    
    local cycle_count=0
    local last_report_time=$(date +%s)
    
    send_discord_message "Service Started" ":green_circle: Pangolin Monitor service started" "success"
    
    while true; do
        cycle_count=$((cycle_count + 1))
        local current_time=$(date +%s)
        
        # Run health check silently
        if ! run_health_check >/dev/null 2>&1; then
            log_message "WARNING" "Health check found issues"
        else
            log_message "INFO" "Health check completed successfully"
        fi
        
        # Check for system updates (once every 24 hours)
        if [[ $cycle_count -eq 1 || $(( cycle_count % (24 * 60 / CHECK_INTERVAL) )) -eq 0 ]]; then
            log_message "INFO" "Checking for system updates"
            check_system_updates >/dev/null 2>&1
        fi
        
        # Monitor network for attacks
        monitor_network_traffic >/dev/null 2>&1
        
        # Check for SSH login events if SSH_CLIENT is set
        if [[ -n "$SSH_CLIENT" && "$SSH_NOTIFY" == "true" ]]; then
            log_message "INFO" "New SSH connection detected"
            ssh_login_notification >/dev/null 2>&1
        fi
        
        # Send heartbeat every hour
        if [[ $cycle_count -eq 1 || $(( cycle_count % (60 * 60 / CHECK_INTERVAL) )) -eq 0 ]]; then
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
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This operation requires root privileges.${NC}"
        echo -e "${YELLOW}Please run with sudo:${NC} sudo $0 --install-service"
        wait_for_key
        return 1
    fi
    
    local SERVICE_NAME="pangolin-monitor"
    local SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    
    # Create service file
    cat > "$SERVICE_FILE" << EOL
[Unit]
Description=Pangolin Stack Monitoring Service
After=docker.service
Wants=docker.service

[Service]
Type=simple
User=root
ExecStart=${SCRIPT_DIR}/$(basename "$0") --service
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL
    
    chmod 644 "$SERVICE_FILE"
    
    # Reload systemd, enable and start service
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    
    # Check status
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}Service installed and started successfully.${NC}"
        echo -e "You can check the status with: ${CYAN}systemctl status $SERVICE_NAME${NC}"
        echo -e "You can view logs with: ${CYAN}journalctl -u $SERVICE_NAME${NC}"
    else
        echo -e "${RED}Service installation failed.${NC}"
        echo -e "Check the status with: ${CYAN}systemctl status $SERVICE_NAME${NC}"
    fi
    
    wait_for_key
}

# ========================
# Menu Functions
# ========================

show_header() {
    clear
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}             PANGOLIN STACK MONITORING SYSTEM v${VERSION}${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo ""
}

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
        echo "8. Configuration"
        echo "9. Generate Security Report"
        echo "0. Exit"
        echo ""
        read -p "Enter your choice [0-9]: " choice
        
        case $choice in
            1) run_health_check; wait_for_key ;;
            2) start_monitoring_foreground ;;
            3) install_systemd_service ;;
            4) display_container_status ;;
            5) display_system_resources ;;
            6) check_ssh_attempts ;;
            7) analyze_traefik_logs ;;
            8) configuration_menu ;;
            9) generate_security_report; echo -e "${GREEN}Report generated and sent to Discord${NC}"; wait_for_key ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; wait_for_key ;;
        esac
    done
}

configuration_menu() {
    while true; do
        show_header
        echo "Configuration Menu:"
        echo "1. View Current Configuration"
        echo "2. Edit Configuration File"
        echo "3. Configure Discord Webhook"
        echo "4. Configure Monitoring Thresholds"
        echo "5. Configure Containers to Monitor"
        echo "6. Configure Notification Settings"
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
            6) configure_notification_settings ;;
            7) save_default_config; echo -e "${GREEN}Configuration reset to defaults${NC}"; wait_for_key ;;
            8) toggle_debug_mode ;;
            0) return ;;
            *) echo -e "${RED}Invalid option${NC}"; wait_for_key ;;
        esac
    done
}

# Configuration editing functions
edit_configuration() {
    if command -v nano >/dev/null 2>&1; then
        nano "$CONFIG_FILE"
    elif command -v vim >/dev/null 2>&1; then
        vim "$CONFIG_FILE"
    else
        echo -e "${RED}No text editor (nano/vim) found.${NC}"
        wait_for_key
        return 1
    fi
    
    # Reload config after editing
    load_config
    echo -e "${GREEN}Configuration updated and reloaded.${NC}"
    wait_for_key
}

configure_discord_webhook() {
    show_header
    echo -e "${CYAN}=== Discord Webhook Configuration ===${NC}"
    echo -e "Current webhook: ${YELLOW}${DISCORD_WEBHOOK:-None}${NC}"
    echo ""
    echo -e "${YELLOW}Enter your Discord webhook URL:${NC}"
    read -r new_webhook
    
    if [[ -z "$new_webhook" ]]; then
        echo -e "${RED}Webhook cannot be empty.${NC}"
        wait_for_key
        return 1
    fi
    
    if ! validate_discord_webhook "$new_webhook"; then
        echo -e "${RED}Invalid webhook URL format.${NC}"
        wait_for_key
        return 1
    fi
    
    # Update config file
    sed -i "s|DISCORD_WEBHOOK=.*|DISCORD_WEBHOOK=\"$new_webhook\"|" "$CONFIG_FILE"
    
    # Reload config
    load_config
    
    # Test webhook
    echo -e "${YELLOW}Testing webhook...${NC}"
    if send_discord_message "Test Message" "Pangolin Monitor webhook test completed successfully." "success"; then
        echo -e "${GREEN}Webhook configured and tested successfully.${NC}"
    else
        echo -e "${RED}Webhook test failed. Please check the URL and try again.${NC}"
    fi
    
    wait_for_key
}

configure_thresholds() {
    show_header
    echo -e "${CYAN}=== Threshold Configuration ===${NC}"
    echo -e "Current thresholds:"
    echo -e "  CPU:    Warning: ${YELLOW}${CPU_WARNING_THRESHOLD}%${NC}, Critical: ${RED}${CPU_CRITICAL_THRESHOLD}%${NC}"
    echo -e "  Memory: Warning: ${YELLOW}${MEM_WARNING_THRESHOLD}%${NC}, Critical: ${RED}${MEM_CRITICAL_THRESHOLD}%${NC}"
    echo -e "  Disk:   Warning: ${YELLOW}${DISK_WARNING_THRESHOLD}%${NC}, Critical: ${RED}${DISK_CRITICAL_THRESHOLD}%${NC}"
    echo -e "  Network: Attack threshold: ${RED}${NETWORK_THRESHOLD}${NC} packets/second"
    echo ""
    
    # Update CPU thresholds
    echo -e "Enter new CPU warning threshold (${CPU_WARNING_THRESHOLD}%):"
    read -r new_cpu_warning
    if [[ -n "$new_cpu_warning" && "$new_cpu_warning" =~ ^[0-9]+$ ]]; then
        sed -i "s/CPU_WARNING_THRESHOLD=.*/CPU_WARNING_THRESHOLD=$new_cpu_warning/" "$CONFIG_FILE"
    fi
    
    echo -e "Enter new CPU critical threshold (${CPU_CRITICAL_THRESHOLD}%):"
    read -r new_cpu_critical
    if [[ -n "$new_cpu_critical" && "$new_cpu_critical" =~ ^[0-9]+$ ]]; then
        sed -i "s/CPU_CRITICAL_THRESHOLD=.*/CPU_CRITICAL_THRESHOLD=$new_cpu_critical/" "$CONFIG_FILE"
    fi
    
    # Update Memory thresholds
    echo -e "Enter new Memory warning threshold (${MEM_WARNING_THRESHOLD}%):"
    read -r new_mem_warning
    if [[ -n "$new_mem_warning" && "$new_mem_warning" =~ ^[0-9]+$ ]]; then
        sed -i "s/MEM_WARNING_THRESHOLD=.*/MEM_WARNING_THRESHOLD=$new_mem_warning/" "$CONFIG_FILE"
    fi
    
    echo -e "Enter new Memory critical threshold (${MEM_CRITICAL_THRESHOLD}%):"
    read -r new_mem_critical
    if [[ -n "$new_mem_critical" && "$new_mem_critical" =~ ^[0-9]+$ ]]; then
        sed -i "s/MEM_CRITICAL_THRESHOLD=.*/MEM_CRITICAL_THRESHOLD=$new_mem_critical/" "$CONFIG_FILE"
    fi
    
    # Update Disk thresholds
    echo -e "Enter new Disk warning threshold (${DISK_WARNING_THRESHOLD}%):"
    read -r new_disk_warning
    if [[ -n "$new_disk_warning" && "$new_disk_warning" =~ ^[0-9]+$ ]]; then
        sed -i "s/DISK_WARNING_THRESHOLD=.*/DISK_WARNING_THRESHOLD=$new_disk_warning/" "$CONFIG_FILE"
    fi
    
    echo -e "Enter new Disk critical threshold (${DISK_CRITICAL_THRESHOLD}%):"
    read -r new_disk_critical
    if [[ -n "$new_disk_critical" && "$new_disk_critical" =~ ^[0-9]+$ ]]; then
        sed -i "s/DISK_CRITICAL_THRESHOLD=.*/DISK_CRITICAL_THRESHOLD=$new_disk_critical/" "$CONFIG_FILE"
    fi
    
    # Update Network threshold
    echo -e "Enter new Network attack threshold (${NETWORK_THRESHOLD} packets/sec):"
    read -r new_network_threshold
    if [[ -n "$new_network_threshold" && "$new_network_threshold" =~ ^[0-9]+$ ]]; then
        sed -i "s/NETWORK_THRESHOLD=.*/NETWORK_THRESHOLD=$new_network_threshold/" "$CONFIG_FILE"
    fi
    
    # Reload config
    load_config
    
    echo -e "${GREEN}Thresholds updated successfully.${NC}"
    wait_for_key
}

configure_containers() {
    show_header
    echo -e "${CYAN}=== Container Configuration ===${NC}"
    echo -e "Current monitored containers: ${YELLOW}${CONTAINER_NAMES[*]}${NC}"
    echo ""
    
    # Get available containers
    echo -e "${CYAN}Available Docker containers:${NC}"
    local available_containers=()
    if command -v docker >/dev/null 2>&1; then
        available_containers=($(docker ps --format '{{.Names}}'))
        for i in "${!available_containers[@]}"; do
            local status=$(docker inspect --format='{{.State.Status}}' "${available_containers[$i]}" 2>/dev/null)
            local container="${available_containers[$i]}"
            if [[ " ${CONTAINER_NAMES[*]} " == *" $container "* ]]; then
                echo -e "  ${GREEN}[$i] $container ($status) [MONITORED]${NC}"
            else
                echo -e "  ${YELLOW}[$i] $container ($status)${NC}"
            fi
        done
    else
        echo -e "${RED}Docker not installed or not running.${NC}"
    fi
    
    echo ""
    echo "Options:"
    echo "1. Add a container to monitoring"
    echo "2. Remove a container from monitoring"
    echo "3. Set list of containers manually"
    echo "0. Back"
    echo ""
    read -p "Enter your choice [0-3]: " choice
    
    case $choice in
        1)
            if [[ ${#available_containers[@]} -eq 0 ]]; then
                echo -e "${RED}No containers available.${NC}"
                wait_for_key
                return
            fi
            
            read -p "Enter container number to add: " container_idx
            if [[ "$container_idx" =~ ^[0-9]+$ && $container_idx -lt ${#available_containers[@]} ]]; then
                local new_container="${available_containers[$container_idx]}"
                if [[ " ${CONTAINER_NAMES[*]} " != *" $new_container "* ]]; then
                    CONTAINER_NAMES+=("$new_container")
                    # Update config file
                    sed -i "s/CONTAINER_NAMES=.*/CONTAINER_NAMES=(${CONTAINER_NAMES[*]})/" "$CONFIG_FILE"
                    echo -e "${GREEN}Added $new_container to monitoring.${NC}"
                else
                    echo -e "${YELLOW}Container $new_container is already being monitored.${NC}"
                fi
            else
                echo -e "${RED}Invalid container number.${NC}"
            fi
            ;;
        2)
            if [[ ${#CONTAINER_NAMES[@]} -eq 0 ]]; then
                echo -e "${RED}No containers being monitored.${NC}"
                wait_for_key
                return
            fi
            
            echo -e "Select container to remove from monitoring:"
            for i in "${!CONTAINER_NAMES[@]}"; do
                echo -e "  ${YELLOW}[$i] ${CONTAINER_NAMES[$i]}${NC}"
            done
            
            read -p "Enter container number to remove: " container_idx
            if [[ "$container_idx" =~ ^[0-9]+$ && $container_idx -lt ${#CONTAINER_NAMES[@]} ]]; then
                local container_to_remove="${CONTAINER_NAMES[$container_idx]}"
                CONTAINER_NAMES=("${CONTAINER_NAMES[@]:0:$container_idx}" "${CONTAINER_NAMES[@]:$((container_idx+1))}")
                # Update config file
                sed -i "s/CONTAINER_NAMES=.*/CONTAINER_NAMES=(${CONTAINER_NAMES[*]})/" "$CONFIG_FILE"
                echo -e "${GREEN}Removed $container_to_remove from monitoring.${NC}"
            else
                echo -e "${RED}Invalid container number.${NC}"
            fi
            ;;
        3)
            echo -e "Enter container names, separated by spaces:"
            read -r new_containers
            read -a CONTAINER_NAMES <<< "$new_containers"
            # Update config file
            sed -i "s/CONTAINER_NAMES=.*/CONTAINER_NAMES=(${CONTAINER_NAMES[*]})/" "$CONFIG_FILE"
            echo -e "${GREEN}Container list updated.${NC}"
            ;;
        0) return ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    # Reload config
    load_config
    
    wait_for_key
}

configure_notification_settings() {
    show_header
    echo -e "${CYAN}=== Notification Settings ===${NC}"
    echo -e "Current settings:"
    echo -e "  SSH Notifications:     ${SSH_NOTIFY}"
    echo -e "  Log Notifications:     ${LOG_NOTIFY}"
    echo -e "  Attack Notifications:  ${ATTACK_NOTIFY}"
    echo -e "  Check Interval:        ${CHECK_INTERVAL} seconds"
    echo -e "  Report Interval:       ${REPORT_INTERVAL} seconds ($(( REPORT_INTERVAL / 3600 )) hours)"
    echo ""
    
    echo "Options:"
    echo "1. Toggle SSH Notifications"
    echo "2. Toggle Log Notifications"
    echo "3. Toggle Attack Notifications"
    echo "4. Change Check Interval"
    echo "5. Change Report Interval"
    echo "0. Back"
    echo ""
    read -p "Enter your choice [0-5]: " choice
    
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
                echo -e "${YELLOW}Log notifications disabled.${NC}"
            else
                sed -i "s/LOG_NOTIFY=.*/LOG_NOTIFY=true/" "$CONFIG_FILE"
                echo -e "${GREEN}Log notifications enabled.${NC}"
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
        4)
            echo -e "Enter new check interval in seconds (current: ${CHECK_INTERVAL}):"
            read -r new_interval
            if [[ -n "$new_interval" && "$new_interval" =~ ^[0-9]+$ && $new_interval -ge 10 ]]; then
                sed -i "s/CHECK_INTERVAL=.*/CHECK_INTERVAL=$new_interval/" "$CONFIG_FILE"
                echo -e "${GREEN}Check interval updated to $new_interval seconds.${NC}"
            else
                echo -e "${RED}Invalid interval. Must be a number >= 10.${NC}"
            fi
            ;;
        5)
            echo -e "Enter new report interval in hours (current: $(( REPORT_INTERVAL / 3600 ))):"
            read -r new_hours
            if [[ -n "$new_hours" && "$new_hours" =~ ^[0-9]+$ && $new_hours -ge 1 ]]; then
                local new_interval=$(( new_hours * 3600 ))
                sed -i "s/REPORT_INTERVAL=.*/REPORT_INTERVAL=$new_interval/" "$CONFIG_FILE"
                echo -e "${GREEN}Report interval updated to $new_hours hours.${NC}"
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

toggle_debug_mode() {
    show_header
    echo -e "${CYAN}=== Debug Mode ===${NC}"
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${YELLOW}Debug mode is currently ${GREEN}ENABLED${NC}"
        echo -e "This will produce more verbose logs in ${LOG_FILE}"
        
        echo -e "${YELLOW}Would you like to disable debug mode? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            sed -i "s/DEBUG=.*/DEBUG=false/" "$CONFIG_FILE"
            echo -e "${GREEN}Debug mode disabled.${NC}"
        fi
    else
        echo -e "${YELLOW}Debug mode is currently ${RED}DISABLED${NC}"
        echo -e "Enabling debug mode will produce more verbose logs in ${LOG_FILE}"
        
        echo -e "${YELLOW}Would you like to enable debug mode? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            sed -i "s/DEBUG=.*/DEBUG=true/" "$CONFIG_FILE"
            echo -e "${GREEN}Debug mode enabled.${NC}"
        fi
    fi
    
    # Reload config
    load_config
    
    wait_for_key
}

# ========================
# Dependency Management
# ========================

check_dependencies() {
    log_message "INFO" "Checking dependencies..."
    local missing=()
    
    # Essential dependencies
    for dep in jq bc curl docker; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
            log_message "WARNING" "$dep not found"
        fi
    done
    
    # Optional dependencies with fallbacks
    if ! command -v column >/dev/null 2>&1; then
        log_message "WARNING" "column not found, some formatting will be limited"
    fi
    
    # Handle missing dependencies
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_message "ERROR" "Missing dependencies: ${missing[*]}"
        
        echo -e "${RED}Missing required dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}Would you like to attempt to install them? (y/n)${NC}"
        read -r install_deps
        
        if [[ "$install_deps" =~ ^[Yy]$ ]]; then
            install_dependencies
        else
            echo -e "${RED}Missing dependencies may cause issues with monitoring.${NC}"
            wait_for_key
            return 1
        fi
    fi
    
    # Check for discord.sh
    check_discord_script
    
    log_message "INFO" "All required dependencies present"
    return 0
}

# Install missing dependencies
install_dependencies() {
    log_message "INFO" "Installing missing dependencies..."
    
    # Check for root privileges
    if [[ "$EUID" -ne 0 ]]; then
        log_message "ERROR" "Root privileges required to install dependencies"
        echo -e "${RED}Error: Root privileges required to install dependencies${NC}"
        echo "Please run with sudo"
        return 1
    fi
    
    # Detect package manager and install dependencies
    local package_manager=""
    local packages=("jq" "bc" "curl")
    
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
        echo "Please install jq, bc, and curl manually."
        return 1
    fi
    
    echo -e "${YELLOW}Installing dependencies using $package_manager...${NC}"
    
    case "$package_manager" in
        apt-get)
            apt-get update
            apt-get install -y "${packages[@]}"
            ;;
        yum)
            yum install -y "${packages[@]}"
            ;;
        dnf)
            dnf install -y "${packages[@]}"
            ;;
        apk)
            apk add --no-cache "${packages[@]}"
            ;;
    esac
    
    if [[ $? -ne 0 ]]; then
        log_message "ERROR" "Failed to install dependencies"
        echo -e "${RED}Error: Failed to install dependencies.${NC}"
        return 1
    fi
    
    log_message "INFO" "Dependencies installed successfully"
    echo -e "${GREEN}Dependencies installed successfully.${NC}"
    return 0
}

# ========================
# Main Script Execution
# ========================

main() {
    # Process command line arguments
    case "$1" in
        --service)
            # Running in service mode
            load_config
            start_service_mode
            exit 0
            ;;
        --check)
            # Just run a health check and exit
            load_config
            run_health_check
            exit $?
            ;;
        --report)
            # Generate a report and exit
            load_config
            generate_security_report
            exit 0
            ;;
        --install-service)
            # Install as systemd service
            load_config
            install_systemd_service
            exit $?
            ;;
        --help|-h)
            echo "Pangolin Stack Monitoring System v${VERSION}"
            echo ""
            echo "Usage: $(basename "$0") [options]"
            echo ""
            echo "Options:"
            echo "  --help, -h       Show this help message"
            echo "  --service        Run in service mode (for systemd)"
            echo "  --check          Run a single health check and exit"
            echo "  --report         Generate a security report and exit"
            echo "  --install-service Install as systemd service"
            echo "  --version, -v    Display version information"
            echo ""
            echo "Without options, the script runs in interactive menu mode."
            exit 0
            ;;
        --version|-v)
            echo "Pangolin Stack Monitoring System v${VERSION}"
            exit 0
            ;;
    esac

    # Load configuration
    load_config

    # Check dependencies
    check_dependencies

    # Start main menu
    main_menu
}

# Call main function
main "$@"
