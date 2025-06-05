#!/bin/bash

# Description:
# This script monitors Docker containers on the system.
# It checks container status, resource usage (CPU, Memory, Disk, Network),
# checks for image updates, checks container logs for errors/warnings,
# and monitors container restarts.
# Output is printed to the standard output with improved formatting and colors and logged to a file.
#
# Configuration:
#   Configuration is primarily done via config.sh and environment variables.
#   Environment variables override settings in config.sh.
#   Script defaults are used if no other configuration is found.
#
# Environment Variables (can be set to customize script behavior):
#   - LOG_LINES_TO_CHECK: Number of log lines to check.
#   - CHECK_FREQUENCY_MINUTES: Frequency of checks in minutes (Note: Script is run by external scheduler).
#   - LOG_FILE: Path to the log file.
#   - CONTAINER_NAMES: Comma-separated list of container names to monitor. Overrides config.sh.
#   - CPU_WARNING_THRESHOLD: CPU usage percentage threshold for warnings.
#   - MEMORY_WARNING_THRESHOLD: Memory usage percentage threshold for warnings.
#   - DISK_SPACE_THRESHOLD: Disk space usage percentage threshold for warnings (for container mounts).
#   - NETWORK_ERROR_THRESHOLD: Network error/drop count threshold for warnings.
#
# Usage:
#   ./docker-container-monitor.sh                           - Monitor based on config (or all running)
#   ./docker-container-monitor.sh <container1> <container2> ... - Monitor specific containers
#   ./docker-container-monitor.sh logs                      - Show logs for all running containers
#   ./docker-container-monitor.sh logs <container_name>     - Show logs for a specific container
#   ./docker-container-monitor.sh logs errors <container_name> - Show errors in logs for a specific container
#   ./docker-container-monitor.sh save logs <container_name> - Save logs for a specific container to a file
#
# Prerequisites:
#   - Docker
#   - jq (for processing JSON output from docker inspect and docker stats)
#   - skopeo (for checking for container image updates)
#   - bc or awk (awk is used in this script for float comparisons to reduce dependencies)
#   - timeout (from coreutils, for docker exec commands)

# --- ANSI Color Codes ---
COLOR_RESET="\033[0m"
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_CYAN="\033[0;36m"
COLOR_MAGENTA="\033[0;35m" # Magenta for Summary

# --- Script Default Configuration Values ---
_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK=20
_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES=360
_SCRIPT_DEFAULT_LOG_FILE="$(cd "$(dirname "$0")" && pwd)/docker-monitor.log"
_SCRIPT_DEFAULT_CPU_WARNING_THRESHOLD=80      # Percentage
_SCRIPT_DEFAULT_MEMORY_WARNING_THRESHOLD=80   # Percentage
_SCRIPT_DEFAULT_DISK_SPACE_THRESHOLD=80       # Percentage
_SCRIPT_DEFAULT_NETWORK_ERROR_THRESHOLD=10    # Number of errors/drops
declare -a _SCRIPT_DEFAULT_CONTAINER_NAMES_ARRAY=()

# Initialize working configuration variables from script defaults
LOG_LINES_TO_CHECK="$_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK"
CHECK_FREQUENCY_MINUTES="$_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES"
LOG_FILE="$_SCRIPT_DEFAULT_LOG_FILE"
CPU_WARNING_THRESHOLD="$_SCRIPT_DEFAULT_CPU_WARNING_THRESHOLD"
MEMORY_WARNING_THRESHOLD="$_SCRIPT_DEFAULT_MEMORY_WARNING_THRESHOLD"
DISK_SPACE_THRESHOLD="$_SCRIPT_DEFAULT_DISK_SPACE_THRESHOLD"
NETWORK_ERROR_THRESHOLD="$_SCRIPT_DEFAULT_NETWORK_ERROR_THRESHOLD"
declare -a CONTAINER_NAMES_FROM_CONFIG_FILE=()

# --- Source Configuration File (config.sh) ---
# config.sh is expected to define VARNAME_DEFAULT variables.
_CONFIG_FILE_PATH="$(cd "$(dirname "$0")" && pwd)/config.sh"
if [ -f "$_CONFIG_FILE_PATH" ]; then
  source "$_CONFIG_FILE_PATH" # This should define LOG_LINES_TO_CHECK_DEFAULT, etc.

  LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK_DEFAULT:-$LOG_LINES_TO_CHECK}"
  CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES_DEFAULT:-$CHECK_FREQUENCY_MINUTES}"
  LOG_FILE="${LOG_FILE_DEFAULT:-$LOG_FILE}"
  CPU_WARNING_THRESHOLD="${CPU_WARNING_THRESHOLD_DEFAULT:-$CPU_WARNING_THRESHOLD}"
  MEMORY_WARNING_THRESHOLD="${MEMORY_WARNING_THRESHOLD_DEFAULT:-$MEMORY_WARNING_THRESHOLD}"
  DISK_SPACE_THRESHOLD="${DISK_SPACE_THRESHOLD_DEFAULT:-$DISK_SPACE_THRESHOLD}"
  NETWORK_ERROR_THRESHOLD="${NETWORK_ERROR_THRESHOLD_DEFAULT:-$NETWORK_ERROR_THRESHOLD}"

  if declare -p CONTAINER_NAMES_DEFAULT &>/dev/null && [[ "$(declare -p CONTAINER_NAMES_DEFAULT)" == "declare -a"* ]]; then
    if [ ${#CONTAINER_NAMES_DEFAULT[@]} -gt 0 ]; then
        CONTAINER_NAMES_FROM_CONFIG_FILE=("${CONTAINER_NAMES_DEFAULT[@]}")
    fi
  fi
else
  # Using echo here as print_message might not be defined yet if this structure was changed.
  echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} Configuration file '$_CONFIG_FILE_PATH' not found. Using script defaults or environment variables."
fi

# --- Override with Environment Variables (highest precedence for these settings) ---
LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK:-$LOG_LINES_TO_CHECK}"
CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES:-$CHECK_FREQUENCY_MINUTES}"
LOG_FILE="${LOG_FILE:-$LOG_FILE}"
CPU_WARNING_THRESHOLD="${CPU_WARNING_THRESHOLD:-$CPU_WARNING_THRESHOLD}"
MEMORY_WARNING_THRESHOLD="${MEMORY_WARNING_THRESHOLD:-$MEMORY_WARNING_THRESHOLD}"
DISK_SPACE_THRESHOLD="${DISK_SPACE_THRESHOLD:-$DISK_SPACE_THRESHOLD}"
NETWORK_ERROR_THRESHOLD="${NETWORK_ERROR_THRESHOLD:-$NETWORK_ERROR_THRESHOLD}"
# CONTAINER_NAMES (env var, comma-separated string) is processed later in main execution.

# --- Prerequisite Checks ---
if ! command -v docker >/dev/null 2>&1; then
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} Docker command not found. Please install Docker." >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} jq command not found. Please install jq." >&2
    exit 1
fi
if ! command -v awk >/dev/null 2>&1; then # awk is used for float comparisons
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} awk command not found. Please install awk (usually part of gawk or mawk)." >&2
    exit 1
fi
if ! command -v timeout >/dev/null 2>&1; then # timeout is used for docker exec
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} timeout command not found. Please install coreutils." >&2
    exit 1
fi
# Skopeo is checked within check_for_updates as it's specific to that function.

# --- Validate Configuration Values ---
if ! [[ "$LOG_LINES_TO_CHECK" =~ ^[0-9]+$ ]] || [ "$LOG_LINES_TO_CHECK" -le 0 ]; then
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} Invalid LOG_LINES_TO_CHECK value ('$LOG_LINES_TO_CHECK'). Using script default: $_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK." >&2
    LOG_LINES_TO_CHECK="$_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK"
fi
# Add similar validation for other numeric threshold variables if desired. For brevity, omitted here but recommended.

# --- Functions ---

print_message() {
  local message="$1"
  local color_type="$2"
  local color_code=""
  local log_output_no_color=""

  case "$color_type" in
    "INFO") color_code="$COLOR_CYAN";;
    "GOOD") color_code="$COLOR_GREEN";;
    "WARNING") color_code="$COLOR_YELLOW";;
    "DANGER") color_code="$COLOR_RED";;
    "SUMMARY") color_code="$COLOR_MAGENTA";;
    *) color_code="$COLOR_RESET"; color_type="NONE";;
  esac

  if [ "$color_type" = "NONE" ]; then
    echo -e "${message}"
    log_output_no_color="${message}"
  else
    local colored_message="${color_code}[${color_type}]${COLOR_RESET} ${message}"
    echo -e "${colored_message}"
    log_output_no_color="[${color_type}] ${message}"
  fi

  if [ -n "$LOG_FILE" ]; then
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir" &>/dev/null
    fi
    if touch "$LOG_FILE" &>/dev/null; then # Check writability and existence
        echo "$(date '+%Y-%m-%d %H:%M:%S') ${log_output_no_color}" >> "$LOG_FILE"
    else
        # Avoid recursive calls to print_message if LOG_FILE itself is the problem
        echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Cannot write to LOG_FILE ('$LOG_FILE'). Logging to file disabled for this message." >&2
    fi
  fi
}

check_container_status() {
  local container_name="$1"
  local inspect_data="$2"
  # CPU and Mem percentages are now handled by check_resource_usage, but kept for context in status messages
  local cpu_for_status_msg="$3" 
  local mem_for_status_msg="$4"
  local status health_status detailed_health

  status=$(jq -r '.[0].State.Status' <<< "$inspect_data")
  health_status="not configured"
  if jq -e '.[0].State.Health != null and .[0].State.Health.Status != null' <<< "$inspect_data" >/dev/null 2>&1; then
    health_status=$(jq -r '.[0].State.Health.Status' <<< "$inspect_data")
  fi

  if [ "$status" != "running" ]; then
    print_message "  Status: Not running (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "DANGER"
    return 1
  else
    if [ "$health_status" = "healthy" ]; then
      print_message "  Status: Running and healthy (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "GOOD"
      return 0
    elif [ "$health_status" = "unhealthy" ]; then
      print_message "  Status: Running but UNHEALTHY (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "DANGER"
      detailed_health=$(jq -r '.[0].State.Health | tojson' <<< "$inspect_data")
      if [ -n "$detailed_health" ] && [ "$detailed_health" != "null" ]; then
        print_message "    Detailed Health Info: $detailed_health" "WARNING"
      fi
      return 1
    elif [ "$health_status" = "not configured" ]; then
      print_message "  Status: Running (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "GOOD"
      return 0
    else
      print_message "  Status: Running (Status: $status, Health: $health_status, CPU: $cpu_for_status_msg, Mem: $mem_for_status_msg)" "WARNING"
      return 1
    fi
  fi
}

check_container_restarts() {
  local container_name="$1"
  local inspect_data="$2"
  local restart_count is_restarting

  restart_count=$(jq -r '.[0].RestartCount' <<< "$inspect_data")
  is_restarting=$(jq -r '.[0].State.Restarting' <<< "$inspect_data")

  if [ "$is_restarting" = "true" ]; then
    print_message "  Restart Status: Container '$container_name' is currently restarting." "WARNING"
    return 1
  elif [ "$restart_count" -gt 0 ]; then
    print_message "  Restart Status: Container '$container_name' has restarted $restart_count times." "WARNING"
    return 1
  else
    print_message "  Restart Status: No unexpected restarts detected for '$container_name'." "GOOD"
    return 0
  fi
}

check_resource_usage() {
  local container_name="$1" # For messages, if needed
  local cpu_percent="$2"    # Already extracted, % removed
  local mem_percent="$3"    # Already extracted, % removed
  local issues_found=0

  # Check CPU usage
  if [[ "$cpu_percent" =~ ^[0-9.]+$ ]]; then
    if awk -v cpu="$cpu_percent" -v threshold="$CPU_WARNING_THRESHOLD" 'BEGIN {exit !(cpu > threshold)}'; then
      print_message "  CPU Usage: High CPU usage detected (${cpu_percent}% > ${CPU_WARNING_THRESHOLD}% threshold)" "WARNING"
      issues_found=1
    else
      print_message "  CPU Usage: Normal (${cpu_percent}%)" "INFO"
    fi
  else
    print_message "  CPU Usage: Could not determine CPU usage (value: ${cpu_percent})" "WARNING"
    issues_found=1 # Consider indeterminate usage an issue
  fi

  # Check Memory usage
  if [[ "$mem_percent" =~ ^[0-9.]+$ ]]; then
    if awk -v mem="$mem_percent" -v threshold="$MEMORY_WARNING_THRESHOLD" 'BEGIN {exit !(mem > threshold)}'; then
      print_message "  Memory Usage: High memory usage detected (${mem_percent}% > ${MEMORY_WARNING_THRESHOLD}% threshold)" "WARNING"
      issues_found=1
    else
      print_message "  Memory Usage: Normal (${mem_percent}%)" "INFO"
    fi
  else
    print_message "  Memory Usage: Could not determine memory usage (value: ${mem_percent})" "WARNING"
    issues_found=1 # Consider indeterminate usage an issue
  fi

  return $issues_found
}

check_disk_space() {
  local container_name="$1"
  local inspect_data="$2"
  local issues_found=0
  local i mp_destination mp_type disk_usage # loop variables
  local num_mounts
  local mount_processed_for_df_check=false # Flag to see if any mount was actually df-checked

  num_mounts=$(jq -r '.[0].Mounts | length // 0' <<< "$inspect_data" 2>/dev/null)

  if ! [[ "$num_mounts" =~ ^[0-9]+$ ]] || [ "$num_mounts" -eq 0 ]; then
    print_message "  Disk Space: No mounted volumes found for '$container_name' or error parsing mounts." "INFO"
    return 0
  fi

  for ((i=0; i<num_mounts; i++)); do
    mp_destination=$(jq -r ".[0].Mounts[$i].Destination // empty" <<< "$inspect_data" 2>/dev/null)
    mp_type=$(jq -r ".[0].Mounts[$i].Type // empty" <<< "$inspect_data" 2>/dev/null)

    if [ -z "$mp_destination" ]; then
        continue
    fi

    # --- Enhanced Filter for special/virtual paths ---
    # Add more patterns here if needed for your specific environment
    if [[ "$mp_destination" == *".sock" ]] || \
       [[ "$mp_destination" == "/proc" ]] || [[ "$mp_destination" == "/proc/"* ]] || \
       [[ "$mp_destination" == "/sys" ]]  || [[ "$mp_destination" == "/sys/"* ]] || \
       [[ "$mp_destination" == "/dev" ]]  || [[ "$mp_destination" == "/dev/"* ]] || \
       [[ "$mp_destination" == "/host/proc" ]] || [[ "$mp_destination" == "/host/proc/"* ]] || \
       [[ "$mp_destination" == "/host/sys" ]]  || [[ "$mp_destination" == "/host/sys/"* ]] ; then
      print_message "  Disk Space: Skipping disk usage percentage check for special/virtual path '$mp_destination' (Type: '$mp_type') in '$container_name'." "INFO"
      continue # Skip to the next mount
    fi
    
    mount_processed_for_df_check=true # Mark that we are attempting a df check for this mount

    disk_usage=$(timeout 5 docker exec "$container_name" df -P "$mp_destination" 2>/dev/null | awk 'NR==2 {val=$(NF-1); sub(/%$/,"",val); print val}')
    
    if ! [[ "$disk_usage" =~ ^[0-9]+$ ]]; then
      print_message "  Disk Space: Could not accurately check usage for '$mp_destination' in '$container_name' (Type: '$mp_type', Raw DF Value: '$disk_usage')." "WARNING"
      issues_found=1
      continue
    fi

    if [ "$disk_usage" -ge "$DISK_SPACE_THRESHOLD" ]; then
      print_message "  Disk Space: High usage ($disk_usage%) at '$mp_destination' in '$container_name' (Threshold: $DISK_SPACE_THRESHOLD%)" "WARNING"
      issues_found=1
    else
      print_message "  Disk Space: Normal usage ($disk_usage%) at '$mp_destination' in '$container_name'." "INFO"
    fi
  done

  if ! $mount_processed_for_df_check && [ "$num_mounts" -gt 0 ]; then
      print_message "  Disk Space: No mounts deemed suitable for percentage-based usage check in '$container_name' (out of $num_mounts total mounts)." "INFO"
  fi

  return $issues_found
}

check_network() {
  local container_name="$1"
  local issues_found=0
  local network_stats line interface errors packets error_rate # loop variables
  local data_part # For parsing /proc/net/dev line
  # Variables for fields from /proc/net/dev
  local _r_bytes _r_packets _r_errs _r_drop _r_fifo _r_frame _r_compressed _r_multicast
  local _t_bytes _t_packets _t_errs _t_drop _t_fifo _t_colls _t_carrier _t_compressed

  network_stats=$(timeout 5 docker exec "$container_name" cat /proc/net/dev 2>/dev/null)

  if [ -z "$network_stats" ]; then
    print_message "  Network: Could not retrieve network statistics for '$container_name'." "WARNING"
    return 1
  fi

  local network_issue_reported_for_container=false
  while IFS= read -r line; do
    if [[ "$line" == *:* ]]; then
      interface=$(echo "$line" | awk -F ':' '{print $1}' | sed 's/^[ \t]*//;s/[ \t]*$//')
      data_part=$(echo "$line" | cut -d':' -f2-)
      
      # Use 'read' to parse the fields robustly
      read -r _r_bytes _r_packets _r_errs _r_drop _r_fifo _r_frame _r_compressed _r_multicast \
                _t_bytes _t_packets _t_errs _t_drop _t_fifo _t_colls _t_carrier _t_compressed <<< "$data_part"
      
      # Check if fields are numeric; if not, skip this interface line (might be malformed)
      if ! [[ "$_r_errs" =~ ^[0-9]+$ && "$_t_drop" =~ ^[0-9]+$ && \
              "$_r_packets" =~ ^[0-9]+$ && "$_t_packets" =~ ^[0-9]+$ ]]; then
          print_message "  Network: Malformed stats line for interface '$interface' in '$container_name'. Skipping." "INFO"
          continue
      fi

      errors=$((_r_errs + _t_drop))
      packets=$((_r_packets + _t_packets))

      if [ "$errors" -gt "$NETWORK_ERROR_THRESHOLD" ]; then
        print_message "  Network: Interface '$interface' in '$container_name' has $errors errors/drops (Threshold: $NETWORK_ERROR_THRESHOLD)." "WARNING"
        issues_found=1
        network_issue_reported_for_container=true
      fi

      if [ "$packets" -gt 0 ] && [ "$errors" -gt 0 ]; then
        error_rate=$(awk -v err="$errors" -v pkt="$packets" 'BEGIN {if (pkt > 0) printf "%.2f", (err * 100 / pkt); else print "0.00"}')
        if awk -v rate="$error_rate" -v threshold="1.0" 'BEGIN {exit !(rate > threshold)}'; then # Example: 1.0% error rate threshold
          print_message "  Network: Interface '$interface' in '$container_name' has high error rate ($error_rate%)." "WARNING"
          issues_found=1
          network_issue_reported_for_container=true
        fi
      fi
    fi
  done <<< "$(tail -n +3 <<< "$network_stats")" # Skip first two header lines

  if [ $issues_found -eq 0 ] && ! $network_issue_reported_for_container ; then # Only print "no issues" if none were warned about
      print_message "  Network: No significant network issues detected for '$container_name'." "INFO"
  fi
  return $issues_found
}

check_for_updates() {
    local container_name="$1"
    local current_image_ref="$2"
    local registry_host image_path_for_skopeo tag image_name_no_tag first_part skopeo_image_ref
    local search_pattern_in_repodigests local_digest_line local_digest skopeo_output skopeo_exit_code remote_digest

    tag="latest"

    if [[ "$current_image_ref" == *@sha256:* ]]; then
        print_message "  Update Check: Container '$container_name' is running image pinned by digest ($current_image_ref). Skipping tag-based update check." "INFO"
        return 0
    fi
    if [[ "$current_image_ref" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; then
        print_message "  Update Check: Container '$container_name' is running image by ID ($current_image_ref). Cannot determine registry." "INFO"
        return 0
    fi

    image_name_no_tag="$current_image_ref"
    if [[ "$current_image_ref" == *":"* ]]; then
        if [[ "${current_image_ref##*:}" =~ ^[0-9a-fA-F]{7,}$ && "${current_image_ref}" == *@* ]]; then
            print_message "  Update Check: Image ref '$current_image_ref' for '$container_name' appears digest-pinned. Skipping tag-based update check." "INFO"
            return 0
        fi
        tag="${current_image_ref##*:}"
        image_name_no_tag="${current_image_ref%:*}"
    fi

    if [[ "$image_name_no_tag" == *"/"* ]]; then
        first_part=$(echo "$image_name_no_tag" | cut -d'/' -f1)
        if [[ "$first_part" == *"."* ]] || [[ "$first_part" == "localhost" ]] || [[ "$first_part" == *":"* ]]; then
            registry_host="$first_part"
            image_path_for_skopeo=$(echo "$image_name_no_tag" | cut -d'/' -f2-)
        else
            registry_host="registry-1.docker.io"
            image_path_for_skopeo="$image_name_no_tag"
        fi
    else
        registry_host="registry-1.docker.io"
        image_path_for_skopeo="library/$image_name_no_tag"
    fi

    skopeo_image_ref="docker://$registry_host/$image_path_for_skopeo:$tag"

    if ! command -v skopeo >/dev/null 2>&1; then
        print_message "  Update Check: skopeo not installed. Cannot check updates for '$container_name'." "DANGER"
        return 1
    fi

    # Inspect the image name/tag directly for its RepoDigests
    search_pattern_in_repodigests="^${registry_host}/${image_path_for_skopeo}@"
    local_digest_line=$(docker inspect -f '{{range .RepoDigests}}{{.}}{{println}}{{end}}' "$current_image_ref" 2>/dev/null | grep -E "$search_pattern_in_repodigests" | head -n 1)
    local_digest=""
    if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
        local_digest="${local_digest_line##*@}"
    else
        print_message "  Update Check: No matching local RepoDigest for '$current_image_ref' via pattern '$search_pattern_in_repodigests'. Fallback: first RepoDigest." "INFO"
        local_digest_line=$(docker inspect -f '{{index .RepoDigests 0}}' "$current_image_ref" 2>/dev/null)
        if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
            local_digest="${local_digest_line##*@}"
        fi
    fi

    if [ -z "$local_digest" ]; then
        print_message "  Update Check: Failed to get local digest for '$current_image_ref' ($registry_host/$image_path_for_skopeo). Cannot check updates." "WARNING"
        return 1
    fi

    print_message "  Update Check: Checking remote '$skopeo_image_ref'..." "INFO"
    skopeo_output=$(skopeo inspect "$skopeo_image_ref" 2>&1)
    skopeo_exit_code=$?
    remote_digest=""
    if [ $skopeo_exit_code -eq 0 ]; then
        remote_digest=$(jq -r '.Digest' <<< "$skopeo_output")
        if [ "$remote_digest" == "null" ] || [ -z "$remote_digest" ]; then
            print_message "  Update Check: skopeo inspect for '$skopeo_image_ref' gave no digest." "DANGER"
            print_message "    Skopeo output: $skopeo_output" "INFO"
            return 1
        fi
    else
        print_message "  Update Check: Error inspecting remote '$skopeo_image_ref'." "DANGER"
        if echo "$skopeo_output" | grep -qiE "unauthorized|authentication|denied|forbidden|credentials"; then
            print_message "    Error: Authentication failed for '$registry_host'." "DANGER"
        elif echo "$skopeo_output" | grep -qiE "manifest unknown|not found|no such host"; then
            print_message "    Error: Image/tag not found at remote, or registry host invalid: '$skopeo_image_ref'." "DANGER"
        else
            print_message "    Skopeo failed (code $skopeo_exit_code)." "WARNING"
        fi
        print_message "    Full skopeo error: $skopeo_output" "INFO"
        return 1
    fi

    print_message "  Comparing Local: $local_digest (image: $current_image_ref) vs Remote: $remote_digest (image: $skopeo_image_ref)" "INFO"
    if [ "$remote_digest" != "$local_digest" ]; then
        print_message "  Update Check: Update available for '$current_image_ref'!\n  Local Digest: $local_digest\n  Remote Digest: $remote_digest" "WARNING"
        return 1
    else
        print_message "  Update Check: Image '$current_image_ref' is up-to-date." "GOOD"
        return 0
    fi
}

check_logs() {
  local container_name="$1"
  local print_to_stdout="${2:-false}"
  local filter_errors="${3:-false}"
  local raw_logs docker_logs_status logs_to_display_or_analyze issues_found_by_grep

  raw_logs=$(docker logs --tail "$LOG_LINES_TO_CHECK" "$container_name" 2>&1)
  docker_logs_status=$?

  if [ $docker_logs_status -ne 0 ]; then
    print_message "  Log Check: Error retrieving logs for '$container_name' (status: $docker_logs_status)." "DANGER"
    print_message "    Docker error: $raw_logs" "INFO"
    return 1
  fi

  logs_to_display_or_analyze="$raw_logs"
  issues_found_by_grep=false

  if [ "$filter_errors" = "true" ]; then
    if echo "$raw_logs" | grep -q -i -E 'error|panic|fail|fatal'; then
      logs_to_display_or_analyze=$(echo "$raw_logs" | grep -i -E 'error|panic|fail|fatal')
      issues_found_by_grep=true
    else
      logs_to_display_or_analyze=""
    fi
  fi

  if [ "$print_to_stdout" = "true" ]; then
    if [ "$filter_errors" = "true" ]; then
      echo "Filtered logs (errors/warnings) for '$container_name' (last $LOG_LINES_TO_CHECK lines):"
    else
      echo "Last $LOG_LINES_TO_CHECK log lines for '$container_name':"
    fi
    if [ -n "$logs_to_display_or_analyze" ]; then
      echo "$logs_to_display_or_analyze"
    else
      if [ "$filter_errors" = "true" ]; then echo "No lines matching error patterns found.";
      elif [ -z "$raw_logs" ]; then echo "No log output in the last $LOG_LINES_TO_CHECK lines.";
      else echo "No log output in the last $LOG_LINES_TO_CHECK lines."; fi
    fi
    echo "-------------------------"
  fi

  if [ "$filter_errors" = "true" ]; then # Usually for CLI 'logs errors' command
    if [ "$issues_found_by_grep" = "true" ]; then
      print_message "  Log Check: Errors/warnings found (when filtering)." "WARNING"; return 0;
    else
      print_message "  Log Check: No specific errors/warnings found (when filtering)." "GOOD"; return 0;
    fi
  else # For main monitoring loop
    if [ -n "$raw_logs" ]; then
      if echo "$raw_logs" | grep -q -i -E 'error|panic|fail|fatal'; then
          print_message "  Log Check: Potential errors/warnings found in recent $LOG_LINES_TO_CHECK lines. Please review." "WARNING"
          return 1 # Flag for summary
      else
          print_message "  Log Check: Logs retrieved (last $LOG_LINES_TO_CHECK lines). No obvious widespread errors found." "GOOD"
          return 0
      fi
    else
      print_message "  Log Check: No log output in last $LOG_LINES_TO_CHECK lines for '$container_name'." "INFO"
      return 1 # Flag "no logs" as an issue for summary
    fi
  fi
}

save_logs() {
  local container_name="$1"
  local log_file_name="${container_name}_logs_$(date '+%Y-%m-%d_%H-%M-%S').log"
  if docker logs "$container_name" > "$log_file_name"; then
    print_message "Logs for '$container_name' saved to '$log_file_name'." "GOOD"
  else
    print_message "Error saving logs for '$container_name'." "DANGER"
  fi
}

check_host_disk_usage() {
    local target_filesystem="/" # Example, make this configurable
    print_message "Host Disk Usage ($target_filesystem):" "INFO"
    local usage_line
    usage_line=$(df -P "$target_filesystem" 2>/dev/null | awk 'NR==2')
    if [ -n "$usage_line" ]; then
        local capacity used avail
        capacity=$(echo "$usage_line" | awk '{print $5}' | tr -d '%') # Use%
        used=$(echo "$usage_line" | awk '{print $3}') # Used blocks/size
        avail=$(echo "$usage_line" | awk '{print $4}') # Available blocks/size
        # Convert used/avail to human readable if desired using numfmt or similar
        print_message "  - $target_filesystem: $capacity% used (Used: $used, Available: $avail)" "INFO" # Or use thresholds for WARNING
    else
        print_message "  - Could not determine disk usage for $target_filesystem" "WARNING"
    fi
}

check_host_memory_usage() {
    print_message "Host Memory Usage:" "INFO"
    if command -v free >/dev/null 2>&1; then # Linux 'free' command
        local mem_line
        mem_line=$(free -m | awk 'NR==2{printf "Total: %sMB, Used: %sMB (%.0f%%), Free: %sMB", $2, $3, ($3*100)/$2, $4}')
        print_message "  - $mem_line" "INFO"
    else
        print_message "  - 'free' command not found, cannot check host memory." "WARNING"
    fi
}

print_summary() {
  local container_name_summary # loop variable
  if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
    print_message "------------------------ Summary of Issues Found ------------------------" "SUMMARY"
    print_message "The following containers have warnings or errors: ⚠️" "SUMMARY"

    # To ensure we list each container only once even if it was somehow added multiple times
    # (though current logic adds it once if any issue), we can iterate unique names.
    # However, current logic should be fine. If not, we can get unique names from map keys.

    # Iterate through containers that had issues
    # Using WARNING_OR_ERROR_CONTAINERS ensures order of detection if that matters,
    # or use map keys for potentially different order: for container_name_summary in "${!CONTAINER_ISSUES_MAP[@]}"; do
    local printed_containers=() # To handle unique printing if WARNING_OR_ERROR_CONTAINERS could have dupes
                                # Not strictly necessary with current population logic but safe.
    for container_name_summary in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
        # Check if already printed this container's summary (if list could have duplicates)
        if [[ " ${printed_containers[*]} " =~ " ${container_name_summary} " ]]; then
            continue
        fi
        printed_containers+=("$container_name_summary")

        local issues="${CONTAINER_ISSUES_MAP["$container_name_summary"]:-Unknown Issue}" # Default if somehow not in map
        print_message "- ${container_name_summary} ❌ (Issues: ${issues})" "WARNING"
    done
  else
    print_message "------------------------ Summary of Issues Found ------------------------" "SUMMARY"
    print_message "No issues found in monitored containers. All checks passed. ✅" "GOOD"
  fi
  print_message "------------------------------------------------------------------------" "SUMMARY"
}

# --- Main Execution ---
declare -a CONTAINERS_TO_CHECK=()
declare -a WARNING_OR_ERROR_CONTAINERS=()
declare -a CONTAINERS_TO_CHECK=()
declare -a WARNING_OR_ERROR_CONTAINERS=()
declare -A CONTAINER_ISSUES_MAP # To store specific issues: CONTAINER_ISSUES_MAP["container_name"]="Issue1, Issue2"

# Variables used in main execution block (not local)
container_name_or_id="" # Loop variable
container_actual_name=""
inspect_json=""
stats_json=""
cpu_percent=""
mem_percent=""
current_image_ref_for_update=""
status_check_result=0
restart_check_result=0
resource_check_result=0
disk_check_result=0
network_check_result=0
update_check_result=0
log_check_result=0
run_monitoring=false
log_dir_final=""
# For argument parsing loop (logs command)
all_running_containers=()
container_id_logs=""
c_name=""
# For ENV var parsing loop
temp_env_names=()
name_from_env=""
name_trimmed=""
# For config.sh default list
all_running_names=()


if [ "$#" -gt 0 ]; then
  case "$1" in
    logs)
      if [ "$#" -eq 1 ]; then
        mapfile -t all_running_containers < <(docker container ls -q 2>/dev/null)
        if [ ${#all_running_containers[@]} -eq 0 ]; then
          print_message "No running containers found to show logs for." "INFO"
        else
          for container_id_logs in "${all_running_containers[@]}"; do
            c_name=$(docker container inspect -f '{{.Name}}' "$container_id_logs" | sed 's|^/||' 2>/dev/null || echo "$container_id_logs")
            check_logs "$c_name" "true" "false"
            echo "----------------------"
          done
        fi
      elif [ "$#" -eq 2 ]; then check_logs "$2" "true" "false";
      elif [ "$#" -eq 3 ] && [ "$2" = "errors" ]; then check_logs "$3" "true" "true";
      else print_message "Usage: $0 logs [errors] [<container_name>]" "DANGER"; exit 1;
      fi
      exit 0 ;;
    save)
      if [ "$#" -eq 3 ] && [ "$2" = "logs" ]; then save_logs "$3";
      else print_message "Usage: $0 save logs <container_name>" "DANGER"; exit 1;
      fi
      exit 0 ;;
    *) CONTAINERS_TO_CHECK=("$@") ;;
  esac
elif [ "$#" -eq 0 ]; then
    if [ -n "$CONTAINER_NAMES" ]; then # Checks ENV var (string)
        IFS=',' read -r -a temp_env_names <<< "$CONTAINER_NAMES"
        for name_from_env in "${temp_env_names[@]}"; do
            name_trimmed="${name_from_env#"${name_from_env%%[![:space:]]*}"}"
            name_trimmed="${name_trimmed%"${name_trimmed##*[![:space:]]}"}"
            if [ -n "$name_trimmed" ]; then CONTAINERS_TO_CHECK+=("$name_trimmed"); fi
        done
        if [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ] && [ -n "$CONTAINER_NAMES" ]; then
            print_message "Warning: ENV CONTAINER_NAMES ('$CONTAINER_NAMES') parsed to empty list." "WARNING"
        fi
    elif [ ${#CONTAINER_NAMES_FROM_CONFIG_FILE[@]} -gt 0 ]; then
        CONTAINERS_TO_CHECK=("${CONTAINER_NAMES_FROM_CONFIG_FILE[@]}")
    else
        mapfile -t all_running_names < <(docker container ls --format '{{.Names}}' 2>/dev/null)
        if [ ${#all_running_names[@]} -gt 0 ]; then CONTAINERS_TO_CHECK=("${all_running_names[@]}"); fi
    fi
fi

run_monitoring=false
if [[ "$#" -gt 0 && "$1" != "logs" && "$1" != "save" ]]; then # CLI args are container names
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then run_monitoring=true;
    else print_message "No valid container names from CLI args." "INFO"; fi
elif [[ "$#" -eq 0 ]]; then # No CLI args
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then run_monitoring=true;
    else print_message "No containers specified or found running to monitor." "INFO"; fi
fi

if [ "$run_monitoring" = "true" ]; then
    print_message "---------------------- Docker Container Monitoring Results ----------------------" "INFO"
    for container_name_or_id in "${CONTAINERS_TO_CHECK[@]}"; do
        print_message "Container: ${container_name_or_id}" "INFO"
        inspect_json=$(docker inspect "$container_name_or_id" 2>/dev/null)
        if [ -z "$inspect_json" ]; then
            print_message "  Status: Container '${container_name_or_id}' not found or inspect failed." "DANGER"
            WARNING_OR_ERROR_CONTAINERS+=("$container_name_or_id")
            echo "-------------------------------------------------------------------------"
            continue
        fi
        
        container_actual_name=$(jq -r '.[0].Name' <<< "$inspect_json" | sed 's|^/||')

        stats_json=$(docker stats --no-stream --format '{{json .}}' "$container_name_or_id" 2>/dev/null)
        cpu_percent="N/A"; mem_percent="N/A" # Reset for each container
        if [ -n "$stats_json" ]; then
            cpu_percent=$(jq -r '.CPUPerc // "N/A"' <<< "$stats_json" | tr -d '%')
            mem_percent=$(jq -r '.MemPerc // "N/A"' <<< "$stats_json" | tr -d '%')
        else
            print_message "  Stats: Could not retrieve stats for '$container_actual_name'." "WARNING"
        fi

        check_container_status "$container_actual_name" "$inspect_json" "$cpu_percent" "$mem_percent"
        status_check_result=$?
        check_container_restarts "$container_actual_name" "$inspect_json"
        restart_check_result=$?
        check_resource_usage "$container_actual_name" "$cpu_percent" "$mem_percent"
        resource_check_result=$?
        check_disk_space "$container_actual_name" "$inspect_json"
        disk_check_result=$?
        check_network "$container_actual_name"
        network_check_result=$?
        current_image_ref_for_update=$(jq -r '.[0].Config.Image' <<< "$inspect_json")
        check_for_updates "$container_actual_name" "$current_image_ref_for_update" # Corrected call
        update_check_result=$?
        check_logs "$container_actual_name" "false" "false"
        log_check_result=$?

    # Collect specific issue tags for the summary
        declare -a issue_tags=()
        if [ $status_check_result -ne 0 ]; then issue_tags+=("Status"); fi
        if [ $restart_check_result -ne 0 ]; then issue_tags+=("Restarts"); fi
        if [ $resource_check_result -ne 0 ]; then issue_tags+=("Resources"); fi # Detailed CPU/Mem warnings are in per-container log
        if [ $disk_check_result -ne 0 ]; then issue_tags+=("Disk"); fi # Detailed mount warnings are in per-container log
        if [ $network_check_result -ne 0 ]; then issue_tags+=("Network"); fi
        if [ $update_check_result -ne 0 ]; then issue_tags+=("Update"); fi # Covers "available" or "check failed"
        if [ $log_check_result -ne 0 ]; then issue_tags+=("Logs"); fi # Covers "warnings in logs", "no logs", or "check failed"

        if [ ${#issue_tags[@]} -gt 0 ]; then
          # Add to the general list of containers with problems
          WARNING_OR_ERROR_CONTAINERS+=("$container_actual_name")

          # Create a comma-separated string of issues for the map
          issues_string=""
          for ((j=0; j<${#issue_tags[@]}; j++)); do
              issues_string+="${issue_tags[$j]}"
              if [ $j -lt $((${#issue_tags[@]} - 1)) ]; then # If not the last element
                  issues_string+=", "
              fi
          done
          CONTAINER_ISSUES_MAP["$container_actual_name"]="$issues_string"
      fi
        echo "-------------------------------------------------------------------------"
    done
    print_message "---------------------- End of Container Monitoring Results -------------------" "INFO"
    print_summary
fi

# --- Finalize ---
if [ -n "$LOG_FILE" ]; then
  log_dir_final=$(dirname "$LOG_FILE")
  if [ ! -d "$log_dir_final" ]; then
    mkdir -p "$log_dir_final"
    if [ $? -ne 0 ]; then
      echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Could not create log directory '$log_dir_final'. Logging to file will be disabled."
      LOG_FILE=""
    fi
  fi
  if [ -n "$LOG_FILE" ]; then
    if ! touch "$LOG_FILE" &>/dev/null; then
        echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Log file '$LOG_FILE' not writable/creatable. Logging disabled." >&2
        LOG_FILE=""
    elif [ ! -f "$LOG_FILE" ]; then # Should have been created by touch
        echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} Log file '$LOG_FILE' created."
    fi
  fi
fi

print_message "Docker monitoring script completed." "INFO"
exit 0
