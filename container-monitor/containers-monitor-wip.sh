#!/bin/bash

# Description:
# This script monitors Docker containers on the system.
# It checks container status, resource usage (CPU, Memory),
# checks for image updates, checks container logs for errors/warnings,
# and monitors container restarts.
# Output is printed to the standard output with improved formatting and colors and logged to a file.
#
# Configuration:
#   Configuration is primarily done via environment variables.
#   See config.sh for default values and environment variable names.
#   Environment variables override settings in config.sh.
#
# Environment Variables (can be set to customize script behavior):
#   - LOG_LINES_TO_CHECK: Number of log lines to check (default: 20)
#   - CHECK_FREQUENCY_MINUTES: Frequency of checks in minutes (default: 360) - Note: Script is run by external scheduler
#   - LOG_FILE: Path to the log file (default: docker-monitor.log in script directory)
#   - CONTAINER_NAMES: Comma-separated list of container names to monitor.
#                       Overrides the CONTAINER_NAMES_DEFAULT array in config.sh.
#                       If not set and CONTAINER_NAMES_DEFAULT is empty in config.sh,
#                       all running containers will be monitored by default.
#
# Usage:
#   ./docker-container-monitor.sh                           - Monitor containers based on config (or all running if config is empty)
#   ./docker-container-monitor.sh <container_name1> <container_name2> ... - Monitor specific containers
#   ./docker-container-monitor.sh logs                      - Show logs for all running containers
#   ./docker-container-monitor.sh logs <container_name>     - Show logs for a specific container
#   ./docker-container-monitor.sh logs errors <container_name> - Show errors in logs for a specific container
#   ./docker-container-monitor.sh save logs <container_name> - Save logs for a specific container to a file
#
# Prerequisites:
#   - Docker
#   - jq (for processing JSON output from docker inspect and docker stats)
#   - skopeo (for checking for container image updates)
#   - (Optional) numfmt: for human-readable formatting in future enhancements (not currently used)

# --- ANSI Color Codes ---
COLOR_RESET="\033[0m"
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_CYAN="\033[0;36m"
COLOR_MAGENTA="\033[0;35m" # Magenta for Summary

# --- Script Default Configuration Values ---
# These are the base defaults. config.sh can override these via *_DEFAULT variables,
# and environment variables can override the final values.
_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK=20
_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES=360 # Currently for documentation; script is run by external scheduler
_SCRIPT_DEFAULT_LOG_FILE="$(cd "$(dirname "$0")" && pwd)/docker-monitor.log" # Absolute path to log file in script's dir
declare -a _SCRIPT_DEFAULT_CONTAINER_NAMES_ARRAY=() # Default is to monitor all running containers if no other config found

# Initialize working config variables from script defaults
LOG_LINES_TO_CHECK="$_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK"
CHECK_FREQUENCY_MINUTES="$_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES" # Retain for consistency if used later
LOG_FILE="$_SCRIPT_DEFAULT_LOG_FILE"
declare -a CONTAINER_NAMES_FROM_CONFIG_FILE=() # Will hold 'CONTAINER_NAMES_DEFAULT' from config.sh

# --- Source Configuration File ---
# Original script used: CONFIG_FILE="./config.sh"
# Using a more robust way to define path relative to script:
_CONFIG_FILE_PATH="$(cd "$(dirname "$0")" && pwd)/config.sh"
if [ -f "$_CONFIG_FILE_PATH" ]; then
  # config.sh is expected to optionally define:
  # LOG_LINES_TO_CHECK_DEFAULT (number)
  # CHECK_FREQUENCY_MINUTES_DEFAULT (number)
  # LOG_FILE_DEFAULT (string, path to log file)
  # CONTAINER_NAMES_DEFAULT (bash array of container names, e.g., ("nginx" "redis"))
  source "$_CONFIG_FILE_PATH"

  # Override script defaults with values from config.sh if they are set
  LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK_DEFAULT:-$LOG_LINES_TO_CHECK}"
  CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES_DEFAULT:-$CHECK_FREQUENCY_MINUTES}"
  LOG_FILE="${LOG_FILE_DEFAULT:-$LOG_FILE}"

  # Ensure CONTAINER_NAMES_DEFAULT from config.sh is a valid array before using
  if declare -p CONTAINER_NAMES_DEFAULT &>/dev/null && [[ "$(declare -p CONTAINER_NAMES_DEFAULT)" == "declare -a"* ]]; then
    if [ ${#CONTAINER_NAMES_DEFAULT[@]} -gt 0 ]; then
        CONTAINER_NAMES_FROM_CONFIG_FILE=("${CONTAINER_NAMES_DEFAULT[@]}")
    fi
  fi
else
  # Using echo here as print_message might not be fully initialized or LOG_FILE not set yet
  echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} Configuration file '$_CONFIG_FILE_PATH' not found. Using script defaults or environment variables."
fi

# --- Override with Environment Variables ---
# Environment variables have the highest precedence.
# Names match script's documentation: LOG_LINES_TO_CHECK, CHECK_FREQUENCY_MINUTES, LOG_FILE, CONTAINER_NAMES
LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK:-$LOG_LINES_TO_CHECK}"
CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES:-$CHECK_FREQUENCY_MINUTES}"
LOG_FILE="${LOG_FILE:-$LOG_FILE}"
# CONTAINER_NAMES (env var, comma-separated string) will be processed in the main execution logic.

# --- Prerequisite Checks ---
if ! command -v docker >/dev/null 2>&1; then
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} Docker command not found. Please install Docker." >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} jq command not found. Please install jq." >&2
    exit 1
fi
# Skopeo is checked within check_for_updates as it's specific to that function.

# Ensure LOG_LINES_TO_CHECK is a positive integer
if ! [[ "$LOG_LINES_TO_CHECK" =~ ^[0-9]+$ ]] || [ "$LOG_LINES_TO_CHECK" -le 0 ]; then
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} Invalid LOG_LINES_TO_CHECK value ('$LOG_LINES_TO_CHECK'). Using default: $_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK." >&2
    LOG_LINES_TO_CHECK="$_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK"
fi

# --- Functions ---

print_message() {
  local message="$1"
  local color_type="$2"
  local color_code=""
  local log_output_no_color="" # For logging to file without color codes

  case "$color_type" in
    "INFO")
      color_code="$COLOR_CYAN"
      ;;
    "GOOD")
      color_code="$COLOR_GREEN"
      ;;
    "WARNING")
      color_code="$COLOR_YELLOW"
      ;;
    "DANGER")
      color_code="$COLOR_RED"
      ;;
    "SUMMARY")
      color_code="$COLOR_MAGENTA"
      ;;
    *)
      color_code="$COLOR_RESET" # Default no color
      color_type="NONE" # Indicate no color type for prefix
      ;;
  esac

  if [ "$color_type" = "NONE" ]; then
    echo -e "${message}" # Use -e for consistent escape sequence processing
    log_output_no_color="${message}" # No prefix for log file
  else
    local colored_message="${color_code}[${color_type}]${COLOR_RESET} ${message}"
    echo -e "${colored_message}" # Output to terminal with color
    log_output_no_color="[${color_type}] ${message}" # Prefix for log file
  fi

  # Log to file (append mode)
  if [ -n "$LOG_FILE" ]; then # Check if LOG_FILE is defined and not empty
    # Ensure log directory exists before attempting to write (relevant if LOG_FILE path was customized)
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir" &>/dev/null # Suppress output for this check within print_message
    fi
    # Check if file is writable, or can be created (minimal check)
    if touch "$LOG_FILE" &>/dev/null; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') ${log_output_no_color}" >> "$LOG_FILE"
    else
        # Avoid recursive calls to print_message if LOG_FILE itself is the problem
        echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Cannot write to LOG_FILE ('$LOG_FILE'). Logging to file disabled for this message." >&2
    fi
  fi
}

check_container_status() {
  local container_name="$1" # For messaging
  local inspect_data="$2"   # JSON string from docker inspect
  local cpu_percent="$3"
  local mem_percent="$4"

  local status
  status=$(echo "$inspect_data" | jq -r '.[0].State.Status')
  # Container not found check is done prior to calling this function in the new loop

  local health_status="not configured"
  # Check if Health key exists and is not null and Health.Status is not null
  if echo "$inspect_data" | jq -e '.[0].State.Health != null and .[0].State.Health.Status != null' >/dev/null 2>&1; then
    health_status=$(echo "$inspect_data" | jq -r '.[0].State.Health.Status')
  fi

  if [ "$status" != "running" ]; then
    print_message "  Status: Not running (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "DANGER"
    return 1
  else
    if [ "$health_status" = "healthy" ]; then
      print_message "  Status: Running and healthy (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "GOOD"
      return 0
    elif [ "$health_status" = "unhealthy" ]; then
      print_message "  Status: Running but UNHEALTHY (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "DANGER"
      local detailed_health
      # Get the Health object as a JSON string
      detailed_health=$(echo "$inspect_data" | jq -r '.[0].State.Health | tojson')
      if [ -n "$detailed_health" ] && [ "$detailed_health" != "null" ]; then
        print_message "    Detailed Health Info: $detailed_health" "WARNING"
      fi
      return 1
    elif [ "$health_status" = "not configured" ]; then
      print_message "  Status: Running (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "GOOD"
      return 0
    else # e.g., "starting" or other health states if Docker introduces them
      print_message "  Status: Running (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "WARNING"
      return 1 # Treat intermediate or unknown health states as a warning/issue for summary
    fi
  fi
}

check_container_restarts() {
  local container_name="$1" # For messaging
  local inspect_data="$2"   # JSON string from docker inspect

  local restart_count
  restart_count=$(echo "$inspect_data" | jq -r '.[0].RestartCount')
  local is_restarting # boolean: true or false
  is_restarting=$(echo "$inspect_data" | jq -r '.[0].State.Restarting')

  if [ "$is_restarting" = "true" ]; then
    print_message "  Restart Status: Container '$container_name' is currently restarting." "WARNING"
    return 1 # Indicates an issue
  elif [ "$restart_count" -gt 0 ]; then
    print_message "  Restart Status: Container '$container_name' has restarted $restart_count times." "WARNING"
    return 1 # Indicates an issue
  else
    print_message "  Restart Status: No unexpected restarts detected for '$container_name'." "GOOD"
    return 0
  fi
}

check_for_updates() {
    local container_name="$1"    # For messaging
    local current_image_ref="$2" # {{.Config.Image}}
    local inspect_data="$3"      # Full inspect JSON for RepoDigests

    # Handle cases where update check by tag is not applicable
    if [[ "$current_image_ref" == *@sha256:* ]]; then
        print_message "  Update Check: Container '$container_name' is running from an image pinned by digest ($current_image_ref). Update check by tag is not applicable." "INFO"
        return 0 # Not an error, but check cannot proceed in the usual way.
    fi
    if [[ "$current_image_ref" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; then
        print_message "  Update Check: Container '$container_name' is running directly from an image ID ($current_image_ref). Cannot determine registry to check for updates." "INFO"
        return 0 # Not an error, but cannot determine registry.
    fi

    # --- Image Parsing Logic ---
    local registry_host=""
    local image_path_for_skopeo="" # This is the part after the registry host, e.g., "namespace/image" or "library/image"
    local tag="latest"             # Default tag

    local image_name_no_tag="$current_image_ref"
    if [[ "$current_image_ref" == *":"* ]]; then
        # Check if the part after the last colon looks like a digest
        if [[ "${current_image_ref##*:}" =~ ^[0-9a-fA-F]{7,}$ && "${current_image_ref}" == *@* ]]; then # Heuristic for image@sha256:digest_prefix
            print_message "  Update Check: Image reference '$current_image_ref' for container '$container_name' appears to be digest-pinned. Skipping tag-based update check." "INFO"
            return 0
        fi
        tag="${current_image_ref##*:}"
        image_name_no_tag="${current_image_ref%:*}"
    fi

    if [[ "$image_name_no_tag" == *"/"* ]]; then # Contains a slash, e.g., registry/image or user/image
        local first_part
        first_part=$(echo "$image_name_no_tag" | cut -d'/' -f1)
        # Check if the first part is a hostname (contains a dot or 'localhost' or a port number)
        if [[ "$first_part" == *"."* ]] || [[ "$first_part" == "localhost" ]] || [[ "$first_part" == *":"* ]]; then
            registry_host="$first_part"
            image_path_for_skopeo=$(echo "$image_name_no_tag" | cut -d'/' -f2-)
        else # No dot, not localhost, no port: assume it's Docker Hub, e.g., username/image
            registry_host="registry-1.docker.io" # Canonical Docker Hub registry
            image_path_for_skopeo="$image_name_no_tag" # e.g., "username/image"
        fi
    else # No slash, e.g., "nginx", assume Docker Hub official image
        registry_host="registry-1.docker.io"
        image_path_for_skopeo="library/$image_name_no_tag" # e.g., "library/nginx"
    fi
    # --- End of Image Parsing Logic ---

    local skopeo_image_ref="docker://$registry_host/$image_path_for_skopeo:$tag"

    if ! command -v skopeo >/dev/null 2>&1; then
        print_message "  Update Check: Error - skopeo is not installed. Cannot check for updates for '$container_name'." "DANGER"
        return 1 # Report as an issue
    fi

    # --- Local Digest Retrieval ---
    # We need to find a RepoDigest that matches the registry and path we are checking against.
    local search_pattern_in_repodigests="^${registry_host}/${image_path_for_skopeo}@"
    local local_digest_line
    # Extract RepoDigests array as lines using jq, then grep. '?' suppresses error if RepoDigests is null/empty.
    local_digest_line=$(echo "$inspect_data" | jq -r '.[0].RepoDigests[]?' | grep -E "$search_pattern_in_repodigests" | head -n 1)

    local local_digest=""
    if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
        local_digest="${local_digest_line##*@}"
    else
        # Fallback: If no specific RepoDigest matches
        print_message "  Update Check: No local RepoDigest found for '$current_image_ref' matching '$search_pattern_in_repodigests'. Attempting fallback using first available RepoDigest. This might be less accurate." "INFO"
        local_digest_line=$(echo "$inspect_data" | jq -r '.[0].RepoDigests[0]?') # Get the first digest, if any
        if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
            local_digest="${local_digest_line##*@}"
        fi
    fi

    if [ -z "$local_digest" ]; then
        print_message "  Update Check: Failed to determine local image digest for '$current_image_ref' ($registry_host/$image_path_for_skopeo). Image may not have RepoDigests, was only built locally, or RepoDigests do not match expected format. Cannot check for updates." "WARNING"
        return 1 # Report as an issue as we cannot determine if an update is needed
    fi
    # --- End of Local Digest Retrieval ---

    print_message "  Update Check: Checking remote image '$skopeo_image_ref' for updates..." "INFO"
    local skopeo_output
    local skopeo_exit_code
    # Capture both stdout and stderr from skopeo
    skopeo_output=$(skopeo inspect "$skopeo_image_ref" 2>&1)
    skopeo_exit_code=$?

    local remote_digest=""
    if [ $skopeo_exit_code -eq 0 ]; then
        remote_digest=$(echo "$skopeo_output" | jq -r '.Digest')
        if [ "$remote_digest" == "null" ] || [ -z "$remote_digest" ]; then # jq -r '.Digest' outputs "null" string if key not found or value is null
            print_message "  Update Check: Error - skopeo inspect succeeded for '$skopeo_image_ref' but returned no digest." "DANGER"
            print_message "    Skopeo output: $skopeo_output" "INFO"
            return 1
        fi
    else
        print_message "  Update Check: Error inspecting remote image '$skopeo_image_ref'." "DANGER"
        if echo "$skopeo_output" | grep -qiE "unauthorized|authentication required|denied|forbidden|credentials"; then
            print_message "    Error details: Authentication failed. Ensure you are logged into '$registry_host' (e.g., run 'docker login $registry_host')." "DANGER"
        elif echo "$skopeo_output" | grep -qiE "manifest unknown|not found|no such host"; then
            print_message "    Error details: Image or tag not found at remote registry, or registry host is invalid: '$skopeo_image_ref'." "DANGER"
        else
            print_message "    Skopeo command failed with exit code $skopeo_exit_code." "WARNING"
        fi
        print_message "    Full skopeo error: $skopeo_output" "INFO" # Log full error for debugging
        return 1 # Report as an issue
    fi

    print_message "  Comparing Local: $local_digest (from $current_image_ref) vs Remote: $remote_digest (from $skopeo_image_ref)" "INFO"
    if [ "$remote_digest" != "$local_digest" ]; then
        print_message "  Update Check: Update available for '$current_image_ref'!\n  Current Digest (local): $local_digest\n  New Digest (remote):    $remote_digest" "WARNING"
        return 1 # Indicates an update is available, treated as a "warning" for summary
    else
        print_message "  Update Check: Image '$current_image_ref' is up-to-date." "GOOD"
        return 0 # No update needed
    fi
}

check_logs() {
  local container_name="$1"
  local print_to_stdout="${2:-false}" # Default false
  local filter_errors="${3:-false}"   # Default false
  # LOG_LINES_TO_CHECK is a global variable, validated to be a positive integer at script start

  local raw_logs
  local docker_logs_status

  raw_logs=$(docker logs --tail "$LOG_LINES_TO_CHECK" "$container_name" 2>&1)
  docker_logs_status=$?

  if [ $docker_logs_status -ne 0 ]; then
    print_message "  Log Check: Error - Could not retrieve logs for '$container_name'. Docker command failed (status: $docker_logs_status)." "DANGER"
    print_message "    Docker error: $raw_logs" "INFO" # Show the actual error from Docker
    return 1 # Definite error retrieving logs
  fi

  local logs_to_display_or_analyze="$raw_logs"
  local issues_found_by_grep=false

  if [ "$filter_errors" = "true" ]; then
    if echo "$raw_logs" | grep -q -i -E 'error|panic|fail|fatal'; then
      logs_to_display_or_analyze=$(echo "$raw_logs" | grep -i -E 'error|panic|fail|fatal')
      issues_found_by_grep=true
    else
      logs_to_display_or_analyze="" # No errors found by grep
    fi
  fi

  if [ "$print_to_stdout" = "true" ]; then
    if [ "$filter_errors" = "true" ]; then
      echo "Filtered logs (errors/warnings) for container '$container_name' (last $LOG_LINES_TO_CHECK lines scanned):"
    else
      echo "Last $LOG_LINES_TO_CHECK log lines for container '$container_name':"
    fi

    if [ -n "$logs_to_display_or_analyze" ]; then
      echo "$logs_to_display_or_analyze"
    else
      if [ "$filter_errors" = "true" ]; then # No errors found by grep
        echo "No lines matching error patterns ('error|panic|fail|fatal') found."
      elif [ -z "$raw_logs" ]; then # Not filtering, and raw_logs itself was empty
        echo "No log output in the last $LOG_LINES_TO_CHECK lines."
      else # Not filtering, raw_logs had content, but somehow logs_to_display_or_analyze is empty (should not happen if not filtering)
           # This implies raw_logs was empty if logs_to_display_or_analyze is empty and not filtering.
        echo "No log output in the last $LOG_LINES_TO_CHECK lines."
      fi
    fi
    echo "-------------------------"
  fi

  # Determine status message and return code for monitoring summary (when not printing to stdout directly from here)
  if [ "$filter_errors" = "true" ]; then
    # This mode is typically for direct CLI use ('logs errors ...'), not the main monitoring loop.
    # The return code here doesn't affect WARNING_OR_ERROR_CONTAINERS in the main loop.
    if [ "$issues_found_by_grep" = "true" ]; then
      print_message "  Log Check: Errors/warnings found in recent logs (when filtering)." "WARNING"
      return 0
    else
      print_message "  Log Check: No specific errors/warnings found in recent logs (when filtering)." "GOOD"
      return 0
    fi
  else
    # This is the path taken during the main monitoring loop (filter_errors=false)
    if [ -n "$raw_logs" ]; then # Logs were retrieved (docker logs command succeeded and returned some output)
      # Optionally, do a quick scan for errors even if not explicitly filtering for the return code logic
      if echo "$raw_logs" | grep -q -i -E 'error|panic|fail|fatal'; then
          print_message "  Log Check: Potential errors/warnings found in recent $LOG_LINES_TO_CHECK lines. Please review." "WARNING"
          # Return 0 because logs were retrieved; the warning is for human review.
          # If finding errors should mark container for summary, this could return 1.
          # For now, matches original behavior where only retrieval failure or no logs (empty) returns 1.
          return 0
      else
          print_message "  Log Check: Logs retrieved (last $LOG_LINES_TO_CHECK lines). No obvious widespread errors found." "GOOD"
          return 0
      fi
    else # No logs retrieved (docker logs command succeeded but returned empty output for the given tail count)
      print_message "  Log Check: No log output in last $LOG_LINES_TO_CHECK lines." "INFO"
      return 1 # As per original logic, "no logs" (empty) is treated as a minor issue for summary.
    fi
  fi
}


save_logs() {
  local container_name="$1"
  local log_file_name="${container_name}_logs_$(date '+%Y-%m-%d_%H-%M-%S').log" # Corrected variable name

  # Docker logs command. stderr is not redirected, so errors from docker cli itself will go to script's stderr.
  if docker logs "$container_name" > "$log_file_name"; then
    print_message "Logs for container '$container_name' saved to '$log_file_name'." "GOOD"
  else
    print_message "Error saving logs for container '$container_name'. Check if container exists and is accessible." "DANGER"
  fi
}

print_summary() {
  if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
    print_message "------------------------ Summary of Issues Found ------------------------" "SUMMARY"
    print_message "The following containers have warnings or errors: ⚠️" "SUMMARY"
    for container_name_summary in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do # Use different loop var name
      print_message "- ${container_name_summary} ❌" "WARNING"
    done
    print_message "------------------------------------------------------------------------" "SUMMARY"
  else
    print_message "------------------------ Summary of Issues Found ------------------------" "SUMMARY"
    print_message "No issues found in any monitored containers. All containers are running, healthy, and up-to-date. ✅" "GOOD"
    print_message "------------------------------------------------------------------------" "SUMMARY"
  fi
}

# --- Main Execution ---

declare -a CONTAINERS_TO_CHECK=() # Ensure it's an array
declare -a WARNING_OR_ERROR_CONTAINERS=()

# Argument Parsing:
# If arguments are provided, they can be:
# 1. 'logs' [errors] [<container_name>]
# 2. 'save logs <container_name>'
# 3. <container_name1> <container_name2> ... (direct container names for monitoring)
if [ "$#" -gt 0 ]; then
  case "$1" in
    logs)
      # Handle: ./script logs
      # Handle: ./script logs <container_name>
      # Handle: ./script logs errors <container_name>
      if [ "$#" -eq 1 ]; then # ./script logs (for all running containers)
        mapfile -t all_running_containers < <(docker container ls -q 2>/dev/null)
        if [ ${#all_running_containers[@]} -eq 0 ]; then
          print_message "No running containers found to show logs for." "INFO"
        else
          for container_id_logs in "${all_running_containers[@]}"; do
            local c_name # container name from ID
            c_name=$(docker container inspect -f '{{.Name}}' "$container_id_logs" | sed 's|^/||' 2>/dev/null || echo "$container_id_logs")
            check_logs "$c_name" "true" "false" # Print to stdout, don't filter errors by default
            echo "----------------------"
          done
        fi
      elif [ "$#" -eq 2 ]; then # ./script logs <container_name>
        check_logs "$2" "true" "false"
      elif [ "$#" -eq 3 ] && [ "$2" = "errors" ]; then # ./script logs errors <container_name>
        check_logs "$3" "true" "true" # Print to stdout, filter for errors
      else
        print_message "Usage: $0 logs [errors] [<container_name>]" "DANGER"
        exit 1
      fi
      exit 0 # Exit after handling 'logs' command
      ;;
    save)
      if [ "$#" -eq 3 ] && [ "$2" = "logs" ]; then # ./script save logs <container_name>
        save_logs "$3"
      else
        print_message "Usage: $0 save logs <container_name>" "DANGER"
        exit 1
      fi
      exit 0 # Exit after handling 'save' command
      ;;
    *) # Not 'logs' or 'save', so arguments are treated as container names for monitoring
      CONTAINERS_TO_CHECK=("$@")
      ;;
  esac
elif [ "$#" -eq 0 ]; then
    # No command-line arguments. Determine containers from ENV, config file, or all running.
    # 1. Environment variable CONTAINER_NAMES (comma-separated string)
    if [ -n "$CONTAINER_NAMES" ]; then # CONTAINER_NAMES is the env var name from script's docs
        IFS=',' read -r -a temp_env_names <<< "$CONTAINER_NAMES"
        for name_from_env in "${temp_env_names[@]}"; do
            # Trim whitespace
            local name_trimmed="${name_from_env#"${name_from_env%%[![:space:]]*}"}" # remove leading whitespace
            name_trimmed="${name_trimmed%"${name_trimmed##*[![:space:]]}"}"   # remove trailing whitespace
            if [ -n "$name_trimmed" ]; then
                CONTAINERS_TO_CHECK+=("$name_trimmed")
            fi
        done
        if [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ] && [ -n "$CONTAINER_NAMES" ]; then
            # Warn if ENV var was set but resulted in no container names (e.g., only commas or whitespace)
            print_message "Warning: Environment variable CONTAINER_NAMES ('$CONTAINER_NAMES') was set but parsed to an empty list of containers." "WARNING"
        fi
    # 2. CONTAINER_NAMES_DEFAULT from config.sh (loaded into CONTAINER_NAMES_FROM_CONFIG_FILE array)
    elif [ ${#CONTAINER_NAMES_FROM_CONFIG_FILE[@]} -gt 0 ]; then
        CONTAINERS_TO_CHECK=("${CONTAINER_NAMES_FROM_CONFIG_FILE[@]}")
    # 3. Default to all running containers if no specific list is provided by other means
    else
        mapfile -t all_running_names < <(docker container ls --format '{{.Names}}' 2>/dev/null)
        if [ ${#all_running_names[@]} -gt 0 ]; then
            CONTAINERS_TO_CHECK=("${all_running_names[@]}")
        fi
        # If no running containers found here, CONTAINERS_TO_CHECK will remain empty.
    fi
fi

# --- Main Monitoring Execution Block ---
# This block runs if:
# - Specific container names were given as arguments (and not 'logs' or 'save').
# - No arguments were given, and CONTAINERS_TO_CHECK was populated (from ENV, config, or all running).
# It does *not* run if 'logs' or 'save' commands were processed (they exit earlier).

# Check if we are in a monitoring scenario and have containers to check
# The first part of OR is for when CLI args are container names.
# The second part of OR is for no CLI args, where CONTAINERS_TO_CHECK was populated by env/config/all.
run_monitoring=false
if [[ "$#" -gt 0 && "$1" != "logs" && "$1" != "save" ]]; then # CLI args are container names
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
        run_monitoring=true
    else # CLI args were given but resulted in empty list (e.g. bad parsing or weird input)
        print_message "No valid container names provided for monitoring from command line arguments." "INFO"
    fi
elif [[ "$#" -eq 0 ]]; then # No CLI args, check if ENV/config/all yielded containers
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
        run_monitoring=true
    else
        # This means no CLI args, and ENV/config/all did not yield any containers.
        print_message "No containers specified or found running to monitor." "INFO"
    fi
fi


if [ "$run_monitoring" = "true" ]; then
    print_message "---------------------- Docker Container Monitoring Results ----------------------" "INFO"
    for container_name_or_id in "${CONTAINERS_TO_CHECK[@]}"; do
        print_message "Container: ${container_name_or_id}" "INFO"

        local inspect_json
        inspect_json=$(docker inspect "$container_name_or_id" 2>/dev/null)

        if [ -z "$inspect_json" ]; then
            print_message "  Status: Container '${container_name_or_id}' not found or inspect failed." "DANGER"
            WARNING_OR_ERROR_CONTAINERS+=("$container_name_or_id")
            echo "-------------------------------------------------------------------------"
            continue # Skip to the next container
        fi

        local stats_json
        # Using --format '{{json .}}' to get a single JSON line, easier to parse with jq
        stats_json=$(docker stats --no-stream --format '{{json .}}' "$container_name_or_id" 2>/dev/null)
        local cpu_percent="N/A"
        local mem_percent="N/A"
        if [ -n "$stats_json" ]; then
            # Use // "N/A" in jq for default value if key is missing or null
            cpu_percent=$(echo "$stats_json" | jq -r '.CPUPerc // "N/A"')
            mem_percent=$(echo "$stats_json" | jq -r '.MemPerc // "N/A"')
        else
            print_message "  Resource Usage: Could not retrieve stats for '$container_name_or_id'." "WARNING"
        fi

        # Pass data to check functions
        check_container_status "$container_name_or_id" "$inspect_json" "$cpu_percent" "$mem_percent"
        status_check_result=$?

        check_container_restarts "$container_name_or_id" "$inspect_json"
        restart_check_result=$? # This function now returns 1 for warnings

        local current_image_ref_for_update
        current_image_ref_for_update=$(echo "$inspect_json" | jq -r '.[0].Config.Image')
        check_for_updates "$container_name_or_id" "$current_image_ref_for_update" "$inspect_json"
        update_check_result=$?

        # For main monitoring, call check_logs without print_to_stdout and without error filtering by default.
        # The function itself will print messages like "Potential errors/warnings found..."
        check_logs "$container_name_or_id" "false" "false"
        log_check_result=$?

        if [ $status_check_result -ne 0 ] || \
           [ $restart_check_result -ne 0 ] || \
           [ $update_check_result -ne 0 ] || \
           [ $log_check_result -ne 0 ]; then
            WARNING_OR_ERROR_CONTAINERS+=("$container_name_or_id")
        fi

        echo "-------------------------------------------------------------------------"
    done
    print_message "---------------------- End of Container Monitoring Results -------------------" "INFO"
    print_summary
fi

# --- Finalize ---
# Ensure log file and its directory exist if LOG_FILE is set (final check, also handles creation)
if [ -n "$LOG_FILE" ]; then
  log_dir_final=$(dirname "$LOG_FILE")
  if [ ! -d "$log_dir_final" ]; then
    mkdir -p "$log_dir_final"
    if [ $? -ne 0 ]; then
      echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Could not create log directory '$log_dir_final'. Logging to file will be disabled."
      LOG_FILE="" # Disable logging if directory creation fails
    fi
  fi

  # If LOG_FILE is still set (i.e., directory exists or was created) and file itself doesn't exist, touch it.
  if [ -n "$LOG_FILE" ] && ! [ -f "$LOG_FILE" ]; then
    touch "$LOG_FILE"
    if [ $? -ne 0 ]; then
      echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Could not create log file '$LOG_FILE'. Logging to file will be disabled for this run."
      LOG_FILE="" # Disable logging if file creation fails
    else
      # This message goes to stdout, not the log file. Using echo, not print_message to avoid loop if logging is broken.
      echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} Log file '$LOG_FILE' created."
    fi
  fi
fi

print_message "Docker monitoring script completed." "INFO"
exit 0
