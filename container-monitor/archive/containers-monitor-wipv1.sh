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
_CONFIG_FILE_PATH="$(cd "$(dirname "$0")" && pwd)/config.sh"
if [ -f "$_CONFIG_FILE_PATH" ]; then
  source "$_CONFIG_FILE_PATH"
  LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK_DEFAULT:-$LOG_LINES_TO_CHECK}"
  CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES_DEFAULT:-$CHECK_FREQUENCY_MINUTES}"
  LOG_FILE="${LOG_FILE_DEFAULT:-$LOG_FILE}"
  if declare -p CONTAINER_NAMES_DEFAULT &>/dev/null && [[ "$(declare -p CONTAINER_NAMES_DEFAULT)" == "declare -a"* ]]; then
    if [ ${#CONTAINER_NAMES_DEFAULT[@]} -gt 0 ]; then
        CONTAINER_NAMES_FROM_CONFIG_FILE=("${CONTAINER_NAMES_DEFAULT[@]}")
    fi
  fi
else
  echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} Configuration file '$_CONFIG_FILE_PATH' not found. Using script defaults or environment variables."
fi

# --- Override with Environment Variables ---
LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK:-$LOG_LINES_TO_CHECK}"
CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES:-$CHECK_FREQUENCY_MINUTES}"
LOG_FILE="${LOG_FILE:-$LOG_FILE}"

# --- Prerequisite Checks ---
if ! command -v docker >/dev/null 2>&1; then
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} Docker command not found. Please install Docker." >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} jq command not found. Please install jq." >&2
    exit 1
fi

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
    if touch "$LOG_FILE" &>/dev/null; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') ${log_output_no_color}" >> "$LOG_FILE"
    else
        echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Cannot write to LOG_FILE ('$LOG_FILE'). Logging to file disabled for this message." >&2
    fi
  fi
}

check_container_status() {
  local container_name="$1"
  local inspect_data="$2"
  local cpu_percent="$3"
  local mem_percent="$4"
  local status health_status detailed_health

  status=$(echo "$inspect_data" | jq -r '.[0].State.Status')
  health_status="not configured"
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
      detailed_health=$(echo "$inspect_data" | jq -r '.[0].State.Health | tojson')
      if [ -n "$detailed_health" ] && [ "$detailed_health" != "null" ]; then
        print_message "    Detailed Health Info: $detailed_health" "WARNING"
      fi
      return 1
    elif [ "$health_status" = "not configured" ]; then
      print_message "  Status: Running (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "GOOD"
      return 0
    else
      print_message "  Status: Running (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "WARNING"
      return 1
    fi
  fi
}

check_container_restarts() {
  local container_name="$1"
  local inspect_data="$2"
  local restart_count is_restarting

  restart_count=$(echo "$inspect_data" | jq -r '.[0].RestartCount')
  is_restarting=$(echo "$inspect_data" | jq -r '.[0].State.Restarting')

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

check_for_updates() {
    local container_name="$1"    # For messaging
    local current_image_ref="$2" # {{.Config.Image}} value, e.g., "registry.name/image:tag"
    # No longer needs $inspect_data (the container's inspect JSON) for RepoDigests

    # Declare other variables used within this function as local
    local registry_host image_path_for_skopeo tag image_name_no_tag first_part skopeo_image_ref
    local search_pattern_in_repodigests local_digest_line local_digest skopeo_output skopeo_exit_code remote_digest

    tag="latest" # Default tag

    # Handle cases where update check by tag is not applicable (same as before)
    if [[ "$current_image_ref" == *@sha256:* ]]; then
        print_message "  Update Check: Container '$container_name' is running from an image pinned by digest ($current_image_ref). Update check by tag is not applicable." "INFO"
        return 0
    fi
    if [[ "$current_image_ref" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; then
        print_message "  Update Check: Container '$container_name' is running directly from an image ID ($current_image_ref). Cannot determine registry to check for updates." "INFO"
        return 0
    fi

    # --- Image Parsing Logic (same as before) ---
    image_name_no_tag="$current_image_ref"
    if [[ "$current_image_ref" == *":"* ]]; then
        if [[ "${current_image_ref##*:}" =~ ^[0-9a-fA-F]{7,}$ && "${current_image_ref}" == *@* ]]; then
            print_message "  Update Check: Image reference '$current_image_ref' for container '$container_name' appears to be digest-pinned. Skipping tag-based update check." "INFO"
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
    # --- End of Image Parsing Logic ---

    skopeo_image_ref="docker://$registry_host/$image_path_for_skopeo:$tag"

    if ! command -v skopeo >/dev/null 2>&1; then
        print_message "  Update Check: Error - skopeo is not installed. Cannot check for updates for '$container_name'." "DANGER"
        return 1
    fi

    # --- Local Digest Retrieval (Reverted to original script's method) ---
    # We need to find a RepoDigest that matches the registry and path we are checking against.
    # $current_image_ref is the image name/tag/id docker has recorded for the container.
    # Inspecting this $current_image_ref directly should give its RepoDigests.
    search_pattern_in_repodigests="^${registry_host}/${image_path_for_skopeo}@"
    
    # Perform docker inspect on the image reference itself (current_image_ref)
    local_digest_line=$(docker inspect -f '{{range .RepoDigests}}{{.}}{{println}}{{end}}' "$current_image_ref" 2>/dev/null | grep -E "$search_pattern_in_repodigests" | head -n 1)

    local_digest="" # Initialized to empty
    if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
        local_digest="${local_digest_line##*@}"
    else
        # This message is printed if the primary search above fails
        print_message "  Update Check: No local RepoDigest found for '$current_image_ref' matching '$search_pattern_in_repodigests'. Attempting fallback using first available RepoDigest. This might be less accurate." "INFO"
        
        # Fallback: Perform another docker inspect on the image reference
        local_digest_line=$(docker inspect -f '{{index .RepoDigests 0}}' "$current_image_ref" 2>/dev/null)

        if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
            local_digest="${local_digest_line##*@}"
        fi
    fi

    if [ -z "$local_digest" ]; then
        # This message is printed if both primary and fallback fail to yield a digest
        print_message "  Update Check: Failed to determine local image digest for '$current_image_ref' ($registry_host/$image_path_for_skopeo). Image may not have suitable RepoDigests or was only built locally. Cannot check for updates." "WARNING"
        return 1
    fi
    # --- End of Local Digest Retrieval ---

    print_message "  Update Check: Checking remote image '$skopeo_image_ref' for updates..." "INFO"
    # Skopeo logic remains the same; using here-string for its jq call is fine.
    skopeo_output=$(skopeo inspect "$skopeo_image_ref" 2>&1)
    skopeo_exit_code=$?

    remote_digest=""
    if [ $skopeo_exit_code -eq 0 ]; then
        remote_digest=$(jq -r '.Digest' <<< "$skopeo_output") # Using here-string
        if [ "$remote_digest" == "null" ] || [ -z "$remote_digest" ]; then
            print_message "  Update Check: Error - skopeo inspect succeeded for '$skopeo_image_ref' but returned no digest." "DANGER"
            print_message "    Skopeo output: $skopeo_output" "INFO"
            return 1
        fi
    else
        # Error handling for skopeo (same as before)
        print_message "  Update Check: Error inspecting remote image '$skopeo_image_ref'." "DANGER"
        if echo "$skopeo_output" | grep -qiE "unauthorized|authentication required|denied|forbidden|credentials"; then
            print_message "    Error details: Authentication failed. Ensure you are logged into '$registry_host' (e.g., run 'docker login $registry_host')." "DANGER"
        elif echo "$skopeo_output" | grep -qiE "manifest unknown|not found|no such host"; then
            print_message "    Error details: Image or tag not found at remote registry, or registry host is invalid: '$skopeo_image_ref'." "DANGER"
        else
            print_message "    Skopeo command failed with exit code $skopeo_exit_code." "WARNING"
        fi
        print_message "    Full skopeo error: $skopeo_output" "INFO" # Log full error for debugging
        return 1
    fi

    print_message "  Comparing Local: $local_digest (from $current_image_ref) vs Remote: $remote_digest (from $skopeo_image_ref)" "INFO"
    if [ "$remote_digest" != "$local_digest" ]; then
        print_message "  Update Check: Update available for '$current_image_ref'!\n  Current Digest (local): $local_digest\n  New Digest (remote):    $remote_digest" "WARNING"
        return 1
    else
        print_message "  Update Check: Image '$current_image_ref' is up-to-date." "GOOD"
        return 0
    fi
}

check_logs() {
  local container_name="$1"
  local print_to_stdout="${2:-false}" # Default false
  local filter_errors="${3:-false}"   # Default false
  # LOG_LINES_TO_CHECK is a global variable, validated to be a positive integer at script start
  local raw_logs docker_logs_status logs_to_display_or_analyze issues_found_by_grep

  raw_logs=$(docker logs --tail "$LOG_LINES_TO_CHECK" "$container_name" 2>&1)
  docker_logs_status=$?

  if [ $docker_logs_status -ne 0 ]; then
    print_message "  Log Check: Error - Could not retrieve logs for '$container_name'. Docker command failed (status: $docker_logs_status)." "DANGER"
    print_message "    Docker error: $raw_logs" "INFO" # Show the actual error from Docker
    return 1 # Definite error retrieving logs
  fi

  logs_to_display_or_analyze="$raw_logs"
  issues_found_by_grep=false

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
      else # Not filtering, raw_logs had content, but somehow logs_to_display_or_analyze is empty
        echo "No log output in the last $LOG_LINES_TO_CHECK lines."
      fi
    fi
    echo "-------------------------"
  fi

  # Determine status message and return code for monitoring summary
  if [ "$filter_errors" = "true" ]; then
    # This mode is typically for direct CLI use ('logs errors ...'), not the main monitoring loop.
    # The return code here doesn't affect WARNING_OR_ERROR_CONTAINERS in the main loop directly
    # as 'logs' command exits before summary.
    if [ "$issues_found_by_grep" = "true" ]; then
      print_message "  Log Check: Errors/warnings found in recent logs (when filtering)." "WARNING"
      return 0 # Check ran, found issues as per filter.
    else
      print_message "  Log Check: No specific errors/warnings found in recent logs (when filtering)." "GOOD"
      return 0
    fi
  else
    # This is the path taken during the main monitoring loop (filter_errors=false)
    if [ -n "$raw_logs" ]; then # Logs were retrieved
      if echo "$raw_logs" | grep -q -i -E 'error|panic|fail|fatal'; then
          print_message "  Log Check: Potential errors/warnings found in recent $LOG_LINES_TO_CHECK lines. Please review." "WARNING"
          return 1 # MODIFIED: Return 1 to indicate an issue found, for summary purposes
      else
          print_message "  Log Check: Logs retrieved (last $LOG_LINES_TO_CHECK lines). No obvious widespread errors found." "GOOD"
          return 0
      fi
    else # No logs retrieved (docker logs command succeeded but returned empty output for the given tail count)
      print_message "  Log Check: No log output in last $LOG_LINES_TO_CHECK lines." "INFO"
      # This already correctly returns 1, flagging it for summary if "no logs" is considered an issue.
      return 1
    fi
  fi
}

save_logs() {
  local container_name="$1"
  local log_file_name="${container_name}_logs_$(date '+%Y-%m-%d_%H-%M-%S').log"

  if docker logs "$container_name" > "$log_file_name"; then
    print_message "Logs for container '$container_name' saved to '$log_file_name'." "GOOD"
  else
    print_message "Error saving logs for container '$container_name'. Check if container exists and is accessible." "DANGER"
  fi
}

print_summary() {
  local container_name_summary # loop variable
  if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
    print_message "------------------------ Summary of Issues Found ------------------------" "SUMMARY"
    print_message "The following containers have warnings or errors: ⚠️" "SUMMARY"
    for container_name_summary in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
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

declare -a CONTAINERS_TO_CHECK=()
declare -a WARNING_OR_ERROR_CONTAINERS=()

# Variables used in main execution block (not local because this is top-level script body)
# These were the source of `local: can only be used in a function` if 'local' was used here.
c_name="" # For 'logs' command
name_from_env=""
name_trimmed=""
inspect_json=""
stats_json=""
cpu_percent=""
mem_percent=""
current_image_ref_for_update=""
status_check_result=0
restart_check_result=0
update_check_result=0
log_check_result=0
run_monitoring=false
log_dir_final=""

if [ "$#" -gt 0 ]; then
  case "$1" in
    logs)
      if [ "$#" -eq 1 ]; then
        mapfile -t all_running_containers < <(docker container ls -q 2>/dev/null)
        if [ ${#all_running_containers[@]} -eq 0 ]; then
          print_message "No running containers found to show logs for." "INFO"
        else
          for container_id_logs in "${all_running_containers[@]}"; do
            # Removed 'local' from c_name
            c_name=$(docker container inspect -f '{{.Name}}' "$container_id_logs" | sed 's|^/||' 2>/dev/null || echo "$container_id_logs")
            check_logs "$c_name" "true" "false"
            echo "----------------------"
          done
        fi
      elif [ "$#" -eq 2 ]; then
        check_logs "$2" "true" "false"
      elif [ "$#" -eq 3 ] && [ "$2" = "errors" ]; then
        check_logs "$3" "true" "true"
      else
        print_message "Usage: $0 logs [errors] [<container_name>]" "DANGER"
        exit 1
      fi
      exit 0
      ;;
    save)
      if [ "$#" -eq 3 ] && [ "$2" = "logs" ]; then
        save_logs "$3"
      else
        print_message "Usage: $0 save logs <container_name>" "DANGER"
        exit 1
      fi
      exit 0
      ;;
    *)
      CONTAINERS_TO_CHECK=("$@")
      ;;
  esac
elif [ "$#" -eq 0 ]; then
    if [ -n "$CONTAINER_NAMES" ]; then
        IFS=',' read -r -a temp_env_names <<< "$CONTAINER_NAMES"
        for name_from_env in "${temp_env_names[@]}"; do
            # Removed 'local' from name_trimmed
            name_trimmed="${name_from_env#"${name_from_env%%[![:space:]]*}"}"
            name_trimmed="${name_trimmed%"${name_trimmed##*[![:space:]]}"}"
            if [ -n "$name_trimmed" ]; then
                CONTAINERS_TO_CHECK+=("$name_trimmed")
            fi
        done
        if [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ] && [ -n "$CONTAINER_NAMES" ]; then
            print_message "Warning: Environment variable CONTAINER_NAMES ('$CONTAINER_NAMES') was set but parsed to an empty list of containers." "WARNING"
        fi
    elif [ ${#CONTAINER_NAMES_FROM_CONFIG_FILE[@]} -gt 0 ]; then
        CONTAINERS_TO_CHECK=("${CONTAINER_NAMES_FROM_CONFIG_FILE[@]}")
    else
        mapfile -t all_running_names < <(docker container ls --format '{{.Names}}' 2>/dev/null)
        if [ ${#all_running_names[@]} -gt 0 ]; then
            CONTAINERS_TO_CHECK=("${all_running_names[@]}")
        fi
    fi
fi

# --- Main Monitoring Execution Block ---
run_monitoring=false
if [[ "$#" -gt 0 && "$1" != "logs" && "$1" != "save" ]]; then
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
        run_monitoring=true
    else
        print_message "No valid container names provided for monitoring from command line arguments." "INFO"
    fi
elif [[ "$#" -eq 0 ]]; then
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
        run_monitoring=true
    else
        print_message "No containers specified or found running to monitor." "INFO"
    fi
fi

if [ "$run_monitoring" = "true" ]; then
    print_message "---------------------- Docker Container Monitoring Results ----------------------" "INFO"
    for container_name_or_id in "${CONTAINERS_TO_CHECK[@]}"; do
        print_message "Container: ${container_name_or_id}" "INFO"

        # Removed 'local' from inspect_json
        inspect_json=$(docker inspect "$container_name_or_id" 2>/dev/null)

        if [ -z "$inspect_json" ]; then
            print_message "  Status: Container '${container_name_or_id}' not found or inspect failed." "DANGER"
            WARNING_OR_ERROR_CONTAINERS+=("$container_name_or_id")
            echo "-------------------------------------------------------------------------"
            continue
        fi

        # Removed 'local' from stats_json, cpu_percent, mem_percent
        stats_json=$(docker stats --no-stream --format '{{json .}}' "$container_name_or_id" 2>/dev/null)
        cpu_percent="N/A"
        mem_percent="N/A"
        if [ -n "$stats_json" ]; then
            cpu_percent=$(echo "$stats_json" | jq -r '.CPUPerc // "N/A"')
            mem_percent=$(echo "$stats_json" | jq -r '.MemPerc // "N/A"')
        else
            print_message "  Resource Usage: Could not retrieve stats for '$container_name_or_id'." "WARNING"
        fi

        check_container_status "$container_name_or_id" "$inspect_json" "$cpu_percent" "$mem_percent"
        status_check_result=$?

        check_container_restarts "$container_name_or_id" "$inspect_json"
        restart_check_result=$?

        # Removed 'local' from current_image_ref_for_update
        current_image_ref_for_update=$(echo "$inspect_json" | jq -r '.[0].Config.Image')
        check_for_updates "$container_name_or_id" "$current_image_ref_for_update" "$inspect_json"
        update_check_result=$?

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
if [ -n "$LOG_FILE" ]; then
  log_dir_final=$(dirname "$LOG_FILE")
  if [ ! -d "$log_dir_final" ]; then
    mkdir -p "$log_dir_final"
    if [ $? -ne 0 ]; then
      echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Could not create log directory '$log_dir_final'. Logging to file will be disabled."
      LOG_FILE=""
    fi
  fi

  if [ -n "$LOG_FILE" ] && ! [ -f "$LOG_FILE" ]; then
    touch "$LOG_FILE"
    if [ $? -ne 0 ]; then
      echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Could not create log file '$LOG_FILE'. Logging to file will be disabled for this run."
      LOG_FILE=""
    else
      echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} Log file '$LOG_FILE' created."
    fi
  fi
fi

print_message "Docker monitoring script completed." "INFO"
exit 0
