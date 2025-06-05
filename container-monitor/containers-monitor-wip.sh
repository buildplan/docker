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
_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK=20
_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES=360
_SCRIPT_DEFAULT_LOG_FILE="$(cd "$(dirname "$0")" && pwd)/docker-monitor.log"
declare -a _SCRIPT_DEFAULT_CONTAINER_NAMES_ARRAY=()

LOG_LINES_TO_CHECK="$_SCRIPT_DEFAULT_LOG_LINES_TO_CHECK"
CHECK_FREQUENCY_MINUTES="$_SCRIPT_DEFAULT_CHECK_FREQUENCY_MINUTES"
LOG_FILE="$_SCRIPT_DEFAULT_LOG_FILE"
declare -a CONTAINER_NAMES_FROM_CONFIG_FILE=()

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

LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK:-$LOG_LINES_TO_CHECK}"
CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES:-$CHECK_FREQUENCY_MINUTES}"
LOG_FILE="${LOG_FILE:-$LOG_FILE}"

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} Docker command not found. Please install Docker." >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo -e "${COLOR_RED}[FATAL]${COLOR_RESET} jq command not found. Please install jq." >&2
    exit 1
fi
# skopeo check will be done within the function that needs it.

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
      return 1 # Or 0 if this intermediate health status is acceptable
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
    local container_name="$1"
    local current_image_ref="$2" # {{.Config.Image}} value, e.g., "registry.name/image:tag"
    # The third argument $inspect_data for RepoDigests is no longer directly needed here with the refined local digest logic

    local registry_host image_path_for_skopeo current_tag image_name_no_tag first_part skopeo_image_ref_for_digest
    local search_pattern_in_repodigests local_digest_line local_digest skopeo_output_digest skopeo_exit_code_digest remote_digest
    local update_for_pinned_tag_found=0 # 0 = no update for pinned tag, 1 = update found for pinned tag
    local newer_version_tag_found=0   # 0 = no newer version tag, 1 = newer version tag found

    if ! command -v skopeo >/dev/null 2>&1; then
        print_message "  Update Check: Error - skopeo is not installed. Cannot check for updates for '$container_name'." "DANGER"
        return 1 # skopeo is critical for this function
    fi
    if ! command -v sort >/dev/null 2>&1 || ! sort --version-sort --help >/dev/null 2>&1; then
        print_message "  Update Check: Error - 'sort --version-sort' is not available. Cannot compare version tags." "DANGER"
        # Depending on strictness, you might return 1 here or allow digest check to proceed
    fi


    # --- Initial checks for applicability ---
    if [[ "$current_image_ref" == *@sha256:* ]]; then
        print_message "  Update Check: Container '$container_name' is running an image pinned by digest ($current_image_ref). Tag-based checks not applicable." "INFO"
        return 0
    fi
    if [[ "$current_image_ref" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; then
        print_message "  Update Check: Container '$container_name' is running directly from an image ID ($current_image_ref). Cannot determine registry." "INFO"
        return 0
    fi

    # --- Image Parsing Logic ---
    current_tag="latest" # Default tag
    image_name_no_tag="$current_image_ref"
    if [[ "$current_image_ref" == *":"* ]]; then
        # Guard against short digests being misinterpreted as tags if image name contains '@'
        if [[ "${current_image_ref##*:}" =~ ^[0-9a-fA-F]{7,}$ && "${current_image_ref}" == *@* && !("${current_image_ref##*:}" =~ ^[0-9]+(\.[0-9]+){0,2}(-.+)?$) ]]; then
            print_message "  Update Check: Image reference '$current_image_ref' for '$container_name' looks digest-pinned. Skipping tag-based checks." "INFO"
            return 0
        fi
        current_tag="${current_image_ref##*:}"
        image_name_no_tag="${current_image_ref%:*}"
    fi

    # Determine registry and image path for skopeo
    if [[ "$image_name_no_tag" == *"/"* ]]; then
        first_part=$(echo "$image_name_no_tag" | cut -d'/' -f1)
        if [[ "$first_part" == *"."* ]] || [[ "$first_part" == "localhost" ]] || [[ "$first_part" == *":"* ]]; then
            registry_host="$first_part"
            image_path_for_skopeo=$(echo "$image_name_no_tag" | cut -d'/' -f2-)
        else # No domain in first part, assume Docker Hub
            registry_host="registry-1.docker.io"
            image_path_for_skopeo="$image_name_no_tag" # This might need "library/" prepended for official images
            if [[ "$image_name_no_tag" != *"/"* ]]; then # If it's an official image like "alpine"
                 image_path_for_skopeo="library/$image_name_no_tag"
            fi
        fi
    else # Single name, assume official Docker Hub image
        registry_host="registry-1.docker.io"
        image_path_for_skopeo="library/$image_name_no_tag"
    fi
    skopeo_image_ref_for_digest="docker://$registry_host/$image_path_for_skopeo:$current_tag"

    # --- 1. Check for updates to the PINNED TAG (Digest Check) ---
    print_message "  Pinned Tag Update Check: Checking remote for '$skopeo_image_ref_for_digest'..." "INFO"
    search_pattern_in_repodigests="^${registry_host}/${image_path_for_skopeo}@"
    local_digest_line=$(docker inspect -f '{{range .RepoDigests}}{{.}}{{println}}{{end}}' "$current_image_ref" 2>/dev/null | grep -E "$search_pattern_in_repodigests" | head -n 1)
    local_digest=""
    if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
        local_digest="${local_digest_line##*@}"
    fi

    if [ -z "$local_digest" ]; then
        # Fallback if specific repo digest not found, try any repo digest
        local_digest_line=$(docker inspect -f '{{index .RepoDigests 0}}' "$current_image_ref" 2>/dev/null)
         if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
            local_digest="${local_digest_line##*@}"
            print_message "    Local Digest: Using fallback RepoDigest: $local_digest (less specific)" "INFO"
        else
            print_message "    Local Digest: Failed to determine local image digest for '$current_image_ref'. Cannot perform digest check for pinned tag." "WARNING"
            # We can still proceed to check for newer version tags if applicable
        fi
    else
        print_message "    Local Digest: $local_digest (for $current_tag)" "INFO"
    fi

    if [ -n "$local_digest" ]; then # Only proceed if we have a local digest
        skopeo_output_digest=$(skopeo inspect "$skopeo_image_ref_for_digest" 2>&1)
        skopeo_exit_code_digest=$?
        remote_digest=""
        if [ $skopeo_exit_code_digest -eq 0 ]; then
            remote_digest=$(jq -r '.Digest' <<< "$skopeo_output_digest")
            if [ "$remote_digest" == "null" ] || [ -z "$remote_digest" ]; then
                print_message "    Remote Digest: Skopeo inspect for '$skopeo_image_ref_for_digest' gave no digest." "WARNING"
            else
                 print_message "    Remote Digest: $remote_digest (for $current_tag)" "INFO"
            fi
        else
            print_message "    Remote Digest: Error inspecting '$skopeo_image_ref_for_digest'." "WARNING"
            # Log details as before, but don't exit the whole function yet
            if echo "$skopeo_output_digest" | grep -qiE "unauthorized|authentication|denied|forbidden"; then
                print_message "      Error details: Authentication failed for '$registry_host'." "WARNING"
            elif echo "$skopeo_output_digest" | grep -qiE "manifest unknown|not found|no such host"; then
                print_message "      Error details: Image or tag not found at remote: '$skopeo_image_ref_for_digest'." "WARNING"
            else
                print_message "      Skopeo failed (code $skopeo_exit_code_digest): ${skopeo_output_digest%%$'\n'*}" "WARNING" # First line of error
            fi
        fi

        if [ -n "$remote_digest" ] && [ "$remote_digest" != "$local_digest" ]; then
            print_message "  Pinned Tag Update Check: Update available for your pinned tag '$current_image_ref'!\n    Current Digest (local): $local_digest\n    New Digest (remote):    $remote_digest" "WARNING"
            update_for_pinned_tag_found=1
        elif [ -n "$remote_digest" ]; then # Implies remote_digest == local_digest
            print_message "  Pinned Tag Update Check: Your pinned tag '$current_image_ref' is up-to-date (digests match)." "GOOD"
        fi
    fi # End of local_digest check block

    # --- 2. Check for NEWER VERSION TAGS (e.g., 1.1 vs 1.2) ---
    # This check is most relevant if current_tag looks like a version number and is not 'latest'.
    # Basic check for version-like tags (e.g., X.Y, X.Y.Z, allow -suffix)
    if [[ "$current_tag" != "latest" && "$current_tag" =~ ^[0-9]+(\.[0-9]+){0,2}(-.+)?$ ]]; then
        print_message "  Newer Version Tag Check: Listing tags for '$registry_host/$image_path_for_skopeo'..." "INFO"
        local skopeo_list_tags_ref="docker://$registry_host/$image_path_for_skopeo"
        local remote_tags_json remote_tags_list skopeo_list_exit_code
        
        remote_tags_json=$(skopeo list-tags "$skopeo_list_tags_ref" 2>&1)
        skopeo_list_exit_code=$?

        if [ $skopeo_list_exit_code -ne 0 ]; then
            print_message "    Newer Version Tag Check: Failed to list tags for '$skopeo_list_tags_ref'." "WARNING"
            if echo "$remote_tags_json" | grep -qiE "unauthorized|authentication|denied|forbidden"; then
                 print_message "      Error details: Authentication failed for '$registry_host'." "WARNING"
            elif echo "$remote_tags_json" | grep -qiE "not found|no such host"; then # repository not found
                 print_message "      Error details: Repository not found or host invalid: '$skopeo_list_tags_ref'." "WARNING"
            else
                 print_message "      Skopeo list-tags failed (code $skopeo_list_exit_code): ${remote_tags_json%%$'\n'*}" "WARNING"
            fi
        else
            # Parse tags, filter for valid-looking versions, sort, and find the highest.
            # This grep aims for X.Y or X.Y.Z, possibly with suffixes like -alpine, -rc1
            # It's not perfect for all semver but good for common cases.
            # Exclude the current tag itself from the list of candidates for "newer".
            highest_remote_version_tag=$(echo "$remote_tags_json" | jq -r '.Tags[]' 2>/dev/null | \
                grep -E '^[0-9]+(\.[0-9]+){1,2}(-.+)?$' | \
                grep -vE "^${current_tag}$" | \
                sort -V | tail -n 1) # Get the highest version tag

            if [[ -n "$highest_remote_version_tag" ]]; then
                # Now compare current_tag with highest_remote_version_tag using sort -V
                # If current_tag sorts before highest_remote_version_tag, then highest is newer.
                # (printf "%s\n%s" item1 item2 | sort -V | head -n1) gives the "smaller" version
                local sorted_first
                sorted_first=$(printf "%s\n%s" "$current_tag" "$highest_remote_version_tag" | sort -V | head -n 1)

                if [[ "$sorted_first" == "$current_tag" && "$current_tag" != "$highest_remote_version_tag" ]]; then
                    print_message "  Newer Version Tag Check: Newer version '$highest_remote_version_tag' found for '$image_name_no_tag' (you are on '$current_tag')." "WARNING"
                    newer_version_tag_found=1
                else
                    print_message "  Newer Version Tag Check: No clearly newer semantic version tag found than '$current_tag'." "GOOD"
                fi
            else
                print_message "  Newer Version Tag Check: No other semantic version tags found to compare against '$current_tag'." "INFO"
            fi
        fi
    else
        if [[ "$current_tag" == "latest" ]]; then
             print_message "  Newer Version Tag Check: Skipped for 'latest' tag (pinned tag digest check covers 'latest')." "INFO"
        elif ! [[ "$current_tag" =~ ^[0-9]+(\.[0-9]+){0,2}(-.+)?$ ]]; then # If not like a version
             print_message "  Newer Version Tag Check: Skipped as current tag '$current_tag' does not appear to be a semantic version." "INFO"
        fi
    fi

    # --- Final Result ---
    if [ $update_for_pinned_tag_found -eq 1 ] || [ $newer_version_tag_found -eq 1 ]; then
        # If either check found something, return 1 (issue/update)
        return 1
    else
        # If both checks passed or were not applicable in a way that signals an issue
        if [ -z "$local_digest" ] && [[ "$current_tag" != "latest" && ! ("$current_tag" =~ ^[0-9]+(\.[0-9]+){0,2}(-.+)?$) ]]; then
            # If we couldn't get local_digest AND we didn't do a version check (e.g. tag was 'stable')
            # This path indicates uncertainty rather than "good"
            print_message "  Update Check: Overall status for '$current_image_ref' is uncertain due to missing local digest and non-versioned tag." "INFO"
            return 0 # Or 1 if uncertainty should be flagged
        elif [ -z "$local_digest" ] && [ $newer_version_tag_found -eq 0 ]; then
            # Could not get local digest, but newer version check ran and found nothing.
            # Still, the primary pinned tag check was inconclusive.
            print_message "  Update Check: Pinned tag digest check inconclusive, but no newer semantic version tags found." "INFO"
            return 0 # Or 1 to flag the inconclusive digest check
        fi
        # Otherwise, if we are here, it means either digest check was good and no newer tag,
        # or one of the checks was N/A but the other was good.
        return 0
    fi
}


check_logs() {
  local container_name="$1"
  local print_to_stdout="${2:-false}" # Default false
  local filter_errors="${3:-false}"   # Default false
  local raw_logs docker_logs_status logs_to_display_or_analyze issues_found_by_grep

  raw_logs=$(docker logs --tail "$LOG_LINES_TO_CHECK" "$container_name" 2>&1)
  docker_logs_status=$?

  if [ $docker_logs_status -ne 0 ]; then
    print_message "  Log Check: Error - Could not retrieve logs for '$container_name'. Docker command failed (status: $docker_logs_status)." "DANGER"
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
      echo "Filtered logs (errors/warnings) for container '$container_name' (last $LOG_LINES_TO_CHECK lines scanned):"
    else
      echo "Last $LOG_LINES_TO_CHECK log lines for container '$container_name':"
    fi

    if [ -n "$logs_to_display_or_analyze" ]; then
      echo "$logs_to_display_or_analyze"
    else
      if [ "$filter_errors" = "true" ]; then
        echo "No lines matching error patterns ('error|panic|fail|fatal') found."
      elif [ -z "$raw_logs" ]; then
        echo "No log output in the last $LOG_LINES_TO_CHECK lines."
      else
        echo "No log output in the last $LOG_LINES_TO_CHECK lines." # Fallback
      fi
    fi
    echo "-------------------------"
  fi

  # Determine status message and return code for monitoring summary
  if [ "$filter_errors" = "true" ]; then
    if [ "$issues_found_by_grep" = "true" ]; then
      print_message "  Log Check: Errors/warnings found in recent logs (when filtering)." "WARNING"
      return 0
    else
      print_message "  Log Check: No specific errors/warnings found in recent logs (when filtering)." "GOOD"
      return 0
    fi
  else # This is the path taken during the main monitoring loop
    if [ -n "$raw_logs" ]; then
      if echo "$raw_logs" | grep -q -i -E 'error|panic|fail|fatal'; then
          print_message "  Log Check: Potential errors/warnings found in recent $LOG_LINES_TO_CHECK lines. Please review." "WARNING"
          return 1
      else
          print_message "  Log Check: Logs retrieved (last $LOG_LINES_TO_CHECK lines). No obvious widespread errors found." "GOOD"
          return 0
      fi
    else
      print_message "  Log Check: No log output in last $LOG_LINES_TO_CHECK lines." "INFO" # Could be normal for some containers
      return 0 # Changed from 1; no logs isn't always an error state for monitoring. If it IS an error, other checks should catch it.
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
      print_message "- ${container_name_summary} ❌" "WARNING" # Changed from DANGER to WARNING for summary items
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

c_name=""
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
      # ... (logs handling logic remains the same) ...
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
      # ... (save logs logic remains the same) ...
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
    # ... (logic for determining containers to check from ENV or config remains the same) ...
    if [ -n "$CONTAINER_NAMES" ]; then
        IFS=',' read -r -a temp_env_names <<< "$CONTAINER_NAMES"
        for name_from_env in "${temp_env_names[@]}"; do
            name_trimmed="${name_from_env#"${name_from_env%%[![:space:]]*}"}" # trim leading
            name_trimmed="${name_trimmed%"${name_trimmed##*[![:space:]]}"}"   # trim trailing
            if [ -n "$name_trimmed" ]; then
                CONTAINERS_TO_CHECK+=("$name_trimmed")
            fi
        done
        if [ ${#CONTAINERS_TO_CHECK[@]} -eq 0 ] && [ -n "$CONTAINER_NAMES" ]; then # Guard against empty list if var was set
            print_message "Warning: Environment variable CONTAINER_NAMES ('$CONTAINER_NAMES') was set but parsed to an empty list." "WARNING"
        fi
    elif [ ${#CONTAINER_NAMES_FROM_CONFIG_FILE[@]} -gt 0 ]; then
        CONTAINERS_TO_CHECK=("${CONTAINER_NAMES_FROM_CONFIG_FILE[@]}")
    else # Default to all running containers if no other source provides names
        mapfile -t all_running_names < <(docker container ls --format '{{.Names}}' 2>/dev/null)
        if [ ${#all_running_names[@]} -gt 0 ]; then
            CONTAINERS_TO_CHECK=("${all_running_names[@]}")
        fi
    fi
fi


# --- Main Monitoring Execution Block ---
run_monitoring=false
if [[ "$#" -gt 0 && "$1" != "logs" && "$1" != "save" ]]; then # Explicit container names from args
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
        run_monitoring=true
    else
        print_message "No valid container names provided for monitoring from command line arguments." "INFO"
    fi
elif [[ "$#" -eq 0 ]]; then # No args, determined by ENV, config, or all running
    if [ ${#CONTAINERS_TO_CHECK[@]} -gt 0 ]; then
        run_monitoring=true
    else
        print_message "No containers specified or found running to monitor." "INFO"
        # If LOG_FILE is set, we might still want to finalize it.
    fi
fi


if [ "$run_monitoring" = "true" ]; then
    print_message "---------------------- Docker Container Monitoring Results ----------------------" "INFO"
    for container_name_or_id in "${CONTAINERS_TO_CHECK[@]}"; do
        print_message "Container: ${container_name_or_id}" "INFO"
        local container_actual_name="${container_name_or_id}" # For consistent naming in messages if ID was given

        inspect_json=$(docker inspect "$container_name_or_id" 2>/dev/null)
        if [ -z "$inspect_json" ]; then
            print_message "  Status: Container '${container_name_or_id}' not found or inspect failed." "DANGER"
            WARNING_OR_ERROR_CONTAINERS+=("$container_name_or_id")
            echo "-------------------------------------------------------------------------"
            continue
        fi
        # Get the actual name in case an ID was provided
        container_actual_name=$(echo "$inspect_json" | jq -r '.[0].Name' | sed 's|^/||')


        stats_json=$(docker stats --no-stream --format '{{json .}}' "$container_name_or_id" 2>/dev/null)
        cpu_percent="N/A"
        mem_percent="N/A"
        if [ -n "$stats_json" ]; then
            cpu_percent=$(echo "$stats_json" | jq -r '.CPUPerc // "N/A"')
            mem_percent=$(echo "$stats_json" | jq -r '.MemPerc // "N/A"')
        else
            print_message "  Resource Usage: Could not retrieve stats for '$container_actual_name'." "WARNING"
        fi

        check_container_status "$container_actual_name" "$inspect_json" "$cpu_percent" "$mem_percent"
        status_check_result=$?

        check_container_restarts "$container_actual_name" "$inspect_json"
        restart_check_result=$?

        current_image_ref_for_update=$(echo "$inspect_json" | jq -r '.[0].Config.Image')
        # Pass container_actual_name for clearer messaging in check_for_updates
        check_for_updates "$container_actual_name" "$current_image_ref_for_update"
        update_check_result=$?

        check_logs "$container_actual_name" "false" "false"
        log_check_result=$?

        if [ $status_check_result -ne 0 ] || \
           [ $restart_check_result -ne 0 ] || \
           [ $update_check_result -ne 0 ] || \
           [ $log_check_result -ne 0 ]; then
            WARNING_OR_ERROR_CONTAINERS+=("$container_actual_name")
        fi
        echo "-------------------------------------------------------------------------"
    done
    print_message "---------------------- End of Container Monitoring Results -------------------" "INFO"
    print_summary
fi

# --- Finalize ---
# ... (Finalize logic remains the same) ...
if [ -n "$LOG_FILE" ]; then
  log_dir_final=$(dirname "$LOG_FILE")
  if [ ! -d "$log_dir_final" ]; then
    mkdir -p "$log_dir_final"
    if [ $? -ne 0 ]; then
      echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Could not create log directory '$log_dir_final'. Logging to file will be disabled."
      LOG_FILE="" # Disable logging if dir creation fails
    fi
  fi

  # Check if LOG_FILE is writable, try to create if not exists
  if [ -n "$LOG_FILE" ]; then # Re-check as it might have been unset
    if ! touch "$LOG_FILE" &>/dev/null; then
        echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} Log file '$LOG_FILE' is not writable or cannot be created. Logging to file disabled." >&2
        LOG_FILE=""
    elif [ ! -f "$LOG_FILE" ]; then # Should have been created by touch if it didn't exist
        # This case is unlikely if touch succeeded, but as a safeguard
        echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} Log file '$LOG_FILE' created."
    fi
  fi
fi

print_message "Docker monitoring script completed." "INFO"
exit 0
