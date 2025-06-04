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
#   - CHECK_FREQUENCY_MINUTES: Frequency of checks in minutes (default: 360)
#   - LOG_FILE: Path to the log file (default: docker-monitor.log in script directory)
#   - CONTAINER_NAMES: Comma-separated list of container names to monitor.
#                      Overrides the CONTAINER_NAMES_DEFAULT array in config.sh.
#                      If not set and CONTAINER_NAMES_DEFAULT is empty in config.sh,
#                      all running containers will be monitored by default.
#
# Usage:
#   ./docker-container-monitor.sh                  - Monitor containers based on config (or all running if config is empty)
#   ./docker-container-monitor.sh <container_name1> <container_name2> ... - Monitor specific containers
#   ./docker-container-monitor.sh logs             - Show logs for all running containers
#   ./docker-container-monitor.sh logs <container_name> - Show logs for a specific container
#   ./docker-container-monitor.sh logs errors <container_name> - Show errors in logs for a specific container
#   ./docker-container-monitor.sh save logs <container_name> - Save logs for a specific container to a file
#
# Prerequisites:
#   - Docker
#   - jq (for processing JSON output from docker inspect and docker stats)
#   - skopeo (for checking for container image updates)
#   - (Optional) numfmt: for human-readable formatting in future enhancements (not currently used)

# --- Source Configuration File (for defaults and documentation) ---
CONFIG_FILE="./config.sh"
if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  echo "Warning: Configuration file '$CONFIG_FILE' not found, using environment variables or script defaults."
  # Continue without config.sh, relying on ENV vars or hardcoded defaults
fi

# --- ANSI Color Codes ---
COLOR_RESET="\033[0m"
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_CYAN="\033[0;36m"
COLOR_MAGENTA="\033[0;35m" # Magenta for Summary

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
    echo "${message}"
    log_output_no_color="${message}" # No prefix for log file
  else
    local colored_message="${color_code}[${color_type}]${COLOR_RESET} ${message}"
    echo -e "${colored_message}" # Output to terminal with color
    log_output_no_color="[${color_type}] ${message}" # Prefix for log file
  fi

  # Log to file (append mode)
  if [ -n "$LOG_FILE" ]; then # Check if LOG_FILE is defined and not empty
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${log_output_no_color}" >> "$LOG_FILE"
  fi
}

check_container_status() {
  local container_name="$1"
  local status=$(docker inspect -f '{{.State.Status}}' "$container_name" 2>/dev/null)

  if [ -z "$status" ]; then
    print_message "  Status: Container not found" "DANGER"
    return 1
  fi

  local health_status="not configured"
  if docker inspect "$container_name" | jq -e '.[0].State.Health' >/dev/null 2>&1; then
    health_status=$(docker inspect -f '{{.State.Health.Status}}' "$container_name")
  fi

  local cpu_percent=$(docker stats --no-stream --format '{{.CPUPerc}}' "$container_name" 2>/dev/null)
  local mem_percent=$(docker stats --no-stream --format '{{.MemPerc}}' "$container_name" 2>/dev/null)

  if [ "$status" != "running" ]; then
    print_message "  Status: Not running (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "DANGER"
    return 1
  else
    if [ "$health_status" = "healthy" ]; then
      print_message "  Status: Running and healthy (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "GOOD"
      return 0
    elif [ "$health_status" = "unhealthy" ]; then
      print_message "  Status: Running but UNHEALTHY (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "DANGER"
      detailed_health=$(docker inspect -f '{{json .State.Health}}' "$container_name" 2>/dev/null)
      if [ -n "$detailed_health" ]; then
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
  local restart_count=$(docker inspect -f '{{.RestartCount}}' "$container_name" 2>/dev/null)
  local is_restarting=$(docker inspect -f '{{.State.Restarting}}' "$container_name" 2>/dev/null)

  if [ "$is_restarting" = "true" ]; then
    print_message "  Restart Status: Container is currently restarting." "WARNING"
  elif [ "$restart_count" -gt 0 ]; then
    print_message "  Restart Status: Container has restarted $restart_count times." "WARNING"
  else
    print_message "  Restart Status: No unexpected restarts detected." "GOOD"
  fi
}

check_for_updates() {
    local container_name="$1"
    # This is the image reference used to start the container, e.g., my.server/image:tag, image:tag, or a SHA ID.
    local current_image_ref
    current_image_ref=$(docker inspect -f '{{.Config.Image}}' "$container_name")

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
    local tag="latest"         # Default tag

    local image_name_no_tag="$current_image_ref"
    if [[ "$current_image_ref" == *":"* ]]; then
        # Check if the part after the last colon looks like a digest (common if image is referenced by name and digest)
        # This is a basic check; actual digest-pinning is handled by the @sha256 check above.
        if [[ "${current_image_ref##*:}" =~ ^[0-9a-fA-F]{7,}$ && "${current_image_ref}" == *@* ]]; then # Heuristic for something like image@sha256:digest_prefix
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
            registry_host="registry-1.docker.io"
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
    # $current_image_ref is the image name/tag/id docker has recorded for the container.
    # Inspecting this ref should give its RepoDigests.
    local_digest_line=$(docker inspect -f '{{range .RepoDigests}}{{.}}{{println}}{{end}}' "$current_image_ref" 2>/dev/null | grep -E "$search_pattern_in_repodigests" | head -n 1)

    local local_digest=""
    if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
        local_digest="${local_digest_line##*@}"
    else
        # Fallback: If no specific RepoDigest matches (e.g. image was retagged, or registry name in RepoDigest differs slightly like docker.io vs registry-1.docker.io)
        # Try to get the first available RepoDigest. This is less precise.
        print_message "  Update Check: No local RepoDigest found for '$current_image_ref' matching '$search_pattern_in_repodigests'. Using first available RepoDigest for comparison. This might be less accurate." "INFO"
        local_digest_line=$(docker inspect -f '{{index .RepoDigests 0}}' "$current_image_ref" 2>/dev/null)
        if [[ -n "$local_digest_line" && "$local_digest_line" == *@* ]]; then
            local_digest="${local_digest_line##*@}"
        fi
    fi

    if [ -z "$local_digest" ]; then
        print_message "  Update Check: Failed to determine local image digest for '$current_image_ref' ($registry_host/$image_path_for_skopeo). Image may not have RepoDigests or was perhaps only built locally. Cannot check for updates." "WARNING"
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
        print_message "  Update Check: Update available for '$current_image_ref'!\n    Current Digest (local): $local_digest\n    New Digest (remote):    $remote_digest" "WARNING"
        return 1 # Indicates an update is available, treated as a "warning" for summary
    else
        print_message "  Update Check: Image '$current_image_ref' is up-to-date." "GOOD"
        return 0 # No update needed
    fi
}

check_logs() {
  local container_name="$1"
  local print_to_stdout="${2:-false}"
  local filter_errors="${3:-false}"

  local logs=""
  if [ "$filter_errors" = "true" ]; then
    logs=$(docker logs "$container_name" 2>&1 | grep -i -E 'error|panic|fail|fatal')
  else
    logs=$(docker logs --tail "$LOG_LINES_TO_CHECK" "$container_name" 2>&1)
  fi

  if [ $? -ne 0 ]; then
    print_message "  Log Check: Error - Could not retrieve logs." "DANGER"
    return 1
  fi

  if [ "$print_to_stdout" = "true" ]; then
    if [ "$filter_errors" = "true" ]; then
      echo "Errors in logs for container '$container_name':"
    else
      echo "Logs for container '$container_name':"
    fi
    echo "$logs"
    echo "-------------------------"
  fi

  if [ -n "$logs" ]; then
    if [ "$filter_errors" = "true" ]; then
      print_message "  Log Check: Errors found in logs." "WARNING"
    else
      print_message "  Log Check: No errors found in last $LOG_LINES_TO_CHECK log lines." "GOOD"
    fi
    return 0
  else
    print_message "  Log Check: No logs available." "INFO"
    return 1
  fi
}

save_logs() {
  local container_name="$1"
  local log_file="${container_name}_logs_$(date '+%Y-%m-%d_%H-%M-%S').log"

  docker logs "$container_name" > "$log_file"
  if [ $? -eq 0 ]; then
    print_message "Logs for container '$container_name' saved to '$log_file'." "GOOD"
  else
    print_message "Error saving logs for container '$container_name'." "DANGER"
  fi
}

print_summary() {
  if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
    print_message "------------------------ Summary of Issues Found ------------------------" "SUMMARY"
    print_message "The following containers have warnings or errors: ⚠️" "SUMMARY"
    for container_name in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
      print_message "- ${container_name} ❌" "WARNING"
    done
    print_message "------------------------------------------------------------------------" "SUMMARY"
  else
    print_message "------------------------ Summary of Issues Found ------------------------" "SUMMARY"
    print_message "No issues found in any monitored containers. All containers are running, healthy, and up-to-date. ✅" "GOOD"
    print_message "------------------------------------------------------------------------" "SUMMARY"
  fi
}

# --- Main Execution ---

CONTAINERS_TO_CHECK=()
WARNING_OR_ERROR_CONTAINERS=()

if [ "$#" -gt 0 ]; then
  case "$1" in
    logs)
      if [ "$#" -eq 2 ]; then
        check_logs "$2" "true"
      elif [ "$#" -eq 3 ] && [ "$2" = "errors" ]; then
        check_logs "$3" "true" "true"
      elif [ "$#" -eq 1 ]; then
        CONTAINERS_TO_CHECK=$(docker container ls -q)
        if [ -z "$CONTAINERS_TO_CHECK" ]; then
          print_message "No running containers found." "INFO"
        else
          for container_id in $CONTAINERS_TO_CHECK; do
            container_name=$(docker container inspect -f '{{.Name}}' "$container_id" | sed 's|^/||')
            check_logs "$container_name" "true"
            echo "----------------------"
          done
        fi
      else
        echo "Usage: $0 logs [errors] <container_name>"
        exit 1
      fi
      ;;
    save)
      if [ "$#" -eq 3 ] && [ "$2" = "logs" ]; then
        save_logs "$3"
      else
        echo "Usage: $0 save logs <container_name>"
        exit 1
      fi
      ;;
    *)
      CONTAINERS_TO_CHECK=("$@")
      ;;
  esac
else
  if [ ${#CONTAINER_NAMES[@]} -gt 0 ]; then
    CONTAINERS_TO_CHECK=("${CONTAINER_NAMES[@]}")
  else
    CONTAINERS_TO_CHECK=$(docker container ls --format '{{.Names}}')
    if [ -z "$CONTAINERS_TO_CHECK" ]; then
      print_message "No running containers found." "INFO"
      exit 0
    fi
  fi
fi

if [ "$#" -eq 0 ] || [ "$1" != "logs" ] && [ "$1" != "save" ]; then
  if [ -z "$CONTAINERS_TO_CHECK" ] && [ "$#" -eq 0 ]; then
      print_message "No running containers found to monitor." "INFO"
  else
    print_message "---------------------- Docker Container Monitoring Results ----------------------" "INFO"
    for container_name in "${CONTAINERS_TO_CHECK[@]}"; do
      print_message "Container: ${container_name}" "INFO"
      check_container_status "$container_name"
      status_check_result=$?
      check_container_restarts "$container_name"
      restart_check_result=$?
      check_for_updates "$container_name"
      update_check_result=$?
      check_logs "$container_name"
      log_check_result=$?

      if [ $status_check_result -ne 0 ] || [ $restart_check_result -ne 0 ] || [ $update_check_result -ne 0 ] || [ $log_check_result -ne 0 ]; then
        WARNING_OR_ERROR_CONTAINERS+=("$container_name")
      fi

      echo "-------------------------------------------------------------------------"
    done
    print_message "---------------------- End of Container Monitoring Results -------------------" "INFO"
    print_summary
  fi
fi

if [ -n "$LOG_FILE" ]; then
  if ! [ -f "$LOG_FILE" ]; then
    touch "$LOG_FILE"
    if [ $? -ne 0 ]; then
      echo "Error: Could not create log file '$LOG_FILE'. Logging to file will be disabled for this run."
      LOG_FILE=""
    else
      echo "Log file '$LOG_FILE' created."
    fi
  fi
fi

print_message "Docker monitoring script completed." "INFO"
exit 0
