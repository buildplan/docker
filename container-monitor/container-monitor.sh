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
  if docker inspect "$container_name" | jq -e '.State.Health' >/dev/null 2>&1; then
    health_status=$(docker inspect -f '{{.State.Health.Status}}' "$container_name")
  fi

  local cpu_percent=$(docker stats --no-stream --format '{{.CPU}}' "$container_name" 2>/dev/null)
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
    local image_name=$(docker inspect -f '{{.Config.Image}}' "$container_name")

    local registry=""
    local full_image_name=""
    local image=""
    local tag="latest"

    if [[ "$image_name" =~ (.+/)?([^:]+)(:(.+))? ]]; then
      registry="${BASH_REMATCH[1]}"
      image="${BASH_REMATCH[2]}"
      tag="${BASH_REMATCH[4]:-latest}"
    fi
    registry=${registry%/}

    if [ -z "$registry" ]; then
      registry="registry-1.docker.io"
      full_image_name="library/$image"
    else
      full_image_name="$image"
    fi

    if ! command -v skopeo >/dev/null 2>&1; then
      print_message "  Update Check: Error - skopeo is not installed." "DANGER"
      return 1
    fi

    local local_digest=$(docker inspect -f '{{index .RepoDigests 0}}' "$image_name" | cut -d '@' -f 2)
    remote_digest=$(skopeo inspect "docker://$registry/$full_image_name:$tag" | jq -r '.Digest')

    if [ -z "$remote_digest" ] || [ -z "$local_digest" ]; then
        print_message "  Update Check: Error - while checking for updates." "DANGER"
        return 1;
    fi

    if [ "$remote_digest" != "$local_digest" ]; then
      print_message "  Update Check: Update available!\n    Current: $local_digest\n    New: $remote_digest" "WARNING"
      return 1
    else
      print_message "  Update Check: No updates available. Current digest is up-to-date." "GOOD"
      return 0
    fi
}

check_logs() {
  local container_name="$1"
  local print_to_stdout="${2:-false}"
  local last_check_time

  if [ -f "last_log_check_time_$container_name" ]; then
    last_check_time=$(cat "last_log_check_time_$container_name")
  else
    last_check_time=$(date -d '10 minutes ago' '+%Y-%m-%dT%H:%M:%S')
  fi

  local logs=$(docker logs --since "$last_check_time" "$container_name" 2>&1)

  if [ $? -ne 0 ]; then
    print_message "  Log Check: Error - Could not retrieve logs." "DANGER"
    return 1
  fi

  if [ "$print_to_stdout" = "true" ]; then
    echo "Logs for container '$container_name' since $last_check_time:"
    echo "$logs"
    echo "-------------------------"
  fi

  if echo "$logs" | grep -i -E 'error|warning' >/dev/null; then
    print_message "  Log Check: Errors/Warnings found in logs since $last_check_time." "WARNING"
    return 1
  else
    print_message "  Log Check: No errors or warnings found in logs since $last_check_time." "GOOD"
    return 0
  fi

  date '+%Y-%m-%dT%H:%M:%S' > "last_log_check_time_$container_name"
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
        echo "Usage: $0 logs [container_name]"
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
