#!/bin/bash

# Description:
# This script monitors Docker containers on the system.
# It checks container status, resource usage (CPU, Memory),
# checks for image updates, and checks container logs.
# Output is printed to the standard output with improved formatting and colors and logged to a file.
#
# Usage:
#   ./docker-container-monitor.sh                                          - Monitor all running containers (status, updates, logs)
#   ./docker-container-monitor.sh <container_name1> <container_name2> ...  - Monitor specific containers
#   ./docker-container-monitor.sh logs                                     - Show logs for all running containers
#   ./docker-container-monitor.sh logs <container_name>                    - Show logs for a specific container
#
# Prerequisites:
#   - Docker
#   - jq (for processing JSON output from docker inspect and docker stats)
#   - skopeo (for checking for container image updates)
#   - config.sh in the same dir

# --- Source Configuration File ---
CONFIG_FILE="./config.sh"
if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  echo "Error: Configuration file '$CONFIG_FILE' not found. Please create it."
  exit 1
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

  # --- Corrected CPU and Memory retrieval using .CPU and .MemPerc ---
  local cpu_percent=$(docker stats --no-stream --format '{{.CPU}}' "$container_name" 2>/dev/null)
  local mem_percent=$(docker stats --no-stream --format '{{.MemPerc}}' "$container_name" 2>/dev/null)
  # --- End of Modified section ---


  if [ "$status" != "running" ]; then
    print_message "  Status: Not running (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "DANGER"
    return 1
  else
    if [ "$health_status" = "healthy" ]; then
      print_message "  Status: Running and healthy (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "GOOD"
    elif [ "$health_status" = "unhealthy" ]; then
      print_message "  Status: Running but UNHEALTHY (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "DANGER"
      detailed_health=$(docker inspect -f '{{json .State.Health}}' "$container_name" 2>/dev/null)
      if [ -n "$detailed_health" ]; then
        print_message "    Detailed Health Info: $detailed_health" "WARNING" # More details in warning color
      fi
    else
      print_message "  Status: Running (Status: $status, Health: $health_status, CPU: $cpu_percent, Mem: $mem_percent)" "WARNING"
    fi
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
    else
      print_message "  Update Check: No updates available. Current digest is up-to-date." "GOOD"
    fi
}

check_logs() {
  local container_name="$1"
  local print_to_stdout="${2:-false}"

  local logs=$(docker logs --tail "$LOG_LINES_TO_CHECK" "$container_name" 2>&1)

  if [ $? -ne 0 ]; then
    print_message "  Log Check: Error - Could not retrieve logs." "DANGER"
    return 1  # Important: Return an error code
  fi

  if [ "$print_to_stdout" = "true" ]; then
      echo "Logs for container '$container_name':"
      echo "$logs"
      echo "-------------------------"
  fi

  if echo "$logs" | grep -i -E 'error|warning' >/dev/null; then
    print_message "  Log Check: Errors/Warnings found in logs." "WARNING"
  else
      print_message "  Log Check: No errors or warnings found in last $LOG_LINES_TO_CHECK log lines." "GOOD"
  fi
}

# --- Main Execution ---

CONTAINERS_TO_CHECK=()
WARNING_OR_ERROR_CONTAINERS=() # Array to track containers with warnings or errors

if [ "$#" -gt 0 ]; then
  case "$1" in
    logs)
      if [ "$#" -eq 2 ]; then  # Check logs for a specific container
        check_logs "$2" "true"
      elif [ "$#" -eq 1 ]; then # Check logs for all running containers
        CONTAINERS_TO_CHECK=$(docker container ls -q) # Get all running container IDs
        if [ -z "$CONTAINERS_TO_CHECK" ]; then
          print_message "No running containers found." "INFO"
        else
          for container_id in $CONTAINERS_TO_CHECK; do
            container_name=$(docker container inspect -f '{{.Name}}' "$container_id" | sed 's|^/||') # Get name from ID, remove leading /
            check_logs "$container_name" "true"
            echo "----------------------" # Separator after each container's logs
          done
        fi
      else
        echo "Usage: $0 logs [container_name]"
        exit 1
      fi
      ;;
    *) # Treat all arguments as container names to monitor
      CONTAINERS_TO_CHECK=("$@")
      ;;
  esac
else # No arguments, monitor containers from config file or all running if config is empty
  if [ ${#CONTAINER_NAMES[@]} -gt 0 ]; then
    CONTAINERS_TO_CHECK=("${CONTAINER_NAMES[@]}") # Use containers from config if defined
  else
    CONTAINERS_TO_CHECK=$(docker container ls -q) # Get all running container IDs if config is empty
    if [ -z "$CONTAINERS_TO_CHECK" ]; then
      print_message "No running containers found." "INFO"
      exit 0 # Exit gracefully if no containers to check
    fi
  fi
fi


if [ "$#" -eq 0 ] || [ "$1" != "logs" ]; then # Run full monitoring unless only 'logs' is specified
  if [ -z "$CONTAINERS_TO_CHECK" ] && [ "$#" -eq 0 ]; then
      print_message "No running containers found to monitor." "INFO"
  else
    print_message "---------------------- Docker Container Monitoring Results ----------------------" "INFO"
    for container_name in "${CONTAINERS_TO_CHECK[@]}"; do
      print_message "Container: ${container_name}" "INFO"
      check_container_status "$container_name"
      status_check_result=$? # Capture exit status of check_container_status
      check_for_updates "$container_name"
      update_check_result=$? # Capture exit status of check_for_updates
      check_logs "$container_name"
      log_check_result=$? # Capture exit status of check_logs

      # Check if any of the checks for this container resulted in a warning or error (non-zero exit code)
      if [ $status_check_result -ne 0 ] || [ $update_check_result -ne 0 ] || [ $log_check_result -ne 0 ]; then
        WARNING_OR_ERROR_CONTAINERS+=("$container_name") # Add container name to warning/error list
      fi

      echo "-------------------------------------------------------------------------" # Separator after each container's check
    done
    print_message "---------------------- End of Container Monitoring Results -------------------" "INFO"

    # --- Summary Reporting ---
    if [ ${#WARNING_OR_ERROR_CONTAINERS[@]} -gt 0 ]; then
      print_message "------------------------ Summary of Issues Found ------------------------" "SUMMARY"
      print_message "The following containers have warnings or errors:" "SUMMARY"
      for container_name in "${WARNING_OR_ERROR_CONTAINERS[@]}"; do
        print_message "- ${container_name}" "WARNING" # List problem containers in warning color
      done
      print_message "------------------------------------------------------------------------" "SUMMARY"
    else
      print_message "------------------------ Summary of Issues Found ------------------------" "SUMMARY"
      print_message "No issues found in any monitored containers. All containers are running, healthy, and up-to-date." "GOOD"
      print_message "------------------------------------------------------------------------" "SUMMARY"
    fi
  fi
fi

print_message "Docker monitoring script completed." "INFO"
exit 0
