#!/bin/bash

# --- Configuration File for Docker Container Monitor Script ---
# --- Default Settings (can be overridden by environment variables) ---

# Log settings
LOG_LINES_TO_CHECK="${LOG_LINES_TO_CHECK:-20}"        # Default: 20 lines, can be set via ENV: LOG_LINES_TO_CHECK
CHECK_FREQUENCY_MINUTES="${CHECK_FREQUENCY_MINUTES:-360}" # Default: 360 mins (6 hours), ENV: CHECK_FREQUENCY_MINUTES
LOG_FILE="${LOG_FILE:-docker-monitor.log}"           # Default: docker-monitor.log, ENV: LOG_FILE

# Container Names to Monitor (can be overridden by CONTAINER_NAMES env variable - comma separated)
# Example: CONTAINER_NAMES="container1,container2,container3"
# If CONTAINER_NAMES environment variable is set, it will override this array.
CONTAINER_NAMES_DEFAULT=(
  "beszel-agent"
  "wg-easy"
  "portainer"
  # Add more default container names here if needed, one per line in quotes
)

# Initialize CONTAINER_NAMES array with defaults, unless overridden by environment variable
if [ -z "$CONTAINER_NAMES" ]; then # Check if CONTAINER_NAMES env var is NOT set
  CONTAINER_NAMES=("${CONTAINER_NAMES_DEFAULT[@]}") # Use default array from config file
else
  # If CONTAINER_NAMES env var is set, split comma-separated string into array
  IFS=',' read -r -a CONTAINER_NAMES <<< "$CONTAINER_NAMES"
fi
