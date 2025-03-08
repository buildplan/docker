#!/bin/bash

# --- Configuration File for Docker Monitoring Script ---

# --- Settings ---
LOG_LINES_TO_CHECK=20
CHECK_FREQUENCY_MINUTES=360
LOG_FILE="docker-container-monitor.log" # Path to the log file

# --- Container Names to Monitor ---
# Define the containers you want to monitor in this array.
CONTAINER_NAMES=(
  "beszel-agent"
  "wg-easy"
  "portainer"
  # Add more container names here, one per line in quotes
)

