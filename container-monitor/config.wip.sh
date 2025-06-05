#!/bin/bash

# --- Configuration File for Docker Container Monitor Script ---
# This file should define default values.
# The main script will handle environment variable overrides and validation.

LOG_LINES_TO_CHECK_DEFAULT=20
CHECK_FREQUENCY_MINUTES_DEFAULT=360
LOG_FILE_DEFAULT="docker-monitor.log" # The main script can make this path absolute if needed

CONTAINER_NAMES_DEFAULT=(
  "dozzle-agent"
  "komodo-periphery"
  "beszel-agent"
  # Add more default container names here if needed
)
