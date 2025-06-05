#!/bin/bash

# --- Configuration File for Docker Container Monitor Script ---
# --- docker ps -a --format '{{.Names}}' for container names --- 
# This file should define default values for the main script.
# The main script will handle environment variable overrides and validation.

## --- General Settings ---
LOG_LINES_TO_CHECK_DEFAULT=20
CHECK_FREQUENCY_MINUTES_DEFAULT=360
LOG_FILE_DEFAULT="docker-monitor.log"

## --- Container Monitoring Thresholds ---
CPU_WARNING_THRESHOLD_DEFAULT=80      # Percentage
MEMORY_WARNING_THRESHOLD_DEFAULT=80   # Percentage
DISK_SPACE_THRESHOLD_DEFAULT=80       # Percentage
NETWORK_ERROR_THRESHOLD_DEFAULT=10    # Number of network errors/drops

## --- Host System Check Settings ---
# Filesystem path on the host to check for disk usage (e.g., "/", "/var/lib/docker")
HOST_DISK_CHECK_FILESYSTEM_DEFAULT="/"

## --- Default Containers to Monitor ---
# This array is used if the CONTAINER_NAMES environment variable is not set
# and no container names are passed as arguments.
CONTAINER_NAMES_DEFAULT=(
  "dozzle-agent"
  "komodo-periphery"
  "beszel-agent"
  # Add more default container names here if needed, one per line in quotes
)
