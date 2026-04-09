#!/bin/bash
# buildx_cleanup.sh

LOG_DIR="/path/to/scripts/logs"
LOG="$LOG_DIR/buildx_cleanup.log"

mkdir -p "$LOG_DIR"

{
  echo "=== $(date '+%Y-%m-%d %H:%M:%S') - Starting buildx cleanup ==="

  # 1/3. Kill old containers using the NAME prefix
  echo "Checking for buildx containers older than a day..."

  OLD_CONTAINERS=$(docker ps -a --filter "name=buildx_buildkit_" --format '{{.ID}} {{.RunningFor}}' | grep -E "days|weeks|months" | awk '{print $1}')

  if [ -n "$OLD_CONTAINERS" ]; then
    echo "Found old zombies: $OLD_CONTAINERS"
    echo "$OLD_CONTAINERS" | xargs -r docker rm -f
    echo "Containers removed."
  else
    echo "No old buildx containers found."
  fi

  # 2/3. Prune builder cache
  echo "Pruning builder cache..."
  docker builder prune -f

  # 3/3. Clean up dangling volumes
  echo "Removing dangling buildx volumes..."
  docker volume ls --filter name=buildx_buildkit --filter dangling=true -q | xargs -r docker volume rm -f

  echo "=== Done ==="
} >> "$LOG" 2>&1
