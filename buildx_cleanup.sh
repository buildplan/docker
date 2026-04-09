#!/bin/bash
# buildx_cleanup.sh

LOG_DIR="/path/to/scripts/logs"
LOG="$LOG_DIR/buildx_cleanup.log"
MAX_AGE_DAYS=1
CUTOFF=$(date -d "${MAX_AGE_DAYS} days ago" +%s)
UNTIL_HOURS="$(( MAX_AGE_DAYS * 24 ))h"

mkdir -p "$LOG_DIR"

{
  echo "=== $(date '+%Y-%m-%d %H:%M:%S') - Starting buildx cleanup ==="

  echo "Removing old buildx containers..."
  docker ps -a --filter "name=buildx_buildkit_" --format '{{.ID}} {{.CreatedAt}}' | \
  while read -r id created_at; do
    created_epoch=$(date -d "$created_at" +%s 2>/dev/null)
    if [[ -n "$created_epoch" && "$created_epoch" -lt "$CUTOFF" ]]; then
      echo "  Removing container $id (Created: $created_at)"
      docker rm -f "$id"
    fi
  done

  echo "Pruning builder cache..."
  docker builder prune --filter "until=$UNTIL_HOURS" -f

  echo "Removing dangling buildx volumes..."
  docker volume ls --filter name=buildx_buildkit --filter dangling=true -q \
    | xargs -r docker volume rm -f

  echo "=== Done ==="
} >> "$LOG" 2>&1
