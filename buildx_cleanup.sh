#!/bin/bash
# buildx_cleanup.sh

LOG_DIR="/path/to/scripts/logs"
LOG="$LOG_DIR/buildx_cleanup.log"
MAX_AGE_DAYS=1
CUTOFF=$(date -d "${MAX_AGE_DAYS} days ago" +%s)

mkdir -p "$LOG_DIR"

{
  echo "=== $(date '+%Y-%m-%d %H:%M:%S') - Starting buildx cleanup ==="
  echo "Disk usage before: $(df -h / | awk 'NR==2 {print $3 "/" $2}')"

  # 1/3. Remove old buildx containers
  echo "Checking for old buildx containers..."
  docker ps -a --filter "name=buildx_buildkit_" --format '{{.ID}} {{.Names}} {{.CreatedAt}}' | \
  while read -r id name created_at; do
    created_epoch=$(date -d "$created_at" +%s 2>/dev/null)
    if [[ -n "$created_epoch" && "$created_epoch" -lt "$CUTOFF" ]]; then
      echo "  Removing: $name (age: $(( ( $(date +%s) - created_epoch ) / 3600 ))h)"
      docker rm -f "$id"
    fi
  done

  echo "Cleaning up broken builder registrations..."
  docker buildx ls | awk '/^[a-zA-Z]/ && !/^NAME/ {gsub(/\*/, ""); print $1}' | \
  while read -r builder; do
    [[ "$builder" == "default" || "$builder" == "desktop-linux" ]] && continue
    docker buildx rm "$builder" 2>/dev/null && echo "  Removed registration: $builder" || true
  done

  # 2/3. Prune builder cache
  echo "Pruning builder cache..."
  docker builder prune -f 2>&1 | tail -1

  # 3/3. Clean up dangling buildx volumes
  echo "Removing dangling buildx volumes..."
  docker volume ls --filter name=buildx_buildkit --filter dangling=true -q | xargs -r docker volume rm -f

  echo "Disk usage after: $(df -h / | awk 'NR==2 {print $3 "/" $2}')"
  echo "=== Done ==="
} >> "$LOG" 2>&1
