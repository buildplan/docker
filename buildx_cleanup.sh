#!/bin/bash
# buildx_cleanup.sh
# Removes stale BuildKit containers, build cache, and dangling volumes.

LOG_DIR="/path/to/scripts/logs"
LOG="$LOG_DIR/buildx_cleanup.log"
MAX_AGE_SECONDS=86400  # 24 hours

mkdir -p "$LOG_DIR"

{
  echo "=== $(date '+%Y-%m-%d %H:%M:%S') - Starting Buildx Cleanup ==="
  echo "Disk usage before: $(df -h / | awk 'NR==2 {print $3 "/" $2}')"

  # 1/3. Remove stale BuildKit containers
  echo "--- [1/3] Scanning for stale BuildKit containers..."

  docker ps -a --filter "name=buildx_buildkit_" --format "{{.ID}}|{{.Names}}" | \
  while IFS="|" read -r id name; do

    raw_date=$(docker inspect -f '{{.Created}}' "$id" 2>/dev/null)
    created_epoch=$(date -d "$raw_date" +%s 2>/dev/null)

    if [[ -z "$created_epoch" ]]; then
      echo "  Skipping $name: could not determine creation time"
      continue
    fi

    age_seconds=$(( $(date +%s) - created_epoch ))

    if (( age_seconds > MAX_AGE_SECONDS )); then
      echo "  Stale: $name ($((age_seconds / 3600))h old)"

      candidate=$(echo "$name" | sed 's/^buildx_buildkit_//')
      trimmed=$(echo "$candidate" | sed 's/[0-9]*$//')
      builder_name=""

      if docker buildx inspect "$candidate" >/dev/null 2>&1; then
        builder_name="$candidate"
      elif [[ "$candidate" != "$trimmed" ]] && \
           docker buildx inspect "$trimmed" >/dev/null 2>&1; then
        builder_name="$trimmed"
      fi

      if [[ -n "$builder_name" ]]; then
        echo "    Registered builder found: $builder_name. removing..."
        docker buildx rm "$builder_name" || docker rm -f "$id"
      else
        echo "    Orphan detected (no buildx registration). Force removing container: $id"
        docker rm -f "$id"
      fi
    fi
  done

  # 2/3. Prune all unused builder cache
  echo "--- [2/3] Pruning builder cache..."
  docker builder prune -f 2>&1 | tail -1

  # 3/3. Remove dangling buildx volumes
  echo "--- [3/3] Removing dangling buildx volumes..."
  docker volume ls --filter name=buildx_buildkit --filter dangling=true -q \
    | xargs -r docker volume rm -f || true

  echo "Disk usage after:  $(df -h / | awk 'NR==2 {print $3 "/" $2}')"
  echo "=== Done ==="

} >> "$LOG" 2>&1
