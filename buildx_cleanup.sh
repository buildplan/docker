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

  # 1/3. Iterate through builders and kill old instances
  echo "Checking for old buildx builders..."

  docker buildx ls --format '{{.Name}}' | sort -u | while read -r builder; do
    [[ "$builder" == "default" || "$builder" == "desktop-linux" || -z "$builder" ]] && continue

    nodes=$(docker buildx inspect "$builder" --format '{{range .Nodes}}{{.Name}}{{"\n"}}{{end}}' 2>/dev/null)

    if [ -z "$nodes" ]; then
      echo "  Removing dangling registration: $builder"
      docker buildx rm "$builder" 2>/dev/null || true
      continue
    fi

    while read -r node_name; do
      [ -z "$node_name" ] && continue
      container_name="buildx_buildkit_${node_name}"
      created=$(docker inspect "$container_name" --format '{{.Created}}' 2>/dev/null)
      if [ -n "$created" ]; then
        created_epoch=$(date -d "$created" +%s 2>/dev/null)
        if [[ -n "$created_epoch" && "$created_epoch" -lt "$CUTOFF" ]]; then
          echo "  Removing builder: $builder (node: $node_name, age: $(( ( $(date +%s) - created_epoch ) / 3600 ))h)"
          docker buildx rm "$builder"
          break
        fi
      else
        echo "  Removing inactive/broken builder: $builder"
        docker buildx rm "$builder" 2>/dev/null || true
        break
      fi
    done <<< "$nodes"
  done

  # 2/3. Prune builder cache
  echo "Pruning remaining builder cache..."
  docker builder prune -f 2>&1 | tail -1

  # 3/3. Clean up dangling volumes
  echo "Removing dangling buildx volumes..."
  docker volume ls --filter name=buildx_buildkit --filter dangling=true -q | xargs -r docker volume rm -f

  echo "Disk usage after: $(df -h / | awk 'NR==2 {print $3 "/" $2}')"
  echo "=== Done ==="
} >> "$LOG" 2>&1
