#!/bin/sh
#
# CrowdSec Cleanup & Database Maintenance

set -e

log() {
    printf "[%s] %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$*"
}

# --- Config ---
log "=== CrowdSec Maintenance Configuration ==="

printf "Enter CrowdSec container name [crowdsec]: "
read -r ans
CONTAINER_NAME="${ans:-crowdsec}"

printf "Enter DB path inside container [/var/lib/crowdsec/data/crowdsec.db]: "
read -r ans
DB_PATH="${ans:-/var/lib/crowdsec/data/crowdsec.db}"

printf "Enter size threshold in MB [100]: "
read -r ans
SIZE_THRESHOLD_MB="${ans:-100}"

printf "Enter max age for alerts flush [12h]: "
read -r ans
MAX_AGE="${ans:-12h}"

printf "Enter blocklist origin to purge [cscli-import]: "
read -r ans
IMPORT_ORIGIN="${ans:-cscli-import}"

printf "Enter host firewall services (space-separated) [crowdsec-firewall-bouncer.service] (or 'skip'): "
read -r ans
HOST_BOUNCER_SVCS="${ans:-crowdsec-firewall-bouncer.service}"

printf "Enter Reverse Proxy container names to restart (space-separated) [traefik] (or 'skip'): "
read -r ans
PROXY_CONTAINERS="${ans:-traefik}"

echo ""
log "=== Starting DB Maintenance & Purge ==="
log "Container:        $CONTAINER_NAME"
log "DB Path:          $DB_PATH"
log "Threshold (MB):   $SIZE_THRESHOLD_MB"
log "Max Age:          $MAX_AGE"
log "Purge Origin:     $IMPORT_ORIGIN"
log "Host Bouncers:    $HOST_BOUNCER_SVCS"
log "Proxy Containers: $PROXY_CONTAINERS"
log "======================================="

# Check if container is running
if ! docker ps -q -f name="^${CONTAINER_NAME}$" >/dev/null 2>&1; then
    log "Error: Container '$CONTAINER_NAME' is not running."
    exit 1
fi

# Get current database size
SIZE_BYTES=$(docker exec "$CONTAINER_NAME" sh -c "wc -c < \"$DB_PATH\"" 2>/dev/null || echo "0")

if [ "$SIZE_BYTES" -eq 0 ]; then
    log "Error: Could not read database file size at $DB_PATH. Does it exist?"
    exit 1
fi

SIZE_MB=$((SIZE_BYTES / 1024 / 1024))
log "Current database size: ${SIZE_MB}MB"
log "Starting cleanup process..."

# Purge the custom blocklists
log "[1/6] Purging decisions (Origin: $IMPORT_ORIGIN)..."
if ! docker exec "$CONTAINER_NAME" cscli decisions delete --origin "$IMPORT_ORIGIN"; then
    log "Notice: Purge returned non-zero (DB locked or empty). Continuing..."
fi
sleep 3

# Flush old alerts
log "[2/6] Flushing alerts older than $MAX_AGE..."
if ! docker exec "$CONTAINER_NAME" cscli alerts flush --max-age "$MAX_AGE"; then
    log "Notice: Alert flush returned non-zero. Continuing..."
fi
sleep 3

# Stop CrowdSec
log "[3/6] Stopping '$CONTAINER_NAME' container (Releasing SQLite locks)..."
docker stop "$CONTAINER_NAME" >/dev/null
sleep 10

# Vacuum and Optimize
log "[4/6] Vacuuming and optimizing database (this may take a minute)..."
docker run --rm --volumes-from "$CONTAINER_NAME" alpine sh -c \
  "apk add --no-cache sqlite && sqlite3 \"$DB_PATH\" 'VACUUM; PRAGMA optimize;'"

# Start CrowdSec
log "[5/6] Starting '$CONTAINER_NAME' container..."
docker start "$CONTAINER_NAME" >/dev/null
sleep 10

# Restart Bouncers & Proxies to clear metrics/cache
log "[6/6] Restarting enforcers to flush cached rules..."

if [ "$HOST_BOUNCER_SVCS" != "skip" ]; then
    for svc in $HOST_BOUNCER_SVCS; do
        log " -> Restarting host firewall bouncer ($svc)..."
        if ! sudo systemctl restart "$svc"; then
            log "Warning: Failed to restart $svc."
        fi
    done
else
    log " -> Skipping host firewall bouncer restart."
fi

if [ "$PROXY_CONTAINERS" != "skip" ]; then
    for container in $PROXY_CONTAINERS; do
        log " -> Restarting Proxy container ($container)..."
        if docker ps -q -f name="^${container}$" >/dev/null 2>&1; then
            docker restart "$container" >/dev/null
        else
            log "Warning: Container '$container' not running or not found. Skipping."
        fi
    done
else
     log " -> Skipping Proxy container restart."
fi

# Verify
NEW_SIZE_BYTES=$(docker exec "$CONTAINER_NAME" sh -c "wc -c < \"$DB_PATH\"" 2>/dev/null || echo "0")
NEW_SIZE_MB=$((NEW_SIZE_BYTES / 1024 / 1024))

log "======================================="
log "Maintenance complete!"
log "Original size: ${SIZE_MB}MB"
log "New size:      ${NEW_SIZE_MB}MB"
echo
if [ "$NEW_SIZE_MB" -lt "$SIZE_THRESHOLD_MB" ]; then
    log "Database size is under the threshold. Cleanup successful!"
else
    log "Warning: Database size (${NEW_SIZE_MB}MB) is still above or equal to threshold (${SIZE_THRESHOLD_MB}MB)."
fi
log "======================================="
