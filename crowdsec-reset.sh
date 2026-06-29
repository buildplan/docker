#!/bin/sh
#
# CrowdSec Cleanup & Database Maintenance

set -e

log() {
    printf "[%s] %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$*"
}

# --- Config ---
log "=== CrowdSec Maintenance Configuration ==="

# --- DETECT MODE ---
MODE="unknown"
if command -v cscli >/dev/null 2>&1 && [ -d "/etc/crowdsec" ]; then
    MODE="native"
elif command -v docker >/dev/null 2>&1; then
    MODE="docker"
else
    log "Error: Could not detect CrowdSec (neither native 'cscli' nor Docker found)."
    exit 1
fi

if [ "$MODE" = "docker" ]; then
    printf "Enter CrowdSec container name [crowdsec]: "
    read -r ans
    CONTAINER_NAME="${ans:-crowdsec}"

    # Check if container is running early
    if ! docker ps -q -f name="^${CONTAINER_NAME}$" >/dev/null 2>&1; then
        log "Error: Container '$CONTAINER_NAME' is not running."
        exit 1
    fi
fi

if [ "$MODE" = "native" ]; then
    printf "Enter DB path [/var/lib/crowdsec/data/crowdsec.db]: "
else
    printf "Enter DB path inside container [/var/lib/crowdsec/data/crowdsec.db]: "
fi
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
if [ "$MODE" = "native" ]; then
    log "Mode:             Native (Host)"
    # Prerequisite check for native mode
    if ! command -v sqlite3 >/dev/null 2>&1; then
        log "Error: 'sqlite3' is not installed on this host."
        log "Please install it (e.g., 'sudo apt install sqlite3') to vacuum natively."
        exit 1
    fi
else
    log "Mode:             Docker (Container: $CONTAINER_NAME)"
fi

log "DB Path:          $DB_PATH"
log "Threshold (MB):   $SIZE_THRESHOLD_MB"
log "Max Age:          $MAX_AGE"
log "Purge Origin:     $IMPORT_ORIGIN"
log "Host Bouncers:    $HOST_BOUNCER_SVCS"
log "Proxy Containers: $PROXY_CONTAINERS"
log "======================================="

get_db_size() {
    if [ "$MODE" = "native" ]; then
        sum_size=0
        for f in "$DB_PATH" "$DB_PATH-wal" "$DB_PATH-shm"; do
            if [ -f "$f" ]; then
                s=$(wc -c < "$f" 2>/dev/null || echo "0")
                sum_size=$((sum_size + s))
            fi
        done
        echo "$sum_size"
    else
        docker exec "$CONTAINER_NAME" sh -c "
            sum_size=0
            for f in \"$DB_PATH\" \"$DB_PATH-wal\" \"$DB_PATH-shm\"; do
                if [ -f \"\$f\" ]; then
                    s=\$(wc -c < \"\$f\" 2>/dev/null || echo \"0\")
                    sum_size=\$((sum_size + s))
                fi
            done
            echo \"\$sum_size\"
        " 2>/dev/null || echo "0"
    fi
}

# Get current database size
SIZE_BYTES=$(get_db_size)

if [ -z "$SIZE_BYTES" ] || [ "$SIZE_BYTES" -eq 0 ]; then
    log "Error: Could not read database file size at $DB_PATH. Does it exist?"
    exit 1
fi

SIZE_MB=$((SIZE_BYTES / 1024 / 1024))
log "Current database size: ${SIZE_MB}MB"
log "Starting cleanup process..."

# Purge the custom blocklists
log "[1/6] Purging decisions (Origin: $IMPORT_ORIGIN)..."
if [ "$MODE" = "native" ]; then
    if ! cscli decisions delete --origin "$IMPORT_ORIGIN"; then
        log "Notice: Purge returned non-zero (DB locked or empty). Continuing..."
    fi
else
    if ! docker exec "$CONTAINER_NAME" cscli decisions delete --origin "$IMPORT_ORIGIN"; then
        log "Notice: Purge returned non-zero (DB locked or empty). Continuing..."
    fi
fi
sleep 3

# Flush old alerts
log "[2/6] Flushing alerts older than $MAX_AGE..."
if [ "$MODE" = "native" ]; then
    if ! cscli alerts flush --max-age "$MAX_AGE"; then
        log "Notice: Alert flush returned non-zero. Continuing..."
    fi
else
    if ! docker exec "$CONTAINER_NAME" cscli alerts flush --max-age "$MAX_AGE"; then
        log "Notice: Alert flush returned non-zero. Continuing..."
    fi
fi
sleep 3

# Stop CrowdSec
if [ "$MODE" = "native" ]; then
    log "[3/6] Stopping CrowdSec service (Releasing SQLite locks)..."
    sudo systemctl stop crowdsec
else
    log "[3/6] Stopping '$CONTAINER_NAME' container (Releasing SQLite locks)..."
    docker stop "$CONTAINER_NAME" >/dev/null
fi
sleep 10

# Vacuum and Optimize
log "[4/6] Vacuuming and optimizing database (this may take a minute)..."
if [ "$MODE" = "native" ]; then
    sqlite3 "$DB_PATH" 'VACUUM; PRAGMA optimize;'
else
    docker run --rm --volumes-from "$CONTAINER_NAME" alpine sh -c \
      "apk add --no-cache sqlite && sqlite3 \"$DB_PATH\" 'VACUUM; PRAGMA optimize;'"
fi

# Start CrowdSec
if [ "$MODE" = "native" ]; then
    log "[5/6] Starting CrowdSec service..."
    sudo systemctl start crowdsec
else
    log "[5/6] Starting '$CONTAINER_NAME' container..."
    docker start "$CONTAINER_NAME" >/dev/null
fi
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
NEW_SIZE_BYTES=$(get_db_size)
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
