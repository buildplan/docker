#!/bin/bash
#
# Production CrowdSec Blocklist Importer
# Final Version: ShellCheck Clean, Docker-safe, Robust
#

set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# CONFIGURATION
# ==============================================================================

# How long to ban IPs for
DECISION_DURATION="${DECISION_DURATION:-24h}"

# CrowdSec container name (if running in Docker)
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-crowdsec}"

# Mode: "auto", "native", or "docker"
MODE="${MODE:-auto}"

# Network timeouts and retries
CURL_TIMEOUT=45
CURL_RETRIES=3

# Whitelist: IPs here will NEVER be imported (space/newline separated)
CUSTOM_WHITELIST=""

# ==============================================================================
# INITIALIZATION
# ==============================================================================

# Dependency check
for cmd in curl sort awk grep comm; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[ERROR] Required command '$cmd' not found. Please install it."
        exit 1
    fi
done

# Create secure temporary directory
TEMP_DIR=$(mktemp -d -t crowdsec-blocklist.XXXXXXXXXX)
LOCK_FILE="/tmp/crowdsec-blocklist-import.lock"

# Cleanup trap
cleanup() {
    rm -rf "$TEMP_DIR"
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

# Prevent concurrent runs
if [ -f "$LOCK_FILE" ]; then
    if kill -0 "$(cat "$LOCK_FILE")" 2>/dev/null; then
        echo "[ERROR] Script is already running (PID $(cat "$LOCK_FILE")). Exiting."
        exit 1
    else
        echo "[WARN] Stale lock file found. Removing."
    fi
fi
echo $$ > "$LOCK_FILE"

# Logging helpers
log()   { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
warn()  { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [WARN]  $*"; }
error() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $*"; }

# ==============================================================================
# CROWDSEC DETECTION LOGIC
# ==============================================================================

detect_env() {
    if [ "$MODE" = "native" ]; then
        if ! command -v cscli &>/dev/null; then
            error "'cscli' not found in PATH (native mode)."
            exit 1
        fi
        log "Mode: Native (cscli found)"
        return
    fi

    if [ "$MODE" = "docker" ]; then
        log "Mode: Docker (container: $CROWDSEC_CONTAINER)"
        return
    fi

    # Auto-detection
    if command -v cscli &>/dev/null && cscli version &>/dev/null 2>&1; then
        MODE="native"
        log "Mode: Auto-detected Native"
    elif docker ps -q -f name="^${CROWDSEC_CONTAINER}$" &>/dev/null; then
        MODE="docker"
        log "Mode: Auto-detected Docker"
    else
        error "Could not detect CrowdSec (neither 'cscli' in PATH nor Docker container '$CROWDSEC_CONTAINER' found)."
        exit 1
    fi
}

# Run cscli command reading from STDIN
run_cscli_stdin() {
    if [ "$MODE" = "native" ]; then
        cat - | cscli "$@"
    else
        docker exec -i "$CROWDSEC_CONTAINER" cscli "$@"
    fi
}

# ==============================================================================
# CORE FUNCTIONS
# ==============================================================================

fetch_list() {
    local name="$1"
    local url="$2"
    local output="$3"
    local filter="${4:-cat}"

    log "Fetching $name..."

    set +e
    curl -sL --fail --retry "$CURL_RETRIES" --retry-delay 2 --max-time "$CURL_TIMEOUT" "$url" \
        | eval "$filter" > "$output"
    local ret=$?
    set -e

    if [ $ret -eq 0 ]; then
        if [ -s "$output" ]; then
            return 0
        else
            warn "$name: Source returned empty list (ignoring)"
            rm -f "$output"
            return 1
        fi
    else
        warn "$name: Download failed after $CURL_RETRIES retries"
        rm -f "$output"
        return 1
    fi
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

main() {
    detect_env

    cd "$TEMP_DIR"

    # --- 1. Fetching Blocklists ---
    fetch_list "IPsum" "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" "ipsum.txt" "grep -v '^#' | awk '{print \$1}'"
    fetch_list "Spamhaus DROP" "https://www.spamhaus.org/drop/drop.txt" "drop.txt" "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"
    fetch_list "Emerging Threats" "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" "et.txt" "grep -v '^#'"
    fetch_list "Feodo Tracker" "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" "feodo.txt" "grep -v '^#'"
    fetch_list "CI Army" "https://cinsscore.com/list/ci-badguys.txt" "ci.txt" "grep -v '^#'"
    fetch_list "Binary Defense" "https://www.binarydefense.com/banlist.txt" "binary.txt" "grep -v '^#'"
    fetch_list "Tor Exit Nodes" "https://check.torproject.org/torbulkexitlist" "tor.txt" "grep -v '^#'"

    # --- 2. Processing & Validation ---
    log "Processing and validating IPs..."

    cat ./*.txt 2>/dev/null > raw_combined.txt || true

    if [ ! -s raw_combined.txt ]; then
        error "No IPs fetched from any source. Aborting."
        exit 1
    fi

    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" raw_combined.txt | \
    awk -F'.' '$1>=0 && $1<=255 && $2>=0 && $2<=255 && $3>=0 && $3<=255 && $4>=0 && $4<=255 { printf "%d.%d.%d.%d\n", $1, $2, $3, $4 }' | \
    grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|224\.|240\.|255\.|169\.254\.)" \
    > validated_ips.txt

    # --- 3. Whitelisting ---
    touch whitelist.txt

    {
        echo "1.1.1.1"
        echo "8.8.8.8"
        echo "9.9.9.9"
        for ip in $CUSTOM_WHITELIST; do
            echo "$ip"
        done
    } >> whitelist.txt

    comm -23 <(sort -u validated_ips.txt) <(sort -u whitelist.txt) > final_import_list.txt

    # --- 4. Deduplication against CrowdSec ---
    log "Checking against existing decisions..."

    if [ "$MODE" = "native" ]; then
        cscli decisions list -a 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u > existing_decisions.txt || touch existing_decisions.txt
    else
        docker exec -i "$CROWDSEC_CONTAINER" cscli decisions list -a 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u > existing_decisions.txt || touch existing_decisions.txt
    fi

    comm -23 final_import_list.txt existing_decisions.txt > new_ips.txt

    COUNT=$(wc -l < new_ips.txt)
    TOTAL=$(wc -l < final_import_list.txt)

    if [ "$COUNT" -eq 0 ]; then
        log "No new IPs to import. (Total list size: $TOTAL, all present)"
        exit 0
    fi

    # --- 5. Import ---
    log "Importing $COUNT new IPs..."

    cat new_ips.txt | run_cscli_stdin decisions import \
        -i - \
        --format values \
        --duration "$DECISION_DURATION" \
        --reason "external_blocklist" \
        --type ban

    log "Successfully imported $COUNT IPs."
}

main "$@"