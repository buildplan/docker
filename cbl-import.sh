#!/bin/bash
#
# CrowdSec Blocklist Importer (IPv4 + IPv6)
# 2026-01-27: Docker-safe, ShellCheck
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
        echo "[ERROR] Required command '$cmd' not found."
        exit 1
    fi
done

# Create temporary directory
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
        echo "[WARN] Stale lock found. Removing."
    fi
fi
echo $$ > "$LOCK_FILE"

# Logging helpers
log()   { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
warn()  { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [WARN]  $*"; }
error() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $*"; }

# ==============================================================================
# DETECTION & API WRAPPERS
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
# MAIN
# ==============================================================================

main() {
    detect_env
    cd "$TEMP_DIR"

    # --- 1. Fetching IPv4 Lists ---
    fetch_list "IPsum" "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" "v4_ipsum.txt" "grep -v '^#' | awk '{print \$1}'"
    fetch_list "Spamhaus DROP" "https://www.spamhaus.org/drop/drop.txt" "v4_drop.txt" "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"
    fetch_list "Emerging Threats" "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" "v4_et.txt" "grep -v '^#'"
    fetch_list "Feodo Tracker" "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" "v4_feodo.txt" "grep -v '^#'"
    fetch_list "CI Army" "https://cinsscore.com/list/ci-badguys.txt" "v4_ci.txt" "grep -v '^#'"
    fetch_list "Binary Defense" "https://www.binarydefense.com/banlist.txt" "v4_binary.txt" "grep -v '^#'"
    fetch_list "Tor Exit Nodes" "https://check.torproject.org/torbulkexitlist" "v4_tor.txt" "grep -v '^#'"
    
    # --- 2. Fetching IPv6 Lists ---
    fetch_list "Spamhaus DROPv6" "https://www.spamhaus.org/drop/dropv6.txt" "v6_drop.txt" "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"

    # --- 3. Validation & Merging ---
    log "Validating IPs..."

    # IPv4 Validation (Strict)
    cat v4_*.txt 2>/dev/null > raw_v4.txt || true
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" raw_v4.txt | \
    awk -F'.' '$1<=255 && $2<=255 && $3<=255 && $4<=255 { print $0 }' | \
    grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|224\.|240\.|255\.)" \
    > clean_v4.txt

    # IPv6 Validation (Loose check for colons/hex, CrowdSec API will do final strict check)
    cat v6_*.txt 2>/dev/null > raw_v6.txt || true
    # Regex looks for at least two colons and hex characters
    grep -iE "^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(/[0-9]{1,3})?$" raw_v6.txt \
    > clean_v6.txt

    cat clean_v4.txt clean_v6.txt > validated_ips.txt

    if [ ! -s validated_ips.txt ]; then
        error "No IPs found. Aborting."
        exit 1
    fi

    # --- 4. Whitelisting ---
    touch whitelist.txt
    {
        echo "1.1.1.1"    # Cloudflare DNS
        echo "8.8.8.8"    # Google DNS
        echo "::1"        # IPv6 Localhost
        echo "2001:4860:4860::8888" # Google IPv6 DNS
        echo "2606:4700:4700::1111" # Cloudflare IPv6 DNS
        for ip in $CUSTOM_WHITELIST; do echo "$ip"; done
    } >> whitelist.txt

    comm -23 <(sort -u validated_ips.txt) <(sort -u whitelist.txt) > final_import_list.txt

    # --- 5. Deduplication ---
    log "Checking against existing decisions..."

    REGEX_IPV4="[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
    REGEX_IPV6="[0-9a-fA-F:]*:[0-9a-fA-F:]+"
    
    if [ "$MODE" = "native" ]; then
        cscli decisions list -a 2>/dev/null | grep -oE "($REGEX_IPV4|$REGEX_IPV6)" | sort -u > existing_decisions.txt || touch existing_decisions.txt
    else
        docker exec -i "$CROWDSEC_CONTAINER" cscli decisions list -a 2>/dev/null | grep -oE "($REGEX_IPV4|$REGEX_IPV6)" | sort -u > existing_decisions.txt || touch existing_decisions.txt
    fi

    comm -23 final_import_list.txt existing_decisions.txt > new_ips.txt

    COUNT=$(wc -l < new_ips.txt)
    TOTAL=$(wc -l < final_import_list.txt)

    if [ "$COUNT" -eq 0 ]; then
        log "No new IPs to import. (Total list size: $TOTAL, all present)"
        exit 0
    fi

    # --- 6. Import ---
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