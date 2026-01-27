#!/bin/bash
#
# Fail2Ban/IPSet blocklists Importer (IPv4 + IPv6)
# This script fetches multiple reputable threat intelligence sources to build a custom blocklist.
#

set -euo pipefail
IFS=$'\n\t'

# --- CONFIGURATION ---

# IPSet Names (These will appear in your firewall)
SET_NAME_V4="f2b-blocklist-v4"
SET_NAME_V6="f2b-blocklist-v6"

# Network timeouts
CURL_TIMEOUT=45
CURL_RETRIES=3

# Add IPs or Prefixes here. Space separated.
# - For single IPs: Just add the IP (e.g. "1.2.3.4")
# - For IPv6 Ranges: Add the prefix ending with a colon (e.g. "2b01:4c00:...")
#
CUSTOM_WHITELIST=""


# --- INITIALIZATION ---

# Dependency check
for cmd in curl sort awk grep comm ipset iptables ip6tables; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[ERROR] Required command '$cmd' not found. Please install it (apt install ipset)."
        exit 1
    fi
done

# Create temporary directory
TEMP_DIR=$(mktemp -d -t f2b-blocklist.XXXXXXXXXX)
LOCK_FILE="/tmp/f2b-blocklist-import.lock"

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

# --- CORE FUNCTIONS ---

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

update_ipset() {
    local set_name="$1"
    local ip_file="$2"
    local family="$3" # inet or inet6
    local tmp_set="${set_name}-tmp"

    local count
    count=$(wc -l < "$ip_file")

    log "Injecting $count IPs into $set_name ($family)..."
    ipset create "$tmp_set" hash:net family "$family" -exist
    ipset flush "$tmp_set"
    sed "s/^/add $tmp_set /" "$ip_file" > "${ip_file}.restore"
    ipset restore < "${ip_file}.restore"
    ipset create "$set_name" hash:net family "$family" -exist
    ipset swap "$tmp_set" "$set_name"
    ipset destroy "$tmp_set"
    log "Updated $set_name with $count entries."
}

ensure_firewall_rule() {
    local set_name="$1"
    local cmd="$2" # iptables or ip6tables

    if ! $cmd -C INPUT -m set --match-set "$set_name" src -j DROP 2>/dev/null; then
        log "Adding Firewall Rule for $set_name..."
        $cmd -I INPUT 1 -m set --match-set "$set_name" src -j DROP
    fi
}

# --- MAIN ---

main() {
    cd "$TEMP_DIR"

    # Fetching IPv4 Lists
    fetch_list "IPsum" "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" "v4_ipsum.txt" "grep -v '^#'"
    fetch_list "Spamhaus DROP" "https://www.spamhaus.org/drop/drop.txt" "v4_drop.txt" "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"
    fetch_list "Emerging Threats" "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" "v4_et.txt" "grep -v '^#'"
    fetch_list "Feodo Tracker" "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" "v4_feodo.txt" "grep -v '^#'"
    fetch_list "CI Army" "https://cinsscore.com/list/ci-badguys.txt" "v4_ci.txt" "grep -v '^#'"
    fetch_list "Binary Defense" "https://www.binarydefense.com/banlist.txt" "v4_binary.txt" "grep -v '^#'"
    fetch_list "Tor Exit Nodes" "https://check.torproject.org/torbulkexitlist" "v4_tor.txt" "grep -v '^#'"
    fetch_list "Blocklist.de" "https://lists.blocklist.de/lists/all.txt" "v4_blocklist_de.txt" "grep -v '^#'"
    fetch_list "GreenSnow" "https://blocklist.greensnow.co/greensnow.txt" "v4_greensnow.txt" "grep -v '^#'"
    fetch_list "DShield" "https://feeds.dshield.org/block.txt" "v4_dshield.txt" "grep -v '^#' | awk '{print \$1 \"/\" \$3}'"

    # Fetching IPv6 Lists
    fetch_list "Spamhaus DROPv6" "https://www.spamhaus.org/drop/dropv6.txt" "v6_drop.txt" "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"

    log "Validating IPs..."

    # IPv4 Validation
    cat v4_*.txt 2>/dev/null > raw_v4.txt || true
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" raw_v4.txt | \
    awk -F'.' '$1<=255 && $2<=255 && $3<=255 && $4<=255 { print $0 }' | \
    grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|224\.|240\.|255\.)" \
    > clean_v4.txt

    # IPv6 Validation
    cat v6_*.txt 2>/dev/null > raw_v6.txt || true
    grep -iE "^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?$" raw_v6.txt \
    > clean_v6.txt

    # Whitelisting
    touch whitelist_patterns.txt
    # Critical Defaults
    {
        echo "1.1.1.1"    # Cloudflare DNS
        echo "8.8.8.8"    # Google DNS
        echo "::1"        # IPv6 Localhost
        echo "2001:4860:4860::8888" # Google IPv6 DNS
        echo "2606:4700:4700::1111" # Cloudflare IPv6 DNS
    } >> whitelist_patterns.txt

    # Custom Whitelist
    for pattern in $CUSTOM_WHITELIST; do
        echo "$pattern" >> whitelist_patterns.txt
    done

    # Filter Lists
    grep -v -F -f whitelist_patterns.txt clean_v4.txt | sort -u > final_v4.txt
    grep -v -F -f whitelist_patterns.txt clean_v6.txt | sort -u > final_v6.txt

    # Injection (IPSet Swap)
    if [ -s final_v4.txt ]; then
        update_ipset "$SET_NAME_V4" "final_v4.txt" "inet"
        ensure_firewall_rule "$SET_NAME_V4" "iptables"
    else
        warn "No IPv4 addresses found to import."
    fi

    if [ -s final_v6.txt ]; then
        update_ipset "$SET_NAME_V6" "final_v6.txt" "inet6"
        ensure_firewall_rule "$SET_NAME_V6" "ip6tables"
    else
        warn "No IPv6 addresses found to import."
    fi

    log "Import complete."
}

main "$@"