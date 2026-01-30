#!/bin/bash
#
# 2026-01-28
# Fail2Ban/NFTables Blocklist Importer (IPv4 + IPv6)
# Fetches multiple public blocklists, validates IPs/CIDRs, applies whitelisting, and updates NFTables sets.
# For use with Fail2Ban to block malicious IPs at the firewall level.
# Works on systems with NFTables (Debian 12/13).

# cron: 0 4 * * * /usr/local/bin/f2b-nft-import.sh >> /var/log/f2b-nft-import.log 2>&1
# @reboot sleep 30 && /usr/local/bin/f2b-nft-import.sh >> /var/log/f2b-nft-import.log 2>&1

set -euo pipefail
IFS=$'\n\t'

# --- CONFIGURATION ---
NFT_TABLE="crowdsec_blocklists"
CURL_TIMEOUT=45
CURL_RETRIES=3
LOG_FILE="/var/log/f2b-nft-import.log"

# CUSTOM WHITELIST
# Add IPs (1.2.3.4) or Prefixes (2b01:...) here.
CUSTOM_WHITELIST=""

# --- INITIALIZATION ---
# Redirect all output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Check for required commands
for cmd in curl sort awk grep comm nft python3; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[ERROR] Required command '$cmd' not found. Please install it (apt install python3 nftables)."
        exit 1
    fi
done

# Create temporary working directory and lock file
TEMP_DIR=$(mktemp -d -t nft-blocklist.XXXXXXXXXX)
LOCK_FILE="/tmp/nft-blocklist-import.lock"

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

optimize_list() {
    python3 -c "
import sys, ipaddress
try:
    nets = [ipaddress.ip_network(line.strip(), strict=False) for line in sys.stdin if line.strip()]
    for net in ipaddress.collapse_addresses(nets):
        print(net)
except Exception as e:
    sys.stderr.write(f'Error optimizing IPs: {e}\n')
    sys.exit(1)
"
}

# --- MAIN ---

main() {
    cd "$TEMP_DIR"

    # Fetching IPv4 Lists
    fetch_list "AbuseIPDB" "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4" "v4_abuseipdb.txt" "grep -v '^#' | awk '{print \$1}'"
    fetch_list "IPsum" "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" "v4_ipsum.txt" "grep -v '^#'"
    fetch_list "Spamhaus DROP" "https://www.spamhaus.org/drop/drop.txt" "v4_drop.txt" "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"
    fetch_list "Spamhaus EDROP" "https://www.spamhaus.org/drop/edrop.txt" "v4_edrop.txt" "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"
    fetch_list "Emerging Threats" "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" "v4_et.txt" "grep -v '^#'"
    fetch_list "Feodo Tracker" "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" "v4_feodo.txt" "grep -v '^#'"
    fetch_list "SSL Blacklist" "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" "v4_sslbl.txt" "grep -v '^#'"
    fetch_list "URLhaus" "https://urlhaus.abuse.ch/downloads/text_online/" "v4_urlhaus.txt" "grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}'"
    fetch_list "CI Army" "https://cinsscore.com/list/ci-badguys.txt" "v4_ci.txt" "grep -v '^#'"
    fetch_list "Binary Defense" "https://www.binarydefense.com/banlist.txt" "v4_binary.txt" "grep -v '^#'"
    fetch_list "Bruteforce Blocker" "https://danger.rulez.sk/projects/bruteforceblocker/blist.php" "v4_bruteforce.txt" "grep -v '^#'"
    fetch_list "Tor Exit Nodes" "https://check.torproject.org/torbulkexitlist" "v4_tor.txt" "grep -v '^#'"
    fetch_list "Tor dan.me.uk" "https://www.dan.me.uk/torlist/?exit" "v4_tor_dan.txt" "grep -v '^#'"
    fetch_list "Blocklist.de" "https://lists.blocklist.de/lists/all.txt" "v4_blocklist_de.txt" "grep -v '^#'"
    fetch_list "Blocklist.de SSH" "https://lists.blocklist.de/lists/ssh.txt" "v4_blocklist_ssh.txt" "grep -v '^#'"
    fetch_list "Blocklist.de Apache" "https://lists.blocklist.de/lists/apache.txt" "v4_blocklist_apache.txt" "grep -v '^#'"
    fetch_list "Blocklist.de mail" "https://lists.blocklist.de/lists/mail.txt" "v4_blocklist_mail.txt" "grep -v '^#'"
    fetch_list "GreenSnow" "https://blocklist.greensnow.co/greensnow.txt" "v4_greensnow.txt" "grep -v '^#'"
    fetch_list "DShield" "https://feeds.dshield.org/block.txt" "v4_dshield.txt" "grep -v '^#' | awk '{print \$1 \"/\" \$3}'"
    fetch_list "Botscout" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/botscout_7d.ipset" "v4_botscout.txt" "grep -v '^#'"
    fetch_list "Firehol level1" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" "v4_firehol_l1.txt" "grep -v '^#'"
    fetch_list "Firehol level2" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset" "v4_firehol_l2.txt" "grep -v '^#'"
    fetch_list "Firehol level3" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/firehol_level3.netset" "v4_firehol_l3.txt" "grep -v '^#'"
    fetch_list "myip.ms" "https://myip.ms/files/blacklist/general/full_blacklist_database.txt" "v4_myip.txt" "grep -oE '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'"
    fetch_list "SOCKS proxies" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/socks_proxy_7d.ipset" "v4_socks_proxy.txt" "grep -v '^#'"
    fetch_list "Darklist" "https://www.darklist.de/raw.php" "v4_darklist.txt" "grep -v '^#'"
    fetch_list "Talos" "https://www.talosintelligence.com/documents/ip-blacklist" "v4_talos.txt" "grep -v '^#'"
    fetch_list "Charles Haley" "https://charles.the-haleys.org/ssh_dico_attack_hdeny_format.php/hostsdeny.txt" "v4_haley.txt" "grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}'"
    fetch_list "Botvrij" "https://www.botvrij.eu/data/ioclist.ip-dst.raw" "v4_botvrij.txt" "grep -v '^#'"
    fetch_list "StopForumSpam" "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt" "v4_stopforumspam.txt" "grep -v '^#'"
    fetch_list "Shodan scanners" "https://gist.githubusercontent.com/jfqd/4ff7fa70950626a11832a4bc39451c1c/raw" "v4_shodan.txt" "grep -v '^#'"

    # Fetching IPv6 Lists
    fetch_list "Spamhaus DROPv6" "https://www.spamhaus.org/drop/dropv6.txt" "v6_drop.txt" "grep -v '^;' | awk '{print \$1}' | cut -d';' -f1"

    log "Validating IPs..."

    # IPv4 Validation (Handles /CIDR)
    cat v4_*.txt 2>/dev/null > raw_v4.txt || true
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]{1,2})?" raw_v4.txt | \
    awk -F'.' '$1<=255 && $2<=255 && $3<=255 && $4<=255 { print $0 }' | \
    grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|224\.|240\.|255\.)" \
    > clean_v4.txt

    # IPv6 Validation
    cat v6_*.txt 2>/dev/null > raw_v6.txt || true
    grep -iE "^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?$" raw_v6.txt \
    > clean_v6.txt

    # Whitelisting
    touch whitelist_patterns.txt
    {
        echo "1.1.1.1"    # Cloudflare DNS
        echo "8.8.8.8"    # Google DNS
        echo "::1"        # IPv6 Localhost
        echo "2001:4860:4860::8888" # Google IPv6 DNS
        echo "2606:4700:4700::1111" # Cloudflare IPv6 DNS
    } >> whitelist_patterns.txt

    for pattern in $CUSTOM_WHITELIST; do
        echo "$pattern" >> whitelist_patterns.txt
    done

    grep -v -F -f whitelist_patterns.txt clean_v4.txt > step1_v4.txt
    grep -v -F -f whitelist_patterns.txt clean_v6.txt > step1_v6.txt

    log "Optimizing Lists (merging overlaps)..."

    # Merge overlapping CIDRs using Python
    cat step1_v4.txt | optimize_list > final_v4.txt
    cat step1_v6.txt | optimize_list > final_v6.txt

    log "Generating NFTables configuration..."

    V4_ELEMENTS=$(paste -sd "," final_v4.txt)
    V6_ELEMENTS=$(paste -sd "," final_v6.txt)

    NFT_FILE="apply_blocklist.nft"

    cat <<EOF > "$NFT_FILE"
table inet $NFT_TABLE {
    set v4_list {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { $V4_ELEMENTS }
    }

    set v6_list {
        type ipv6_addr
        flags interval
        auto-merge
        elements = { $V6_ELEMENTS }
    }

    chain inbound {
        type filter hook input priority -100; policy accept;
        ip saddr @v4_list drop
        ip6 saddr @v6_list drop
    }
}
EOF

    # Safety Check
    log "Performing safety check on total IPs..."

    MIN_IPS=500
    TOTAL_IPS=$(( $(wc -l < final_v4.txt) + $(wc -l < final_v6.txt) ))
    if [ "$TOTAL_IPS" -lt "$MIN_IPS" ]; then
        error "Safety Brake: Only found $TOTAL_IPS IPs (Threshold: $MIN_IPS)."
        error "Something went wrong with downloads. Keeping old rules active."
        exit 1
    fi

    # Apply to Kernel
    log "Applying rules to NFTables..."

    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFT_TABLE"
    fi

    if nft -f "$NFT_FILE"; then
        V4_COUNT=$(wc -l < final_v4.txt)
        V6_COUNT=$(wc -l < final_v6.txt)
        log "Success. Blocked $V4_COUNT IPv4 and $V6_COUNT IPv6 addresses."
    else
        error "Failed to apply NFTables rules. Check syntax."
        exit 1
    fi
}

main "$@"
