#!/bin/bash
# deploy-daemon-config.sh
# Deploys Docker daemon.json with safe validation
#
# Usage:
#   curl -LO https://raw.githubusercontent.com/buildplan/docker/refs/heads/main/deploy-daemon-config.sh
#   less deploy-daemon-config.sh  # Review the script
#   chmod +x deploy-daemon-config.sh
#   sudo ./deploy-daemon-config.sh

set -euo pipefail

DAEMON_JSON="/etc/docker/daemon.json"
TEMP_DAEMON_JSON="/tmp/daemon.json.$$"
BACKUP_FILE=""

# Clean up temporary file on exit
trap 'rm -f "$TEMP_DAEMON_JSON"' EXIT

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "✗ This script must be run as root (use sudo)"
    exit 1
fi

# Check for required commands
for cmd in systemctl docker python3; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "✗ Required command '$cmd' is not installed."
        exit 1
    fi
done

# Check if Docker daemon is running
if ! systemctl is-active --quiet docker; then
    echo "⚠ Docker daemon is not currently running"
    echo "Attempting to start Docker..."
    systemctl start docker || {
        echo "✗ Failed to start Docker daemon"
        exit 1
    }
fi

# Backup existing daemon.json if it exists
if [[ -f "$DAEMON_JSON" ]]; then
    BACKUP_FILE="${DAEMON_JSON}.backup.$(date +%Y%m%d_%H%M%S)"
    echo "Backing up existing daemon.json to $BACKUP_FILE"
    cp "$DAEMON_JSON" "$BACKUP_FILE"
fi

# Create the daemon.json configuration in a temporary file
cat > "$TEMP_DAEMON_JSON" << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5",
    "compress": "true"
  },
  "live-restore": true,
  "dns": [
    "9.9.9.9",
    "1.1.1.1",
    "208.67.222.222"
  ],
  "default-address-pools": [
    {
      "base": "172.80.0.0/16",
      "size": 24
    }
  ],
  "userland-proxy": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "features": {
    "buildkit": true
  }
}
EOF

# --- Validation Step 1: Python JSON Syntax Check ---
echo "Validating JSON syntax..."
if ! cat "$TEMP_DAEMON_JSON" | python3 -m json.tool > /dev/null 2>&1; then
    echo "✗ Invalid JSON syntax! Aborting."
    cat "$TEMP_DAEMON_JSON" | python3 -m json.tool
    exit 1
fi
echo "✓ JSON syntax is valid"
echo ""

# --- Validation Step 2: Docker Daemon Configuration Check ---
echo "Validating Docker configuration..."
if ! dockerd --validate --config-file="$TEMP_DAEMON_JSON"; then
    echo "✗ Docker configuration is invalid! Aborting."
    exit 1
fi
echo "✓ Docker configuration is valid"
echo ""

# --- Apply Configuration ---
echo "Applying new configuration..."
mv "$TEMP_DAEMON_JSON" "$DAEMON_JSON"
chmod 644 "$DAEMON_JSON"

echo "Reloading Docker daemon..."
systemctl reload docker

# --- Verification Step 1: Check if Docker is Active ---
if systemctl is-active --quiet docker; then
    echo "✓ Docker daemon reloaded successfully"
    echo ""
    
    # --- Verification Step 2: Check Specific Settings ---
    echo "--- Verifying settings ---"
    
    echo "Checking Logging Driver:"
    docker info | grep "Logging Driver"
    
    echo "Checking Live Restore:"
    docker info | grep "Live Restore"
    
    echo "Checking Default Address Pools:"
    docker info | grep -A 3 "Default Address Pools"
    
    # --- Verification Step 3: Test Network Allocation ---
    echo "--- Testing network allocation (should be 172.80.x.0/24) ---"
    if docker network create test-net > /dev/null 2>&1; then
        if docker network inspect test-net | grep -q "172.80."; then
            echo "✓ Network allocation test PASSED"
            docker network inspect test-net | grep "Subnet"
        else
            echo "✗ Network allocation test FAILED: Subnet is not in the 172.80.0.0/16 range."
            docker network inspect test-net | grep "Subnet"
        fi
        docker network rm test-net > /dev/null
    else
        echo "✗ Failed to create test network for verification"
    fi
    echo "----------------------------"

else
    # --- Automatic Rollback ---
    echo "✗ Docker failed to reload! Restoring backup..."
    if [[ -n "$BACKUP_FILE" && -f "$BACKUP_FILE" ]]; then
        cp "$BACKUP_FILE" "$DAEMON_JSON"
        systemctl restart docker
        echo "✓ Backup restored and Docker restarted"
    else
        echo "✗ No backup file found! Docker may be in a failed state."
    fi
    exit 1
fi
