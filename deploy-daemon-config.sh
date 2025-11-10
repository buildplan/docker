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
BACKUP_SUFFIX=".backup.$(date +%Y%m%d_%H%M%S)"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "✗ This script must be run as root (use sudo)"
   exit 1
fi

# Check if systemctl is available
if ! command -v systemctl &> /dev/null; then
    echo "✗ systemctl is required but not found. This script is for systemd-based systems."
    exit 1
fi

# Check if docker is available
if ! command -v docker &> /dev/null; then
    echo "✗ docker is required but not installed."
    exit 1
fi

# Check if Docker daemon is running
if ! systemctl is-active --quiet docker; then
    echo "⚠ Docker daemon is not currently running"
    echo "Attempting to start Docker..."
    systemctl start docker || {
        echo "✗ Failed to start Docker daemon"
        exit 1
    }
fi

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    echo "✗ python3 is required but not installed"
    exit 1
fi

# Backup existing daemon.json if it exists
if [[ -f "$DAEMON_JSON" ]]; then
    BACKUP_FILE="${DAEMON_JSON}${BACKUP_SUFFIX}"
    echo "Backing up existing daemon.json to $BACKUP_FILE"
    cp "$DAEMON_JSON" "$BACKUP_FILE"
fi

# Create the daemon.json configuration
cat > "$DAEMON_JSON" << 'EOF'
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

# Validate JSON syntax using Python's json.tool
echo "Validating JSON syntax..."
if cat "$DAEMON_JSON" | python3 -m json.tool > /dev/null 2>&1; then
    echo "✓ JSON syntax is valid"
    echo ""
    echo "Pretty-printed configuration:"
    cat "$DAEMON_JSON" | python3 -m json.tool
    echo ""
    echo "Restarting Docker daemon..."
    systemctl restart docker
    
    if systemctl is-active --quiet docker; then
        echo "✓ Docker daemon restarted successfully"
        docker info | grep -A 5 "Security Options" || true
    else
        echo "✗ Docker failed to start! Restoring backup..."
        if [[ -f "$BACKUP_FILE" ]]; then
            cp "$BACKUP_FILE" "$DAEMON_JSON"
            systemctl restart docker
            echo "✓ Backup restored"
        fi
        exit 1
    fi
else
    echo "✗ Invalid JSON syntax! Not restarting Docker."
    if [[ -f "$BACKUP_FILE" ]]; then
        echo "Restoring backup..."
        cp "$BACKUP_FILE" "$DAEMON_JSON"
    fi
    exit 1
fi
