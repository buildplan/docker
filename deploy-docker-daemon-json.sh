#!/bin/bash
# deploy-daemon-config.sh
# Deploys Docker daemon.json with safe validation

DAEMON_JSON="/etc/docker/daemon.json"

# Create the daemon.json configuration
cat > "$DAEMON_JSON" << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "dns": ["9.9.9.9", "1.1.1.1", "208.67.222.222"],
  "userland-proxy": false,
  "no-new-privileges": true,
  "icc": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
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
    sudo systemctl restart docker
    echo "✓ Docker daemon restarted successfully"
else
    echo "✗ Invalid JSON syntax! Not restarting Docker."
    echo "Please check the configuration file."
    exit 1
fi
