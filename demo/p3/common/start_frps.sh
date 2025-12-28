#!/bin/bash
# Start real FRPS server for three-process test

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FRPS_PATH="${PROJECT_ROOT}/build/frps"

# Configuration
BIND_PORT="${FRPS_PORT:-7001}"
TOKEN="${FRPS_TOKEN:-test_token}"

# Check if frps exists
if [ ! -f "$FRPS_PATH" ]; then
    echo "Error: frps not found at $FRPS_PATH"
    echo "Run 'make frps-build' first"
    exit 1
fi

# Create config file
CONFIG_FILE=$(mktemp /tmp/frps_demo.XXXXXX.toml)
cat > "$CONFIG_FILE" << EOF
bindPort = ${BIND_PORT}

[auth]
method = "token"
token = "${TOKEN}"

[transport]
tcpMux = false

[log]
level = "debug"
EOF

echo "=================================================="
echo "  FRPS Server - Three Process Test"
echo "=================================================="
echo "Bind Port: ${BIND_PORT}"
echo "Token: ${TOKEN}"
echo "Config: ${CONFIG_FILE}"
echo "=================================================="
echo ""
echo "Starting FRPS..."
echo ""

# Run frps
"$FRPS_PATH" -c "$CONFIG_FILE"

# Cleanup
rm -f "$CONFIG_FILE"
