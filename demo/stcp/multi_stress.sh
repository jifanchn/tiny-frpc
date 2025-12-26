#!/bin/bash
#
# Multi-channel STCP Stress Test
# Runs multiple visitor-server pairs in parallel for higher load
#

set -e

# Configuration
NUM_CHANNELS=${1:-4}          # Number of parallel channels
DURATION=${2:-30}             # Test duration per channel (seconds)
INTERVAL=${3:-50}             # Message interval (ms)
MIN_PAYLOAD=${4:-64}
MAX_PAYLOAD=${5:-512}

BASE_FRPS_PORT=17100
BASE_DATA_PORT=19100

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../../build"

echo "=== Multi-Channel STCP Stress Test ==="
echo "  Channels:     ${NUM_CHANNELS}"
echo "  Duration:     ${DURATION}s per channel"
echo "  Interval:     ${INTERVAL}ms"
echo "  Payload:      ${MIN_PAYLOAD}-${MAX_PAYLOAD} bytes"
echo ""

# Check binaries exist
if [[ ! -x "${BUILD_DIR}/demo_stcp_frps" ]] || [[ ! -x "${BUILD_DIR}/demo_stcp_stress" ]]; then
    echo "Error: Build demo-stcp first with 'make demo-stcp'"
    exit 1
fi

# Arrays to track PIDs
declare -a FRPS_PIDS
declare -a SERVER_PIDS
declare -a VISITOR_PIDS

cleanup() {
    echo ""
    echo "Cleaning up..."
    for pid in "${VISITOR_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${SERVER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${FRPS_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Start all channels
echo "Starting ${NUM_CHANNELS} channels..."

for i in $(seq 1 "${NUM_CHANNELS}"); do
    FRPS_PORT=$((BASE_FRPS_PORT + i))
    DATA_PORT=$((BASE_DATA_PORT + i))
    PROXY_NAME="stress_ch${i}"
    SK="secret_ch${i}"
    
    LOG_DIR="/tmp/multi_stress_${i}"
    mkdir -p "${LOG_DIR}"
    
    # Start mock FRPS for this channel
    "${BUILD_DIR}/demo_stcp_frps" --listen-port "${FRPS_PORT}" > "${LOG_DIR}/frps.log" 2>&1 &
    FRPS_PIDS+=($!)
    
    sleep 0.1
    
    # Start server for this channel
    "${BUILD_DIR}/demo_stcp_stress" --mode server \
        --frps-port "${FRPS_PORT}" \
        --data-port "${DATA_PORT}" \
        --proxy-name "${PROXY_NAME}" \
        --sk "${SK}" \
        --duration $((DURATION + 5)) \
        -v > "${LOG_DIR}/server.log" 2>&1 &
    SERVER_PIDS+=($!)
    
    sleep 0.1
    
    # Start visitor for this channel
    "${BUILD_DIR}/demo_stcp_stress" --mode visitor \
        --frps-port "${FRPS_PORT}" \
        --data-port "${DATA_PORT}" \
        --proxy-name "${PROXY_NAME}" \
        --sk "${SK}" \
        --duration "${DURATION}" \
        --interval "${INTERVAL}" \
        --min-payload "${MIN_PAYLOAD}" \
        --max-payload "${MAX_PAYLOAD}" \
        -v > "${LOG_DIR}/visitor.log" 2>&1 &
    VISITOR_PIDS+=($!)
    
    echo "  Channel ${i}: FRPS=${FRPS_PORT}, Data=${DATA_PORT}"
done

echo ""
echo "All channels started. Waiting for completion..."
echo "Progress (updates every 5s):"

# Wait for visitors to complete, show progress
ELAPSED=0
while [ $ELAPSED -lt $DURATION ]; do
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    
    # Check if all visitors still running
    RUNNING=0
    for pid in "${VISITOR_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            RUNNING=$((RUNNING + 1))
        fi
    done
    
    echo "  [${ELAPSED}s] ${RUNNING}/${NUM_CHANNELS} channels active"
    
    if [ $RUNNING -eq 0 ]; then
        break
    fi
done

echo ""
echo "Waiting for all processes to finish..."
wait "${VISITOR_PIDS[@]}" 2>/dev/null || true

echo ""
echo "=== Results ==="

TOTAL_SENT=0
TOTAL_RECV=0
TOTAL_BYTES_SENT=0
TOTAL_BYTES_RECV=0
TOTAL_ERRORS=0

for i in $(seq 1 "${NUM_CHANNELS}"); do
    LOG_DIR="/tmp/multi_stress_${i}"
    
    # Parse visitor log for FINAL stats (last occurrence after "FINAL")
    if [[ -f "${LOG_DIR}/visitor.log" ]]; then
        # Get lines after "FINAL" marker
        FINAL_SECTION=$(grep -A10 "FINAL" "${LOG_DIR}/visitor.log" 2>/dev/null | tail -10 || echo "")
        
        SENT=$(echo "${FINAL_SECTION}" | grep "Messages sent:" | awk '{print $3}' || echo "0")
        RECV=$(echo "${FINAL_SECTION}" | grep "Messages recv:" | awk '{print $3}' || echo "0")
        BYTES_SENT=$(echo "${FINAL_SECTION}" | grep "Bytes sent:" | awk '{print $3}' || echo "0")
        BYTES_RECV=$(echo "${FINAL_SECTION}" | grep "Bytes recv:" | awk '{print $3}' || echo "0")
        ERRORS=$(echo "${FINAL_SECTION}" | grep "Errors:" | awk '{print $2}' || echo "0")
        
        echo "Channel ${i}: sent=${SENT:-0} recv=${RECV:-0} errors=${ERRORS:-0}"
        
        TOTAL_SENT=$((TOTAL_SENT + ${SENT:-0}))
        TOTAL_RECV=$((TOTAL_RECV + ${RECV:-0}))
        TOTAL_BYTES_SENT=$((TOTAL_BYTES_SENT + ${BYTES_SENT:-0}))
        TOTAL_BYTES_RECV=$((TOTAL_BYTES_RECV + ${BYTES_RECV:-0}))
        TOTAL_ERRORS=$((TOTAL_ERRORS + ${ERRORS:-0}))
    fi
done

echo ""
echo "=== TOTAL ==="
echo "  Messages sent:   ${TOTAL_SENT}"
echo "  Messages recv:   ${TOTAL_RECV}"
echo "  Bytes sent:      ${TOTAL_BYTES_SENT}"
echo "  Bytes recv:      ${TOTAL_BYTES_RECV}"
echo "  Total errors:    ${TOTAL_ERRORS}"

if [ ${TOTAL_ERRORS} -eq 0 ]; then
    echo ""
    echo "✅ All channels completed successfully!"
else
    echo ""
    echo "⚠️  Some errors occurred. Check logs in /tmp/multi_stress_*/"
fi

# Calculate aggregate rates
if [ $DURATION -gt 0 ]; then
    MSG_RATE=$(echo "scale=2; ${TOTAL_SENT} / ${DURATION}" | bc)
    BYTES_RATE=$(echo "scale=2; ${TOTAL_BYTES_SENT} / ${DURATION} / 1024" | bc)
    echo ""
    echo "Aggregate rate: ${MSG_RATE} msg/s, ${BYTES_RATE} KB/s"
fi

echo ""
echo "Logs available at: /tmp/multi_stress_*/"

