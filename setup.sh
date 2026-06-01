#!/bin/bash
set -e

# --- Configuration ---
INTERFACE="isla0"
HOST_IP="192.168.1.1/24"
HOST_MAC="00:11:22:33:44:55"
PROJECT_NAME="isla"

# --- Argument Parsing ---
MODE="release"
BUILD_FLAG="--release"
TARGET_DIR="release"

if [[ "$1" == "--debug" ]]; then
    MODE="debug"
    BUILD_FLAG=""
    TARGET_DIR="debug"
fi

BINARY="./target/$TARGET_DIR/$PROJECT_NAME"

echo "========================================"
echo "   Project Isla: Environment Setup"
echo "   Mode: $MODE"
echo "========================================"

# --- Step 1: Build the Stack (As User) ---
echo "[*] Building binary..."
if cargo build $BUILD_FLAG; then
    echo "[✔] Build successful."
else
    echo "[✘] Build failed! Aborting."
    exit 1
fi

# --- Step 2: Network Configuration (Requires Sudo) ---
cleanup() {
    echo ""
    echo "[*] Shutting down..."
    # Only delete if it exists
    if ip link show $INTERFACE > /dev/null 2>&1; then
        sudo ip link delete $INTERFACE
        echo "[✔] Interface $INTERFACE removed."
    fi
}

# Trap Ctrl+C (SIGINT) to ensure cleanup runs
trap cleanup SIGINT

echo "[*] Configuring Network Interface..."

# Check if interface exists and reset it
if ip link show $INTERFACE > /dev/null 2>&1; then
    echo "    [-] Removing existing $INTERFACE..."
    sudo ip link delete $INTERFACE
fi

# Create TAP
sudo ip tuntap add mode tap name $INTERFACE
echo "    [+] Created TAP interface: $INTERFACE"

# Assign IP & MAC
sudo ip addr add $HOST_IP dev $INTERFACE
sudo ip link set dev $INTERFACE address $HOST_MAC
echo "    [+] Host IP assigned: $HOST_IP"
echo "    [+] Host MAC static:  $HOST_MAC"

# Bring Up
sudo ip link set dev $INTERFACE up
echo "    [+] Interface is UP"

# --- Step 3: Permissions & Launch ---
echo "[*] Setting Capabilities..."
if [ -f "$BINARY" ]; then
    # Give the binary permission to use network interfaces without running as full root
    sudo setcap cap_net_admin,cap_net_raw+eip "$BINARY"
    echo "    [+] Capabilities set on $BINARY"
else
    echo "[✘] Critical Error: Binary not found at $BINARY"
    cleanup
    exit 1
fi

echo "========================================"
echo "   Isla Stack Launching..."
echo "   (Ctrl+C to stop and cleanup)"
echo "========================================"

# Launch the binary
"$BINARY"

cleanup
