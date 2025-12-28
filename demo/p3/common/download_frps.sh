#!/bin/bash
#
# download_frps.sh - Download and install FRPS binary for current platform
#
# Usage:
#   ./download_frps.sh [version]
#
# Examples:
#   ./download_frps.sh          # Download latest release
#   ./download_frps.sh 0.62.1   # Download specific version
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
FRPS_PATH="${BUILD_DIR}/frps"

# FRP version (default: latest)
VERSION="${1:-0.62.1}"

# Detect platform
detect_platform() {
    local os arch
    
    case "$(uname -s)" in
        Linux)
            os="linux"
            ;;
        Darwin)
            os="darwin"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            os="windows"
            ;;
        *)
            echo "Error: Unsupported OS: $(uname -s)"
            exit 1
            ;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64)
            arch="amd64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        armv7l)
            arch="arm"
            ;;
        i386|i686)
            arch="386"
            ;;
        *)
            echo "Error: Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
    
    echo "${os}_${arch}"
}

# Download FRP release
download_frp() {
    local platform="$1"
    local version="$2"
    local ext="tar.gz"
    
    if [[ "$platform" == windows_* ]]; then
        ext="zip"
    fi
    
    local filename="frp_${version}_${platform}.${ext}"
    local url="https://github.com/fatedier/frp/releases/download/v${version}/${filename}"
    
    echo "=============================================="
    echo "  FRPS Downloader"
    echo "=============================================="
    echo "Version:  ${version}"
    echo "Platform: ${platform}"
    echo "URL:      ${url}"
    echo "Target:   ${FRPS_PATH}"
    echo "=============================================="
    echo ""
    
    # Create temp directory
    local tmp_dir=$(mktemp -d)
    local tmp_file="${tmp_dir}/${filename}"
    
    echo "Downloading ${filename}..."
    if command -v curl &> /dev/null; then
        curl -L -o "${tmp_file}" "${url}"
    elif command -v wget &> /dev/null; then
        wget -O "${tmp_file}" "${url}"
    else
        echo "Error: Neither curl nor wget found"
        exit 1
    fi
    
    echo "Extracting..."
    mkdir -p "${BUILD_DIR}"
    cd "${tmp_dir}"
    
    if [[ "$ext" == "tar.gz" ]]; then
        tar -xzf "${filename}"
    else
        unzip -q "${filename}"
    fi
    
    # Find and copy frps binary
    local frps_bin=$(find . -name "frps" -o -name "frps.exe" | head -1)
    if [[ -z "$frps_bin" ]]; then
        echo "Error: frps binary not found in archive"
        exit 1
    fi
    
    cp "$frps_bin" "${FRPS_PATH}"
    chmod +x "${FRPS_PATH}"
    
    # Cleanup
    cd /
    rm -rf "${tmp_dir}"
    
    echo ""
    echo "✅ FRPS installed successfully!"
    echo "   Location: ${FRPS_PATH}"
    echo "   Version:  $(${FRPS_PATH} -v 2>&1 || echo ${version})"
    echo ""
}

# Main
main() {
    local platform=$(detect_platform)
    
    # Check if already exists
    if [[ -f "${FRPS_PATH}" ]]; then
        echo "FRPS already exists at ${FRPS_PATH}"
        echo "Current version: $(${FRPS_PATH} -v 2>&1 || echo 'unknown')"
        read -p "Do you want to re-download? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Skipping download."
            exit 0
        fi
    fi
    
    download_frp "$platform" "$VERSION"
}

main

