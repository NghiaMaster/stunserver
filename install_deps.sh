#!/bin/bash

# Detect package manager
if command -v pacman &> /dev/null; then
    # Arch Linux
    pacman -Sy --noconfirm \
        curl \
        nlohmann-json
else
    # Debian/Ubuntu
    apt-get update
    apt-get install -y \
        libcurl4-openssl-dev \
        nlohmann-json3-dev
fi

# Verify installations
if ! pkg-config --exists libcurl; then
    echo "Failed to install libcurl"
    exit 1
fi

if ! pkg-config --exists nlohmann_json; then
    echo "Failed to install nlohmann-json"
    exit 1
fi

echo "Dependencies installed successfully" 