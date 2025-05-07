#!/bin/bash
# build.sh - Build script for Network Scanner Tool

# Exit on errors
set -e

# Create build directory if it doesn't exist
mkdir -p build
cd build

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for required dependencies
echo -e "${YELLOW}Checking for required dependencies...${NC}"

# Check for compiler
if ! command -v g++ &> /dev/null; then
    echo -e "${RED}Error: g++ compiler not found. Please install g++.${NC}"
    exit 1
fi

# Check for OpenSSL
if ! pkg-config --exists openssl; then
    echo -e "${RED}Error: OpenSSL development files not found. Please install libssl-dev.${NC}"
    exit 1
fi

# Check for CLI11 (header-only library)
if [ ! -f "../include/CLI/CLI.hpp" ]; then
    echo -e "${YELLOW}CLI11 not found. Downloading...${NC}"
    mkdir -p ../include/CLI
    wget -q -O ../include/CLI/CLI.hpp https://github.com/CLIUtils/CLI11/releases/download/v2.3.2/CLI11.hpp
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to download CLI11. Please download it manually.${NC}"
        exit 1
    fi
    echo -e "${GREEN}CLI11 downloaded successfully.${NC}"
fi

# Configuration options
BUILD_TYPE="Release"
if [ "$1" == "debug" ]; then
    BUILD_TYPE="Debug"
    echo -e "${YELLOW}Building in Debug mode${NC}"
else
    echo -e "${YELLOW}Building in Release mode${NC}"
fi

# Use CMake if available, otherwise direct g++ command
if command -v cmake &> /dev/null; then
    echo -e "${YELLOW}Using CMake build system${NC}"

    # Generate CMake build files
    cmake .. \
        -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
        -DCMAKE_CXX_STANDARD=17

    # Build with make, using all available cores
    cmake --build . -- -j$(nproc)

    echo -e "${GREEN}Build completed successfully!${NC}"
    echo -e "Executable located at: ${YELLOW}$(pwd)/network_scanner${NC}"
else
    echo -e "${YELLOW}CMake not found, using direct compilation${NC}"

    # Set compiler flags based on build type
    CXXFLAGS="-std=c++17 -Wall -Wextra"
    if [ "$BUILD_TYPE" == "Debug" ]; then
        CXXFLAGS="$CXXFLAGS -g -O0"
    else
        CXXFLAGS="$CXXFLAGS -O2"
    fi

    # Get OpenSSL flags
    SSL_CFLAGS=$(pkg-config --cflags openssl)
    SSL_LIBS=$(pkg-config --libs openssl)

    # Compile
    echo -e "${YELLOW}Compiling network_scanner...${NC}"
    g++ $CXXFLAGS -I../include $SSL_CFLAGS -pthread \
        -o network_scanner ../src/*.cpp \
        $SSL_LIBS

    echo -e "${GREEN}Build completed successfully!${NC}"
    echo -e "Executable located at: ${YELLOW}$(pwd)/network_scanner${NC}"
fi

# Return to original directory
cd ..

# Show usage information
echo -e "\n${YELLOW}Usage:${NC}"
echo -e "  ${GREEN}./build/network_scanner --help${NC} - Show help information"
echo -e "  ${GREEN}./build/network_scanner --target 192.168.1.0/24 --port 80 --port 443 --protocol TCP${NC} - Sample scan"
