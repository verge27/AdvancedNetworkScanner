 Advanced Network Scanner

![C++](https://img.shields.io/badge/language-C++17-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

## Overview

`AdvancedNetworkScanner` is a powerful, multithreaded network scanning tool built in modern C++. It goes beyond simple port scans to provide deep protocol analysis, SSL/TLS inspection, DNSSEC validation, passive OS fingerprinting, geolocation and real-time threat intelligence lookups.

Designed for security researchers, sysadmins, and privacy-focused developers, this tool emphasizes both thoroughness and modularity, while maintaining a clean command-line interface.

---

## ✨ Features

- 🔁 **Multithreaded Scanning** — Accelerated performance across large IP ranges.
- 🌐 **Protocol Detection** — Supports TCP, UDP, QUIC, MQTT, CoAP, and more.
- 🔐 **SSL/TLS Analysis** — Validates certs, expiration, ciphers, and common names.
- 🧠 **Passive OS Fingerprinting** — Infers OS without intrusive packet crafting.
- 🌍 **GeoIP + ISP Lookup** — Contextual info for each host from offline database.
- ⚠️ **Threat Intelligence Integration** — Flags IPs from threat feeds (e.g. VirusTotal-style).
- 🔎 **DNS + DNSSEC Analysis** — Detects potential spoofing or misconfigurations.
- 📊 **Export Options** — Output to text, JSON, CSV or XML.
- 🛠️ **RAII Resource Management** — All sockets, memory and threads safely managed.

---

## 🔧 Build Instructions

### Dependencies

- **C++17** or higher
- [CLI11](https://github.com/CLIUtils/CLI11) (for argument parsing)
- **OpenSSL**
- A C++ compiler (e.g. `g++`, `clang++`, or MSVC)

### Linux

```bash
sudo apt update
sudo apt install libssl-dev g++ cmake -y
git clone https://github.com/yourusername/AdvancedNetworkScanner.git
cd AdvancedNetworkScanner
mkdir build && cd build
cmake ..
make
./scanner --help
