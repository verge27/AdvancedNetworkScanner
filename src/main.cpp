#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <atomic>
#include <memory>
#include <cstring>
#include <ctime>
#include <regex>
#include <optional>
#include <string_view>
#include <filesystem>
#include <functional>
#include <stdexcept>

// Modern CLI parser
#include <CLI/CLI.hpp>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    typedef SOCKET socket_t;
    #define CLOSE_SOCKET closesocket
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <ifaddrs.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    typedef int socket_t;
    #define CLOSE_SOCKET close
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

// Forward declarations
class NetworkScanner;
class OutputManager;
class ThreatIntelligence;

// Version and constants
constexpr auto VERSION = "1.0.0";
constexpr size_t DEFAULT_BUFFER_SIZE = 1024;
constexpr int DEFAULT_TIMEOUT_MS = 1000;
constexpr int DEFAULT_SSL_TIMEOUT_SEC = 2;

// Output formats
enum class OutputFormat {
    TEXT,
    JSON,
    CSV,
    XML
};

// Protocol types
enum class Protocol {
    TCP,
    UDP,
    QUIC,
    MQTT,
    COAP,
    DNS,
    DNSSEC,
    HTTP,
    HTTPS,
    FTP,
    SSH,
    TELNET,
    SMTP,
    POP3,
    IMAP,
    OTHER
};

// Structure to represent scan results for a single host
struct HostScanResult {
    std::string ipAddress;
    std::string hostname;
    std::string osInfo;
    std::string location;
    std::string isp;
    std::vector<std::pair<int, Protocol>> openPorts;
    std::map<int, std::string> bannerInfo;
    std::map<int, std::map<std::string, std::string>> sslInfo;
    std::map<std::string, std::string> dnsInfo;
    bool isUp;
    float responseTime; // in milliseconds
    std::map<std::string, std::string> threatInfo;

    HostScanResult() : isUp(false), responseTime(0.0f) {}
};

// RAII wrappers for resources
namespace ResourceGuard {
    // Socket RAII wrapper
    class SocketGuard {
    public:
        explicit SocketGuard(socket_t sock_fd) : fd_(sock_fd) {}
        ~SocketGuard() {
            if (fd_ != INVALID_SOCKET) {
                CLOSE_SOCKET(fd_);
            }
        }

        // Delete copy operators
        SocketGuard(const SocketGuard&) = delete;
        SocketGuard& operator=(const SocketGuard&) = delete;

        // Move operators
        SocketGuard(SocketGuard&& other) noexcept : fd_(other.fd_) {
            other.fd_ = INVALID_SOCKET; // Transfer ownership
        }

        SocketGuard& operator=(SocketGuard&& other) noexcept {
            if (this != &other) {
                if (fd_ != INVALID_SOCKET) {
                    CLOSE_SOCKET(fd_);
                }
                fd_ = other.fd_;
                other.fd_ = INVALID_SOCKET;
            }
            return *this;
        }

        socket_t get() const { return fd_; }
        bool isValid() const { return fd_ != INVALID_SOCKET; }

    private:
        socket_t fd_;
    };

    // OpenSSL resource deleters
    struct SSL_CTX_deleter {
        void operator()(SSL_CTX* ctx) const { if(ctx) SSL_CTX_free(ctx); }
    };

    struct SSL_deleter {
        void operator()(SSL* ssl) const { if(ssl) SSL_free(ssl); }
    };

    struct X509_deleter {
        void operator()(X509* x509) const { if(x509) X509_free(x509); }
    };

    struct BIO_deleter {
        void operator()(BIO* bio) const { if(bio) BIO_free(bio); }
    };

    // Typedefs for OpenSSL smart pointers
    using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, SSL_CTX_deleter>;
    using SSL_ptr = std::unique_ptr<SSL, SSL_deleter>;
    using X509_ptr = std::unique_ptr<X509, X509_deleter>;
    using BIO_ptr = std::unique_ptr<BIO, BIO_deleter>;
}

// Error handling utilities
namespace ErrorHandling {
    // Get error message for socket operations
    std::string getSocketErrorMsg() {
        #ifdef _WIN32
            int errCode = WSAGetLastError();
            char* msgBuf = nullptr;
            FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&msgBuf, 0, NULL);
            std::string errorMsg = msgBuf ? msgBuf : "Unknown error";
            LocalFree(msgBuf);
            return "Error " + std::to_string(errCode) + ": " + errorMsg;
        #else
            return "Error " + std::to_string(errno) + ": " + strerror(errno);
        #endif
    }

    // Get OpenSSL error message
    std::string getOpenSSLErrorMsg() {
        std::string errorMsg;
        unsigned long errCode;
        char errBuf[256];

        while ((errCode = ERR_get_error()) != 0) {
            ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
            if (!errorMsg.empty()) {
                errorMsg += "; ";
            }
            errorMsg += errBuf;
        }

        return errorMsg.empty() ? "Unknown OpenSSL error" : errorMsg;
    }

    // Exception classes
    class NetworkException : public std::runtime_error {
    public:
        explicit NetworkException(const std::string& message) 
            : std::runtime_error("Network error: " + message) {}
    };

    class SSLException : public std::runtime_error {
    public:
        explicit SSLException(const std::string& message) 
            : std::runtime_error("SSL error: " + message) {}
    };

    class ConfigException : public std::runtime_error {
    public:
        explicit ConfigException(const std::string& message) 
            : std::runtime_error("Configuration error: " + message) {}
    };
}

// Utility functions
namespace Utils {
    std::vector<std::string> parseIPRange(std::string_view range) {
        std::vector<std::string> ips;
        std::string rangeStr(range);

        try {
            // Check if it's a CIDR notation
            size_t cidrPos = rangeStr.find('/');
            if (cidrPos != std::string::npos) {
                // Extract the base IP and prefix length
                std::string baseIP = rangeStr.substr(0, cidrPos);
                int prefixLen = std::stoi(rangeStr.substr(cidrPos + 1));

                if (prefixLen < 0 || prefixLen > 32) {
                    throw ErrorHandling::ConfigException("Invalid CIDR prefix length: " + std::to_string(prefixLen));
                }

                // Convert IP to integer
                struct in_addr addr;
                if (inet_pton(AF_INET, baseIP.c_str(), &addr) != 1) {
                    throw ErrorHandling::ConfigException("Invalid IP address in CIDR notation: " + baseIP);
                }

                uint32_t ip = ntohl(addr.s_addr);

                // Calculate the number of IPs in this range
                uint32_t mask = (0xFFFFFFFF << (32 - prefixLen)) & 0xFFFFFFFF;
                uint32_t network = ip & mask;
                uint32_t broadcast = network | (~mask & 0xFFFFFFFF);

                // Generate all IPs in the range
                for (uint32_t i = network + 1; i < broadcast; i++) {
                    addr.s_addr = htonl(i);
                    ips.push_back(inet_ntoa(addr));
                }
            } else if (rangeStr.find('-') != std::string::npos) {
                // It's a range like 192.168.1.1-192.168.1.254
                size_t dashPos = rangeStr.find('-');
                std::string startIP = rangeStr.substr(0, dashPos);
                std::string endIP = rangeStr.substr(dashPos + 1);

                struct in_addr addr1, addr2;
                if (inet_pton(AF_INET, startIP.c_str(), &addr1) != 1) {
                    throw ErrorHandling::ConfigException("Invalid start IP address: " + startIP);
                }
                if (inet_pton(AF_INET, endIP.c_str(), &addr2) != 1) {
                    throw ErrorHandling::ConfigException("Invalid end IP address: " + endIP);
                }

                uint32_t start = ntohl(addr1.s_addr);
                uint32_t end = ntohl(addr2.s_addr);

                if (start > end) {
                    throw ErrorHandling::ConfigException("Start IP must be less than or equal to end IP");
                }

                for (uint32_t i = start; i <= end; i++) {
                    addr1.s_addr = htonl(i);
                    ips.push_back(inet_ntoa(addr1));
                }
            } else {
                // It's a single IP
                struct in_addr addr;
                if (inet_pton(AF_INET, rangeStr.c_str(), &addr) != 1) {
                    throw ErrorHandling::ConfigException("Invalid IP address: " + rangeStr);
                }
                ips.push_back(rangeStr);
            }
        } catch (const std::exception& e) {
            throw ErrorHandling::ConfigException(std::string("Error parsing IP range: ") + e.what());
        }

        return ips;
    }

    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    std::string protocolToString(Protocol protocol) {
        switch (protocol) {
            case Protocol::TCP: return "TCP";
            case Protocol::UDP: return "UDP";
            case Protocol::QUIC: return "QUIC";
            case Protocol::MQTT: return "MQTT";
            case Protocol::COAP: return "CoAP";
            case Protocol::DNS: return "DNS";
            case Protocol::DNSSEC: return "DNSSEC";
            case Protocol::HTTP: return "HTTP";
            case Protocol::HTTPS: return "HTTPS";
            case Protocol::FTP: return "FTP";
            case Protocol::SSH: return "SSH";
            case Protocol::TELNET: return "TELNET";
            case Protocol::SMTP: return "SMTP";
            case Protocol::POP3: return "POP3";
            case Protocol::IMAP: return "IMAP";
            default: return "OTHER";
        }
    }

    Protocol stringToProtocol(std::string_view str) {
        if (str == "TCP") return Protocol::TCP;
        if (str == "UDP") return Protocol::UDP;
        if (str == "QUIC") return Protocol::QUIC;
        if (str == "MQTT") return Protocol::MQTT;
        if (str == "CoAP") return Protocol::COAP;
        if (str == "DNS") return Protocol::DNS;
        if (str == "DNSSEC") return Protocol::DNSSEC;
        if (str == "HTTP") return Protocol::HTTP;
        if (str == "HTTPS") return Protocol::HTTPS;
        if (str == "FTP") return Protocol::FTP;
        if (str == "SSH") return Protocol::SSH;
        if (str == "TELNET") return Protocol::TELNET;
        if (str == "SMTP") return Protocol::SMTP;
        if (str == "POP3") return Protocol::POP3;
        if (str == "IMAP") return Protocol::IMAP;
        return Protocol::OTHER;
    }

    // DNS resolution with std::optional
    std::optional<std::string> resolveHostname(std::string_view ipAddress) {
        struct sockaddr_in sa;
        char host[NI_MAXHOST];
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ipAddress.data(), &(sa.sin_addr));

        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
            return std::string(host);
        }
        return std::nullopt;
    }

    // Safe buffer for receiving data
    class SafeBuffer {
    private:
        std::vector<char> buffer;

    public:
        explicit SafeBuffer(size_t size = DEFAULT_BUFFER_SIZE) : buffer(size, 0) {}

        char* data() { return buffer.data(); }
        const char* data() const { return buffer.data(); }
        size_t size() const { return buffer.size(); }

        void resize(size_t newSize) {
            buffer.resize(newSize, 0);
        }

        std::string toString(size_t length) const {
            if (length > buffer.size()) {
                throw std::out_of_range("Length exceeds buffer size");
            }
            return std::string(buffer.data(), length);
        }

        // Clean buffer for displaying
        std::string toPrintableString(size_t length) const {
            std::string result = toString(length);
            result.erase(std::remove_if(result.begin(), result.end(), 
                [](unsigned char c) { return !std::isprint(c); }), result.end());
            return result;
        }
    };

    // Helper for ASN1_TIME to string conversion
    std::string ASN1_TIME_toString(ASN1_TIME* time) {
        if (!time) return "Invalid time";

        ResourceGuard::BIO_ptr bio(BIO_new(BIO_s_mem()));
        if (!bio) return "Error creating BIO";

        if (!ASN1_TIME_print(bio.get(), time)) {
            return "Error printing time: " + ErrorHandling::getOpenSSLErrorMsg();
        }

        SafeBuffer buffer(100);
        int len = BIO_read(bio.get(), buffer.data(), buffer.size() - 1);
        if (len <= 0) {
            return "Error reading time";
        }

        return buffer.toString(len);
    }

    // String escaping for JSON
    std::string escapeJsonString(const std::string& input) {
        std::string output;
        output.reserve(input.length() * 2); // Rough estimation for escaped string size

        for (char c : input) {
            switch (c) {
                case '\"': output += "\\\""; break;
                case '\\': output += "\\\\"; break;
                case '\b': output += "\\b"; break;
                case '\f': output += "\\f"; break;
                case '\n': output += "\\n"; break;
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 32) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                        output += buf;
                    } else {
                        output += c;
                    }
                    break;
            }
        }

        return output;
    }
}

// Geolocation and ISP identification class
class GeoipService {
private:
    std::map<std::string, std::pair<std::string, std::string>> geoDatabase;
    std::mutex databaseMutex;

    void loadDatabase(const std::filesystem::path& filename) {
        std::lock_guard<std::mutex> lock(databaseMutex);
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw ErrorHandling::ConfigException("Failed to open GeoIP database: " + filename.string());
        }

        std::string line;
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string ip, location, isp;

            if (std::getline(iss, ip, ',') && 
                std::getline(iss, location, ',') && 
                std::getline(iss, isp)) {
                geoDatabase[ip] = std::make_pair(location, isp);
            }
        }
    }

public:
    GeoipService(const std::filesystem::path& databaseFile = "geoip_database.csv") {
        try {
            loadDatabase(databaseFile);
        } catch (const std::exception& e) {
            std::cerr << "Failed to load GeoIP database: " << e.what() << std::endl;
        }
    }

    std::pair<std::string, std::string> lookup(std::string_view ipAddress) {
        std::lock_guard<std::mutex> lock(databaseMutex);
        std::string ipStr(ipAddress);
        auto it = geoDatabase.find(ipStr);
        if (it != geoDatabase.end()) {
            return it->second;
        }

        // If not found, return placeholder values
        return std::make_pair("Unknown Location", "Unknown ISP");
    }
};

// Threat intelligence class
class ThreatIntelligence {
private:
    std::map<std::string, std::map<std::string, std::string>> threatDatabase;
    std::mutex databaseMutex;

    void loadDatabase(const std::filesystem::path& filename) {
        std::lock_guard<std::mutex> lock(databaseMutex);
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw ErrorHandling::ConfigException("Failed to open threat database: " + filename.string());
        }

        std::string line;
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string indicator, type, description;

            if (std::getline(iss, indicator, ',') && 
                std::getline(iss, type, ',') && 
                std::getline(iss, description)) {
                threatDatabase[indicator]["type"] = type;
                threatDatabase[indicator]["description"] = description;
            }
        }
    }

public:
    ThreatIntelligence(const std::filesystem::path& databaseFile = "threat_database.csv") {
        try {
            loadDatabase(databaseFile);
        } catch (const std::exception& e) {
            std::cerr << "Failed to load threat intelligence database: " << e.what() << std::endl;
        }
    }

    std::map<std::string, std::string> lookup(std::string_view indicator) {
        std::lock_guard<std::mutex> lock(databaseMutex);
        std::string indStr(indicator);
        auto it = threatDatabase.find(indStr);
        if (it != threatDatabase.end()) {
            return it->second;
        }
        return {};
    }

    void updateDatabase(const std::filesystem::path& databaseFile = "threat_database.csv") {
        // In a real implementation, this would download the latest threat data
        // from various sources (VirusTotal, OpenPhish, etc.)
        std::cout << "Updating threat intelligence database..." << std::endl;
        try {
            loadDatabase(databaseFile);
            std::cout << "Threat intelligence database updated successfully." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Failed to update threat database: " << e.what() << std::endl;
        }
    }
};

// Output manager class with better structure
class OutputManager {
private:
    OutputFormat format;
    std::filesystem::path outputFile;
    std::mutex outputMutex;

    // Helper methods for breaking down complex output functions
    void writeHostHeaderText(const HostScanResult& host, std::ostream& out) const {
        out << "Host: " << host.ipAddress << "\n";
        if (!host.hostname.empty()) {
            out << "Hostname: " << host.hostname << "\n";
        }
        out << "Status: " << (host.isUp ? "UP" : "DOWN") << "\n";
    }

    void writeHostDetailsText(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp) return;

        out << "Response time: " << host.responseTime << "ms\n";

        if (!host.osInfo.empty()) {
            out << "OS: " << host.osInfo << "\n";
        }

        if (!host.location.empty() || !host.isp.empty()) {
            out << "Location: " << host.location << "\n";
            out << "ISP: " << host.isp << "\n";
        }
    }

    void writePortsInfoText(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp || host.openPorts.empty()) return;

        out << "Open ports:\n";
        for (const auto& [port, protocol] : host.openPorts) {
            out << "  " << port << "/" << Utils::protocolToString(protocol);

            auto bannerIt = host.bannerInfo.find(port);
            if (bannerIt != host.bannerInfo.end()) {
                out << " - " << bannerIt->second;
            }
            out << "\n";
        }
    }

    void writeSSLInfoText(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp || host.sslInfo.empty()) return;

        out << "SSL/TLS Information:\n";
        for (const auto& [port, sslData] : host.sslInfo) {
            out << "  Port " << port << ":\n";
            for (const auto& [field, value] : sslData) {
                out << "    " << field << ": " << value << "\n";
            }
        }
    }

    void writeDNSInfoText(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp || host.dnsInfo.empty()) return;

        out << "DNS Information:\n";
        for (const auto& [field, value] : host.dnsInfo) {
            out << "  " << field << ": " << value << "\n";
        }
    }

    void writeThreatInfoText(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp || host.threatInfo.empty()) return;

        out << "Threat Information:\n";
        for (const auto& [field, value] : host.threatInfo) {
            out << "  " << field << ": " << value << "\n";
        }
    }

    void outputAsText(const std::vector<HostScanResult>& results, std::ostream& out) const {
        out << "=== Network Scanner Results ===\n";
        out << "Scan date: " << Utils::getTimestamp() << "\n";
        out << "Total hosts scanned: " << results.size() << "\n\n";

        for (const auto& host : results) {
            writeHostHeaderText(host, out);
            writeHostDetailsText(host, out);
            writePortsInfoText(host, out);
            writeSSLInfoText(host, out);
            writeDNSInfoText(host, out);
            writeThreatInfoText(host, out);
            out << "\n";
        }
    }

    // JSON output helpers
    void writeHostJsonHeader(const HostScanResult& host, std::ostream& out) const {
        out << "    {\n";
        out << "      \"ipAddress\": \"" << host.ipAddress << "\",\n";
        out << "      \"hostname\": \"" << host.hostname << "\",\n";
        out << "      \"status\": \"" << (host.isUp ? "UP" : "DOWN") << "\"";
    }

    void writeHostJsonDetails(const HostScanResult& host, std::ostream& out) const {
        if (host.isUp) {
            out << ",\n      \"responseTime\": " << host.responseTime << ",\n";
            out << "      \"osInfo\": \"" << Utils::escapeJsonString(host.osInfo) << "\",\n";
            out << "      \"location\": \"" << Utils::escapeJsonString(host.location) << "\",\n";
            out << "      \"isp\": \"" << Utils::escapeJsonString(host.isp) << "\"";
        } else {
            out << ",\n      \"responseTime\": null,\n";
            out << "      \"osInfo\": null,\n";
            out << "      \"location\": null,\n";
            out << "      \"isp\": null";
        }
    }

    void writePortsJsonArray(const HostScanResult& host, std::ostream& out) const {
        out << ",\n      \"openPorts\": [";
        if (host.isUp && !host.openPorts.empty()) {
            out << "\n";
            for (size_t i = 0; i < host.openPorts.size(); ++i) {
                const auto& [port, protocol] = host.openPorts[i];
                out << "        {\n";
                out << "          \"port\": " << port << ",\n";
                out << "          \"protocol\": \"" << Utils::protocolToString(protocol) << "\"";

                auto bannerIt = host.bannerInfo.find(port);
                if (bannerIt != host.bannerInfo.end()) {
                    out << ",\n          \"banner\": \"" << Utils::escapeJsonString(bannerIt->second) << "\"";
                }

                out << "\n        }";
                if (i < host.openPorts.size() - 1) out << ",";
                out << "\n";
            }
            out << "      ";
        }
        out << "]";
    }

    void writeSSLJsonObject(const HostScanResult& host, std::ostream& out) const {
        out << ",\n      \"sslInfo\": {";
        if (host.isUp && !host.sslInfo.empty()) {
            out << "\n";
            size_t count = 0;
            for (const auto& [port, sslData] : host.sslInfo) {
                out << "        \"" << port << "\": {\n";
                size_t fieldCount = 0;
                for (const auto& [field, value] : sslData) {
                    out << "          \"" << field << "\": \"" << Utils::escapeJsonString(value) << "\"";
                    if (++fieldCount < sslData.size()) out << ",";
                    out << "\n";
                }
                out << "        }";
                if (++count < host.sslInfo.size()) out << ",";
                out << "\n";
            }
            out << "      ";
        }
        out << "}";
    }

    void writeDNSJsonObject(const HostScanResult& host, std::ostream& out) const {
        out << ",\n      \"dnsInfo\": {";
        if (host.isUp && !host.dnsInfo.empty()) {
            out << "\n";
            size_t count = 0;
            for (const auto& [field, value] : host.dnsInfo) {
                out << "        \"" << field << "\": \"" << Utils::escapeJsonString(value) << "\"";
                if (++count < host.dnsInfo.size()) out << ",";
                out << "\n";
            }
            out << "      ";
        }
        out << "}";
    }

    void writeThreatJsonObject(const HostScanResult& host, std::ostream& out) const {
        out << ",\n      \"threatInfo\": {";
        if (host.isUp && !host.threatInfo.empty()) {
            out << "\n";
            size_t count = 0;
            for (const auto& [field, value] : host.threatInfo) {
                out << "        \"" << field << "\": \"" << Utils::escapeJsonString(value) << "\"";
                if (++count < host.threatInfo.size()) out << ",";
                out << "\n";
            }
            out << "      ";
        }
        out << "}";
    }

    void outputAsJson(const std::vector<HostScanResult>& results, std::ostream& out) const {
        out << "{\n";
        out << "  \"scanDate\": \"" << Utils::getTimestamp() << "\",\n";
        out << "  \"totalHosts\": " << results.size() << ",\n";
        out << "  \"hosts\": [\n";

        for (size_t i = 0; i < results.size(); ++i) {
            const auto& host = results[i];
            writeHostJsonHeader(host, out);
            writeHostJsonDetails(host, out);
            writePortsJsonArray(host, out);
            writeSSLJsonObject(host, out);
            writeDNSJsonObject(host, out);
            writeThreatJsonObject(host, out);

            out << "\n    }";
            if (i < results.size() - 1) out << ",";
            out << "\n";
        }

        out << "  ]\n";
        out << "}\n";
    }

    // Helper for formatting CSV values
    std::string formatCsvValue(const std::string& value) const {
        // If the value contains commas, quotes, or newlines, wrap it in quotes
        // and escape any existing quotes
        if (value.find(',') != std::string::npos || 
            value.find('"') != std::string::npos || 
            value.find('\n') != std::string::npos) {

            std::string escaped = value;
            // Replace " with ""
            size_t pos = 0;
            while ((pos = escaped.find('"', pos)) != std::string::npos) {
                escaped.replace(pos, 1, "\"\"");
                pos += 2;
            }
            return "\"" + escaped + "\"";
        }
        return value;
    }

    std::string formatPortsForCsv(const HostScanResult& host) const {
        if (!host.isUp || host.openPorts.empty()) return "";

        std::ostringstream oss;
        for (size_t i = 0; i < host.openPorts.size(); ++i) {
            const auto& [port, protocol] = host.openPorts[i];
            oss << port << "/" << Utils::protocolToString(protocol);

            auto bannerIt = host.bannerInfo.find(port);
            if (bannerIt != host.bannerInfo.end()) {
                oss << " (" << bannerIt->second << ")";
            }

            if (i < host.openPorts.size() - 1) oss << "; ";
        }
        return formatCsvValue(oss.str());
    }

    std::string formatSSLForCsv(const HostScanResult& host) const {
        if (!host.isUp || host.sslInfo.empty()) return "";

        std::ostringstream oss;
        size_t count = 0;
        for (const auto& [port, sslData] : host.sslInfo) {
            oss << "Port " << port << ": ";
            size_t fieldCount = 0;
            for (const auto& [field, value] : sslData) {
                oss << field << "=" << value;
                if (++fieldCount < sslData.size()) oss << ", ";
            }
            if (++count < host.sslInfo.size()) oss << "; ";
        }
        return formatCsvValue(oss.str());
    }

    std::string formatDNSForCsv(const HostScanResult& host) const {
        if (!host.isUp || host.dnsInfo.empty()) return "";

        std::ostringstream oss;
        size_t count = 0;
        for (const auto& [field, value] : host.dnsInfo) {
            oss << field << "=" << value;
            if (++count < host.dnsInfo.size()) oss << "; ";
        }
        return formatCsvValue(oss.str());
    }

    std::string formatThreatForCsv(const HostScanResult& host) const {
        if (!host.isUp || host.threatInfo.empty()) return "";

        std::ostringstream oss;
        size_t count = 0;
        for (const auto& [field, value] : host.threatInfo) {
            oss << field << "=" << value;
            if (++count < host.threatInfo.size()) oss << "; ";
        }
        return formatCsvValue(oss.str());
    }

    void outputAsCsv(const std::vector<HostScanResult>& results, std::ostream& out) const {
        out << "IP Address,Hostname,Status,Response Time (ms),OS,Location,ISP,Open Ports,SSL Info,DNS Info,Threat Info\n";

        for (const auto& host : results) {
            out << host.ipAddress << ",";
            out << formatCsvValue(host.hostname) << ",";
            out << (host.isUp ? "UP" : "DOWN") << ",";

            if (host.isUp) {
                out << host.responseTime << ",";
                out << formatCsvValue(host.osInfo) << ",";
                out << formatCsvValue(host.location) << ",";
                out << formatCsvValue(host.isp) << ",";
                out << formatPortsForCsv(host) << ",";
                out << formatSSLForCsv(host) << ",";
                out << formatDNSForCsv(host) << ",";
                out << formatThreatForCsv(host);
            } else {
                out << ",,,,,,,,";
            }

            out << "\n";
        }
    }

    // XML output helpers
    void writeHostXmlHeader(const HostScanResult& host, std::ostream& out) const {
        out << "  <host>\n";
        out << "    <ipAddress>" << host.ipAddress << "</ipAddress>\n";
        out << "    <hostname>" << host.hostname << "</hostname>\n";
        out << "    <status>" << (host.isUp ? "UP" : "DOWN") << "</status>\n";
    }

    void writeHostXmlDetails(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp) return;

        out << "    <responseTime>" << host.responseTime << "</responseTime>\n";

        if (!host.osInfo.empty()) {
            out << "    <os>" << host.osInfo << "</os>\n";
        }

        if (!host.location.empty() || !host.isp.empty()) {
            out << "    <location>" << host.location << "</location>\n";
            out << "    <isp>" << host.isp << "</isp>\n";
        }
    }

    void writePortsXml(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp || host.openPorts.empty()) return;

        out << "    <openPorts>\n";
        for (const auto& [port, protocol] : host.openPorts) {
            out << "      <port number=\"" << port << "\" protocol=\"" << Utils::protocolToString(protocol) << "\">";

            auto bannerIt = host.bannerInfo.find(port);
            if (bannerIt != host.bannerInfo.end()) {
                out << "<banner>" << bannerIt->second << "</banner>";
            }

            out << "</port>\n";
        }
        out << "    </openPorts>\n";
    }

    void writeSSLXml(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp || host.sslInfo.empty()) return;

        out << "    <sslInfo>\n";
        for (const auto& [port, sslData] : host.sslInfo) {
            out << "      <port number=\"" << port << "\">\n";
            for (const auto& [field, value] : sslData) {
                out << "        <" << field << ">" << value << "</" << field << ">\n";
            }
            out << "      </port>\n";
        }
        out << "    </sslInfo>\n";
    }

    void writeDNSXml(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp || host.dnsInfo.empty()) return;

        out << "    <dnsInfo>\n";
        for (const auto& [field, value] : host.dnsInfo) {
            out << "      <" << field << ">" << value << "</" << field << ">\n";
        }
        out << "    </dnsInfo>\n";
    }

    void writeThreatXml(const HostScanResult& host, std::ostream& out) const {
        if (!host.isUp || host.threatInfo.empty()) return;

        out << "    <threatInfo>\n";
        for (const auto& [field, value] : host.threatInfo) {
            out << "      <" << field << ">" << value << "</" << field << ">\n";
        }
        out << "    </threatInfo>\n";
    }

    void outputAsXml(const std::vector<HostScanResult>& results, std::ostream& out) const {
        out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        out << "<networkScan date=\"" << Utils::getTimestamp() << "\" totalHosts=\"" << results.size() << "\">\n";

        for (const auto& host : results) {
            writeHostXmlHeader(host, out);
            writeHostXmlDetails(host, out);
            writePortsXml(host, out);
            writeSSLXml(host, out);
            writeDNSXml(host, out);
            writeThreatXml(host, out);
            out << "  </host>\n";
        }

        out << "</networkScan>\n";
    }

public:
    OutputManager(OutputFormat fmt = OutputFormat::TEXT, const std::filesystem::path& outFile = "")
        : format(fmt), outputFile(outFile) {}

    void output(const std::vector<HostScanResult>& results) {
        std::lock_guard<std::mutex> lock(outputMutex);

        try {
            if (outputFile.empty()) {
                // Output to console
                if (format == OutputFormat::TEXT) {
                    outputAsText(results, std::cout);
                } else if (format == OutputFormat::JSON) {
                    outputAsJson(results, std::cout);
                } else if (format == OutputFormat::CSV) {
                    outputAsCsv(results, std::cout);
                } else if (format == OutputFormat::XML) {
                    outputAsXml(results, std::cout);
                }
            } else {
                // Output to file
                std::ofstream file(outputFile);
                if (!file) {
                    throw ErrorHandling::ConfigException("Failed to open output file: " + outputFile.string());
                }

                if (format == OutputFormat::TEXT) {
                    outputAsText(results, file);
                } else if (format == OutputFormat::JSON) {
                    outputAsJson(results, file);
                } else if (format == OutputFormat::CSV) {
                    outputAsCsv(results, file);
                } else if (format == OutputFormat::XML) {
                    outputAsXml(results, file);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error during output: " << e.what() << std::endl;
        }
    }

    void setFormat(OutputFormat fmt) {
        format = fmt;
    }

    void setOutputFile(const std::filesystem::path& outFile) {
        outputFile = outFile;
    }
};

// Network scanner class with improved structure
class NetworkScanner {
private:
    int timeout; // in milliseconds
    int numThreads;
    std::vector<std::string> targetHosts;
    std::vector<int> targetPorts;
    std::vector<Protocol> targetProtocols;
    std::mutex resultsMutex;
    std::vector<HostScanResult> results;
    GeoipService geoipService;
    ThreatIntelligence threatIntelligence;
    bool enableDnsAnalysis;
    bool enableOsFingerprinting;
    bool enableSslAnalysis;

    // Initialize and cleanup networking libraries
    static void initializeNetworking() {
        #ifdef _WIN32
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                throw ErrorHandling::NetworkException("Failed to initialize Winsock: " + ErrorHandling::getSocketErrorMsg());
            }
        #endif

        // Initialize OpenSSL
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_crypto_strings();
    }

    static void cleanupNetworking() {
        #ifdef _WIN32
            WSACleanup();
        #endif

        // Cleanup OpenSSL
        ERR_free_strings();
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
    }

    // Improved host availability check
    bool isHostUp(const std::string& ipAddress, float& responseTime) {
        socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            return false;
        }

        ResourceGuard::SocketGuard sockGuard(s);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80); // Try connecting to port 80 (HTTP)
        if (inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr) != 1) {
            return false;
        }

        // Set socket to non-blocking
        #ifdef _WIN32
            u_long mode = 1;
            if (ioctlsocket(sockGuard.get(), FIONBIO, &mode) != 0) {
                return false;
            }
        #else
            int flags = fcntl(sockGuard.get(), F_GETFL, 0);
            if (flags == -1 || fcntl(sockGuard.get(), F_SETFL, flags | O_NONBLOCK) == -1) {
                return false;
            }
        #endif

        auto startTime = std::chrono::high_resolution_clock::now();

        // Try to connect
        connect(sockGuard.get(), (struct sockaddr*)&addr, sizeof(addr));

        // Wait for the socket to be ready
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sockGuard.get(), &fdset);

        struct timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        int result = select(sockGuard.get() + 1, NULL, &fdset, NULL, &tv);
        auto endTime = std::chrono::high_resolution_clock::now();

        responseTime = std::chrono::duration<float, std::milli>(endTime - startTime).count();

        return (result > 0);
    }

    // Improved TCP port scanning
    bool scanTcpPort(const std::string& ipAddress, int port, std::string& banner) {
        socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            return false;
        }

        ResourceGuard::SocketGuard sockGuard(s);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr) != 1) {
            return false;
        }

        // Set socket to non-blocking
        #ifdef _WIN32
            u_long mode = 1;
            if (ioctlsocket(sockGuard.get(), FIONBIO, &mode) != 0) {
                return false;
            }
        #else
            int flags = fcntl(sockGuard.get(), F_GETFL, 0);
            if (flags == -1 || fcntl(sockGuard.get(), F_SETFL, flags | O_NONBLOCK) == -1) {
                return false;
            }
        #endif

        // Try to connect
        connect(sockGuard.get(), (struct sockaddr*)&addr, sizeof(addr));

        // Wait for the socket to be ready
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sockGuard.get(), &fdset);

        struct timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        int result = select(sockGuard.get() + 1, NULL, &fdset, NULL, &tv);

        if (result > 0) {
            // Connected, try to get a banner
            Utils::SafeBuffer buffer(DEFAULT_BUFFER_SIZE);

            // Some protocols require sending something first
            if (port == 80 || port == 8080) {
                // HTTP
                const char* httpRequest = "HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                send(sockGuard.get(), httpRequest, strlen(httpRequest), 0);
            } else if (port == 25 || port == 587) {
                // SMTP - Just wait for the banner
            } else if (port == 21) {
                // FTP - Just wait for the banner
            } else if (port == 22) {
                // SSH - Just wait for the banner
            }

            // Set back to blocking for receiving
            #ifdef _WIN32
                mode = 0;
                ioctlsocket(sockGuard.get(), FIONBIO, &mode);
            #else
                fcntl(sockGuard.get(), F_SETFL, flags);
            #endif

            // Receive data
            tv.tv_sec = DEFAULT_SSL_TIMEOUT_SEC; // Shorter timeout for banner grabbing
            tv.tv_usec = 0;
            setsockopt(sockGuard.get(), SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

            int bytesReceived = recv(sockGuard.get(), buffer.data(), buffer.size() - 1, 0);
            if (bytesReceived > 0) {
                banner = buffer.toPrintableString(bytesReceived);
            }

            return true;
        }

        return false;
    }

    // Improved UDP port scanning
    bool scanUdpPort(const std::string& ipAddress, int port, std::string& banner) {
        socket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            return false;
        }

        ResourceGuard::SocketGuard sockGuard(s);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr) != 1) {
            return false;
        }

        // For UDP, we need to send something to get a response
        std::vector<char> sendBuf(10, 0);
        if (port == 53) {
            // DNS query (simplified)
            sendBuf[0] = 0x12; sendBuf[1] = 0x34; // ID
            sendBuf[2] = 0x01; sendBuf[3] = 0x00; // Flags
            sendBuf[4] = 0x00; sendBuf[5] = 0x01; // Questions
            sendBuf[6] = 0x00; sendBuf[7] = 0x00; // Answers
            sendBuf[8] = 0x00; sendBuf[9] = 0x00; // Authority
        }

        sendto(sockGuard.get(), sendBuf.data(), sendBuf.size(), 0, (struct sockaddr*)&addr, sizeof(addr));

        // Try to receive a response
        Utils::SafeBuffer recvBuf(DEFAULT_BUFFER_SIZE);
        struct timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        setsockopt(sockGuard.get(), SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

        socklen_t addrLen = sizeof(addr);
        int bytesReceived = recvfrom(sockGuard.get(), recvBuf.data(), recvBuf.size() - 1, 0, 
                                     (struct sockaddr*)&addr, &addrLen);

        if (bytesReceived > 0) {
            // We got a response, the port is open
            banner = recvBuf.toPrintableString(bytesReceived);
            return true;
        }

        return false;
    }

    // Stub for QUIC protocol scanning
    bool scanQuicPort(const std::string& ipAddress, int port, std::string& banner) {
        // QUIC protocol implementation would use a library like msquic, lsquic, or neqo
        // This is a stub that would be replaced with actual implementation
        std::cerr << "Warning: QUIC protocol scanning not implemented" << std::endl;
        return false;
    }

    // Stub for MQTT protocol scanning
    bool scanMqttPort(const std::string& ipAddress, int port, std::string& banner) {
        // MQTT protocol implementation would use a library like Paho MQTT or Mosquitto
        // This is a stub that would be replaced with actual implementation
        std::cerr << "Warning: MQTT protocol scanning not implemented" << std::endl;
        return false;
    }

    // Stub for CoAP protocol scanning
    bool scanCoapPort(const std::string& ipAddress, int port, std::string& banner) {
        // CoAP protocol implementation would use a library like libcoap
        // This is a stub that would be replaced with actual implementation
        std::cerr << "Warning: CoAP protocol scanning not implemented" << std::endl;
        return false;
    }

    // Main port scanning function
    bool scanPort(const std::string& ipAddress, int port, Protocol protocol, std::string& banner) {
        try {
            switch (protocol) {
                case Protocol::TCP:
                    return scanTcpPort(ipAddress, port, banner);

                case Protocol::UDP:
                    return scanUdpPort(ipAddress, port, banner);

                case Protocol::QUIC:
                    return scanQuicPort(ipAddress, port, banner);

                case Protocol::MQTT:
                    return scanMqttPort(ipAddress, port, banner);

                case Protocol::COAP:
                    return scanCoapPort(ipAddress, port, banner);

                default:
                    return false;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error scanning port " << port << " with protocol " 
                      << Utils::protocolToString(protocol) << ": " << e.what() << std::endl;
            return false;
        }
    }

    // Improved DNS analysis
    std::map<std::string, std::string> analyzeDns(const std::string& hostname) {
        std::map<std::string, std::string> dnsInfo;

        try {
            // Simple DNS resolution
            struct addrinfo hints, *res;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            int result = getaddrinfo(hostname.c_str(), NULL, &hints, &res);
            if (result != 0) {
                dnsInfo["status"] = "failed";
                dnsInfo["error"] = gai_strerror(result);
                return dnsInfo;
            }

            struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
            dnsInfo["ip"] = ip;
            dnsInfo["status"] = "resolved";

            // For DNSSEC validation, you'd typically use a library like libunbound or call a DNS server
            // This is a placeholder for that functionality
            dnsInfo["dnssec_validation"] = "not validated";

            freeaddrinfo(res);
        } catch (const std::exception& e) {
            dnsInfo["status"] = "error";
            dnsInfo["error"] = e.what();
        }

        return dnsInfo;
    }

    // Improved SSL/TLS certificate analysis
    std::map<std::string, std::string> analyzeSSLCertificate(const std::string& ipAddress, int port) {
        std::map<std::string, std::string> sslInfo;

        try {
            ResourceGuard::SSL_CTX_ptr ctx(SSL_CTX_new(SSLv23_client_method()));
            if (!ctx) {
                throw ErrorHandling::SSLException(ErrorHandling::getOpenSSLErrorMsg());
            }

            ResourceGuard::SSL_ptr ssl(SSL_new(ctx.get()));
            if (!ssl) {
                throw ErrorHandling::SSLException(ErrorHandling::getOpenSSLErrorMsg());
            }

            socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                throw ErrorHandling::NetworkException(ErrorHandling::getSocketErrorMsg());
            }

            ResourceGuard::SocketGuard sockGuard(sock);

            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            if (inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr) != 1) {
                throw ErrorHandling::NetworkException("Invalid IP address");
            }

            // Set socket timeout
            struct timeval tv;
            tv.tv_sec = timeout / 1000;
            tv.tv_usec = (timeout % 1000) * 1000;
            setsockopt(sockGuard.get(), SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
            setsockopt(sockGuard.get(), SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

            if (connect(sockGuard.get(), (struct sockaddr*)&addr, sizeof(addr)) != 0) {
                throw ErrorHandling::NetworkException(ErrorHandling::getSocketErrorMsg());
            }

            SSL_set_fd(ssl.get(), sockGuard.get());

            if (SSL_connect(ssl.get()) != 1) {
                throw ErrorHandling::SSLException(ErrorHandling::getOpenSSLErrorMsg());
            }

            ResourceGuard::X509_ptr cert(SSL_get_peer_certificate(ssl.get()));
            if (!cert) {
                throw ErrorHandling::SSLException("No certificate presented by server");
            }

            // Extract certificate information
            Utils::SafeBuffer buffer(256);

            // Get subject
            X509_NAME* subject = X509_get_subject_name(cert.get());
            X509_NAME_oneline(subject, buffer.data(), buffer.size());
            sslInfo["subject"] = buffer.toString(strlen(buffer.data()));

            // Get issuer
            X509_NAME* issuer = X509_get_issuer_name(cert.get());
            X509_NAME_oneline(issuer, buffer.data(), buffer.size());
            sslInfo["issuer"] = buffer.toString(strlen(buffer.data()));

            // Get common name
            X509_NAME_get_text_by_NID(subject, NID_commonName, buffer.data(), buffer.size());
            sslInfo["common_name"] = buffer.toString(strlen(buffer.data()));

            // Get expiration date
            ASN1_TIME* notAfter = X509_get_notAfter(cert.get());
            sslInfo["expiration_date"] = Utils::ASN1_TIME_toString(notAfter);

            // Get SSL version
            sslInfo["version"] = SSL_get_version(ssl.get());

            // Get cipher
            sslInfo["cipher"] = SSL_get_cipher(ssl.get());

            // Graceful shutdown
            SSL_shutdown(ssl.get());

        } catch (const std::exception& e) {
            sslInfo["error"] = e.what();
        }

        return sslInfo;
    }

    // Improved OS fingerprinting
    std::string fingerprintOS(const std::string& ipAddress) {
        // This is a simplified OS fingerprinting function
        // A real implementation would use more sophisticated techniques
        try {
            // Try to connect to common ports and analyze responses
            std::string banner;
            if (scanPort(ipAddress, 22, Protocol::TCP, banner)) {
                if (banner.find("OpenSSH") != std::string::npos) {
                    if (banner.find("Ubuntu") != std::string::npos) {
                        return "Linux (Ubuntu)";
                    } else if (banner.find("Debian") != std::string::npos) {
                        return "Linux (Debian)";
                    } else if (banner.find("CentOS") != std::string::npos) {
                        return "Linux (CentOS)";
                    } else {
                        return "Linux";
                    }
                } else if (banner.find("Microsoft") != std::string::npos) {
                    return "Windows";
                }
            }

            if (scanPort(ipAddress, 80, Protocol::TCP, banner)) {
                if (banner.find("Server: Apache") != std::string::npos) {
                    return "Likely Linux";
                } else if (banner.find("Server: Microsoft-IIS") != std::string::npos) {
                    return "Windows";
                } else if (banner.find("Server: nginx") != std::string::npos) {
                    return "Likely Linux or BSD";
                }
            }

            // More advanced techniques like TCP/IP stack fingerprinting would be implemented here

        } catch (const std::exception& e) {
            std::cerr << "Error during OS fingerprinting: " << e.what() << std::endl;
        }

        return "Unknown";
    }

    // Improved host scanning
    void scanHost(const std::string& ipAddress) {
        HostScanResult result;
        result.ipAddress = ipAddress;

        try {
            // Try to resolve hostname
            auto hostname = Utils::resolveHostname(ipAddress);
            if (hostname) {
                result.hostname = *hostname;
            }

            // Check if host is up
            result.isUp = isHostUp(ipAddress, result.responseTime);

            if (result.isUp) {
                // Get geolocation and ISP info
                auto geoInfo = geoipService.lookup(ipAddress);
                result.location = geoInfo.first;
                result.isp = geoInfo.second;

                // Check for known threats
                result.threatInfo = threatIntelligence.lookup(ipAddress);

                // OS fingerprinting
                if (enableOsFingerprinting) {
                    result.osInfo = fingerprintOS(ipAddress);
                }

                // DNS analysis
                if (enableDnsAnalysis && !result.hostname.empty()) {
                    result.dnsInfo = analyzeDns(result.hostname);
                }

                // Port scanning
                for (int port : targetPorts) {
                    for (Protocol protocol : targetProtocols) {
                        std::string banner;
                        if (scanPort(ipAddress, port, protocol, banner)) {
                            result.openPorts.emplace_back(port, protocol);

                            if (!banner.empty()) {
                                result.bannerInfo[port] = banner;
                            }

                            // SSL/TLS analysis for HTTPS ports
                            if (enableSslAnalysis && (port == 443 || port == 8443) && protocol == Protocol::TCP) {
                                result.sslInfo[port] = analyzeSSLCertificate(ipAddress, port);
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error scanning host " << ipAddress << ": " << e.what() << std::endl;
        }

        // Add result to the global results vector
        {
            std::lock_guard<std::mutex> lock(resultsMutex);
            results.push_back(result);
        }
    }

    // Worker thread function
    void workerThread(const std::vector<std::string>& hosts) {
        for (const auto& host : hosts) {
            scanHost(host);
        }
    }

public:
    NetworkScanner() 
        : timeout(DEFAULT_TIMEOUT_MS), 
          numThreads(std::thread::hardware_concurrency() ? std::thread::hardware_concurrency() : 4), 
          enableDnsAnalysis(true), 
          enableOsFingerprinting(true), 
          enableSslAnalysis(true) {

        initializeNetworking();

        // Default to common ports
        targetPorts = {21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5900, 8080, 8443};

        // Default to TCP and UDP
        targetProtocols = {Protocol::TCP, Protocol::UDP};
    }

    ~NetworkScanner() {
        cleanupNetworking();
    }

    void addTarget(const std::string& target) {
        auto hosts = Utils::parseIPRange(target);
        targetHosts.insert(targetHosts.end(), hosts.begin(), hosts.end());
    }

    void addPort(int port) {
        if (port <= 0 || port > 65535) {
            throw ErrorHandling::ConfigException("Invalid port number: " + std::to_string(port));
        }
        targetPorts.push_back(port);
    }

    void addProtocol(Protocol protocol) {
        targetProtocols.push_back(protocol);
    }

    void setTimeout(int ms) {
        if (ms <= 0) {
            throw ErrorHandling::ConfigException("Timeout must be positive");
        }
        timeout = ms;
    }

    void setThreads(int threads) {
        if (threads <= 0) {
            throw ErrorHandling::ConfigException("Thread count must be positive");
        }
        numThreads = threads;
    }

    void setDnsAnalysis(bool enable) {
        enableDnsAnalysis = enable;
    }

    void setOsFingerprinting(bool enable) {
        enableOsFingerprinting = enable;
    }

    void setSslAnalysis(bool enable) {
        enableSslAnalysis = enable;
    }

    void clearTargets() {
        targetHosts.clear();
    }

    void clearPorts() {
        targetPorts.clear();
    }

    void clearProtocols() {
        targetProtocols.clear();
    }

    std::vector<HostScanResult> scan() {
        results.clear();

        if (targetHosts.empty()) {
            throw ErrorHandling::ConfigException("No targets specified. Use addTarget() to add targets.");
        }

        if (targetPorts.empty()) {
            throw ErrorHandling::ConfigException("No ports specified. Use addPort() to add ports.");
        }

        if (targetProtocols.empty()) {
            throw ErrorHandling::ConfigException("No protocols specified. Use addProtocol() to add protocols.");
        }

        // Divide hosts among threads
        std::vector<std::thread> threads;
        std::vector<std::vector<std::string>> hostChunks;

        size_t hostsPerThread = targetHosts.size() / numThreads;
        if (hostsPerThread == 0) hostsPerThread = 1;

        for (size_t i = 0; i < targetHosts.size(); i += hostsPerThread) {
            size_t end = std::min(i + hostsPerThread, targetHosts.size());
            std::vector<std::string> chunk(targetHosts.begin() + i, targetHosts.begin() + end);
            hostChunks.push_back(chunk);
        }

        // Launch threads
        for (const auto& chunk : hostChunks) {
            threads.push_back(std::thread(&NetworkScanner::workerThread, this, chunk));
        }

        // Wait for all threads to complete
        for (auto& t : threads) {
            t.join();
        }

        return results;
    }
};

// Command-line interface class with improved CLI library
class CommandLineInterface {
private:
    NetworkScanner scanner;
    OutputManager outputManager;
    ThreatIntelligence threatIntel;

public:
    int run(int argc, char* argv[]) {
        CLI::App app{"Network Scanner Tool v" + std::string(VERSION)};

        // Target options
        std::vector<std::string> targets;
        app.add_option("-t,--target", targets, "Add a target (IP, range, or CIDR)");

        // Port options
        std::vector<int> ports;
        app.add_option("-p,--port", ports, "Add a port to scan");

        // Protocol options
        std::vector<std::string> protocols;
        app.add_option("-P,--protocol", protocols, "Add a protocol (TCP, UDP, QUIC, MQTT, COAP)");

        // Timeout option
        int timeout = DEFAULT_TIMEOUT_MS;
        app.add_option("--timeout", timeout, "Set timeout in milliseconds");

        // Threads option
        int threads = 0; // 0 means use default
        app.add_option("--threads", threads, "Set number of threads");

        // Feature toggles
        bool dns_analysis = true;
        app.add_option("--dns", dns_analysis, "Enable or disable DNS analysis");

        bool os_fingerprinting = true;
        app.add_option("--os", os_fingerprinting, "Enable or disable OS fingerprinting");

        bool ssl_analysis = true;
        app.add_option("--ssl", ssl_analysis, "Enable or disable SSL/TLS analysis");

        // Output options
        std::string output_file;
        app.add_option("-o,--output", output_file, "Write output to file");

        std::string format_str = "text";
        app.add_option("-f,--format", format_str, "Output format (text, json, csv, xml)");

        // Update option
        bool update_threats = false;
        app.add_flag("--update-threats", update_threats, "Update threat intelligence database");

        // Parse options
        try {
            app.parse(argc, argv);

            // Check if we just need to update threats
            if (update_threats) {
                threatIntel.updateDatabase();
                return 0;
            }

            // Configure scanner
            for (const auto& target : targets) {
                scanner.addTarget(target);
            }

            for (int port : ports) {
                scanner.addPort(port);
            }

            for (const auto& proto_str : protocols) {
                scanner.addProtocol(Utils::stringToProtocol(proto_str));
            }

            if (timeout > 0) {
                scanner.setTimeout(timeout);
            }

            if (threads > 0) {
                scanner.setThreads(threads);
            }

            scanner.setDnsAnalysis(dns_analysis);
            scanner.setOsFingerprinting(os_fingerprinting);
            scanner.setSslAnalysis(ssl_analysis);

            // Configure output
            if (!output_file.empty()) {
                outputManager.setOutputFile(output_file);
            }

            if (format_str == "text") {
                outputManager.setFormat(OutputFormat::TEXT);
            } else if (format_str == "json") {
                outputManager.setFormat(OutputFormat::JSON);
            } else if (format_str == "csv") {
                outputManager.setFormat(OutputFormat::CSV);
            } else if (format_str == "xml") {
                outputManager.setFormat(OutputFormat::XML);
            } else {
                throw ErrorHandling::ConfigException("Unknown output format: " + format_str);
            }

            // Perform the scan
            std::cout << "Starting network scan..." << std::endl;
            auto results = scanner.scan();
            std::cout << "Scan complete. Found " << results.size() << " hosts." << std::endl;

            // Output results
            outputManager.output(results);

        } catch (const CLI::ParseError& e) {
            return app.exit(e);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }

        return 0;
    }
};

// Main function
int main(int argc, char* argv[]) {
    try {
        CommandLineInterface cli;
        return cli.run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}// Advanced Network Scanner Tool - Paste full source code here
