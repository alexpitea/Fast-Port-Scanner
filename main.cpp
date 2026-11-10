// Fast Port Scanner - multithreaded TCP connect scanner for Windows (Winsock).
//
//   scanner <host> <first-port> <last-port> [--threads N] [--timeout MS]
//   scanner                      (asks for the values interactively)
//
// Only scan hosts you own or are allowed to test.

#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")  // with g++ link with -lws2_32 instead
#endif

namespace {

struct Options {
    std::string host;
    int firstPort = 1;
    int lastPort = 1024;
    int threads = 100;
    int timeoutMs = 500;
};

enum class PortState { Open, Refused, NoAnswer };

struct Totals {
    std::atomic<int> nextPort{0};
    std::atomic<int> refused{0};
    std::atomic<int> noAnswer{0};
    std::mutex lock;             // protects `open` and the console
    std::vector<int> open;
};

const char* serviceName(int port) {
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 135: return "msrpc";
        case 139: return "netbios-ssn";
        case 143: return "imap";
        case 443: return "https";
        case 445: return "microsoft-ds";
        case 465: return "smtps";
        case 587: return "submission";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "mssql";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 5900: return "vnc";
        case 8080: return "http-alt";
        case 8443: return "https-alt";
        default: return "";
    }
}

// One connection attempt with a time limit. The socket is non-blocking, so
// connect() returns at once and select() waits for the result: writable means
// the handshake finished, an error means the port refused, nothing within the
// time limit means a firewall dropped the packets (or the host is down).
PortState probe(const sockaddr_in& target, int port, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return PortState::NoAnswer;

    u_long nonBlocking = 1;
    ioctlsocket(s, FIONBIO, &nonBlocking);

    sockaddr_in address = target;
    address.sin_port = htons((u_short)port);

    PortState state = PortState::NoAnswer;
    int rc = connect(s, (const sockaddr*)&address, sizeof(address));
    if (rc == 0) {
        state = PortState::Open;
    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set writable, failed;
        FD_ZERO(&writable);
        FD_ZERO(&failed);
        FD_SET(s, &writable);
        FD_SET(s, &failed);

        timeval limit;
        limit.tv_sec = timeoutMs / 1000;
        limit.tv_usec = (timeoutMs % 1000) * 1000;

        if (select(0, nullptr, &writable, &failed, &limit) > 0) {
            if (FD_ISSET(s, &writable)) state = PortState::Open;
            else if (FD_ISSET(s, &failed)) state = PortState::Refused;
        }
    } else {
        state = PortState::Refused;
    }

    closesocket(s);
    return state;
}

// Every thread takes the next unscanned port from a shared counter, so the
// work stays balanced even when some ports answer slowly.
void worker(const sockaddr_in& target, const Options& options, Totals& totals) {
    for (;;) {
        int port = totals.nextPort.fetch_add(1);
        if (port > options.lastPort) return;

        switch (probe(target, port, options.timeoutMs)) {
            case PortState::Open: {
                std::lock_guard<std::mutex> guard(totals.lock);
                totals.open.push_back(port);
                std::cout << "[+] Port " << port << " is OPEN" << std::endl;
                break;
            }
            case PortState::Refused:
                totals.refused++;
                break;
            case PortState::NoAnswer:
                totals.noAnswer++;
                break;
        }
    }
}

bool parseNumber(const std::string& text, int minimum, int maximum, int& value) {
    if (text.empty() || text.size() > 6) return false;
    int number = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        number = number * 10 + (c - '0');
    }
    if (number < minimum || number > maximum) return false;
    value = number;
    return true;
}

void printUsage() {
    std::cout << "Usage: scanner <host> <first-port> <last-port> [--threads N] [--timeout MS]\n"
                 "  host       IPv4 address or name (for example 127.0.0.1)\n"
                 "  --threads  parallel connections, 1-1000 (default 100)\n"
                 "  --timeout  wait per port in milliseconds, 50-10000 (default 500)\n"
                 "Run without arguments to be asked for the values.\n";
}

bool readOptions(int argc, char** argv, Options& options) {
    if (argc == 1) {
        std::string first, last;
        std::cout << "--- FAST PORT SCANNER ---\nTarget host: ";
        std::cin >> options.host;
        std::cout << "First port: ";
        std::cin >> first;
        std::cout << "Last port: ";
        std::cin >> last;
        return parseNumber(first, 1, 65535, options.firstPort) && parseNumber(last, 1, 65535, options.lastPort);
    }

    if (argc < 4) return false;
    options.host = argv[1];
    if (!parseNumber(argv[2], 1, 65535, options.firstPort)) return false;
    if (!parseNumber(argv[3], 1, 65535, options.lastPort)) return false;

    for (int i = 4; i < argc; i++) {
        std::string name = argv[i];
        if (i + 1 >= argc) return false;
        std::string value = argv[++i];
        if (name == "--threads") {
            if (!parseNumber(value, 1, 1000, options.threads)) return false;
        } else if (name == "--timeout") {
            if (!parseNumber(value, 50, 10000, options.timeoutMs)) return false;
        } else {
            return false;
        }
    }
    return true;
}

bool resolve(const std::string& host, sockaddr_in& address) {
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* found = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &found) != 0 || found == nullptr) return false;
    address = *(const sockaddr_in*)found->ai_addr;
    freeaddrinfo(found);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!readOptions(argc, argv, options) || options.firstPort > options.lastPort) {
        printUsage();
        return 2;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cout << "Winsock init failed.\n";
        return 1;
    }

    sockaddr_in target = {};
    if (!resolve(options.host, target)) {
        std::cout << "Cannot resolve host: " << options.host << "\n";
        WSACleanup();
        return 1;
    }

    char ip[INET_ADDRSTRLEN] = "";
    inet_ntop(AF_INET, &target.sin_addr, ip, sizeof(ip));

    const int portCount = options.lastPort - options.firstPort + 1;
    const int threadCount = std::min(options.threads, portCount);

    std::cout << "Scanning " << options.host << " (" << ip << "), ports " << options.firstPort << "-"
              << options.lastPort << ", " << threadCount << " threads, " << options.timeoutMs
              << " ms timeout\n";

    Totals totals;
    totals.nextPort = options.firstPort;

    const auto started = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    threads.reserve(threadCount);
    for (int i = 0; i < threadCount; i++) threads.emplace_back(worker, std::cref(target), std::cref(options), std::ref(totals));
    for (std::thread& t : threads) t.join();

    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    WSACleanup();

    std::sort(totals.open.begin(), totals.open.end());

    std::cout << "\nOpen ports:";
    if (totals.open.empty()) std::cout << " none";
    std::cout << "\n";
    for (int port : totals.open) {
        const char* service = serviceName(port);
        std::cout << "  " << port << "/tcp";
        if (*service) std::cout << "  " << service;
        std::cout << "\n";
    }

    std::cout << "\nScanned " << portCount << " ports in " << std::fixed << std::setprecision(2) << seconds
              << " s: " << totals.open.size() << " open, "
              << totals.refused << " refused, " << totals.noAnswer << " no answer within " << options.timeoutMs
              << " ms\n";
    return 0;
}
