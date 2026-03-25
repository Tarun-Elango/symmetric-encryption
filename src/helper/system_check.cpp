#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#include <sodium.h>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <net/if.h>
#endif

void clear_screen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

bool startup_checks() {
    bool ok = true;
    bool memlock_info_available = false;

    std::cout << "[startup] Running secure memory checks...\n";

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    struct rlimit rl{};

    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
        memlock_info_available = true;
        constexpr rlim_t EXPECTED_LOCK_BYTES = 512UL * 1024;

        std::cout << "[startup] RLIMIT_MEMLOCK: cur="
                  << (rl.rlim_cur == RLIM_INFINITY ? "inf" : std::to_string((unsigned long long)rl.rlim_cur))
                  << ", max="
                  << (rl.rlim_max == RLIM_INFINITY ? "inf" : std::to_string((unsigned long long)rl.rlim_max))
                  << "\n";

        if (rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < EXPECTED_LOCK_BYTES) {
            ok = false;
            std::cerr
                << "[warning] Low RLIMIT_MEMLOCK (" << rl.rlim_cur << " bytes).\n"
                << "          Sensitive memory may not be locked (may swap to disk).\n"
                << "          Suggested: ulimit -l unlimited\n";
        } else {
            std::cout << "[startup] RLIMIT_MEMLOCK looks sufficient (>= 512KB)\n";
        }
    } else {
        ok = false;
        std::cerr << "[warning] Failed to read RLIMIT_MEMLOCK\n";
    }
#endif

    // --- Probe sodium_malloc / mlock behavior ---
    std::cout << "[startup] Probing sodium_malloc / mlock...\n";

    void* probe = sodium_malloc(4096);
    if (probe) {
        std::cout << "[startup] Allocated secure memory (4KB)\n";

        if (sodium_mlock(probe, 4096) != 0) {
            ok = false;
            std::cerr
                << "[warning] Unable to confirm memory locking (mlock probe failed).\n"
                << "          Memory may not be locked.\n"
                << "          Check RLIMIT_MEMLOCK or privileges.\n";

#if defined(__APPLE__)
            std::cerr
                << "          Note: macOS restricts mlock for non-root processes.\n";
#endif
        } else {
            std::cout << "[startup] mlock probe succeeded (memory lock likely working)\n";
            sodium_munlock(probe, 4096); // zero + unlock
        }

        sodium_free(probe);
    } else {
        ok = false;
        std::cerr
            << "[warning] sodium_malloc() failed — cannot verify secure memory.\n";
    }

#if defined(__linux__)
    // --- Detect swap usage (advanced) ---
    std::cout << "[startup] Checking for swap...\n";

    std::ifstream swaps("/proc/swaps");
    if (swaps) {
        std::string line;
        int count = 0;

        while (std::getline(swaps, line)) {
            count++;
        }

        if (count > 1) { // first line is header
            ok = false;
            std::cerr
                << "[warning] Swap is ENABLED on this system.\n"
                << "          Sensitive data could be written to disk.\n"
                << "          Consider disabling swap for higher security.\n";
        } else {
            std::cout << "[startup] No active swap detected\n";
        }
    } else {
        std::cerr << "[warning] Could not read /proc/swaps\n";
    }
#endif

    // --- Final result ---
    if (ok) {
        std::cout
            << "[startup] ✓ All secure memory checks passed"
            << " | libsodium=" << sodium_version_string()
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
            << " | RLIMIT_MEMLOCK("
            << (memlock_info_available
                    ? "cur=" + (rl.rlim_cur == RLIM_INFINITY
                                     ? std::string("inf")
                                     : std::to_string((unsigned long long)rl.rlim_cur)) +
                          ", max=" +
                          (rl.rlim_max == RLIM_INFINITY
                               ? std::string("inf")
                               : std::to_string((unsigned long long)rl.rlim_max))
                    : std::string("unavailable"))
            << ")"
#endif
            << " | mlock_probe=ok\n";
    } else {
        std::cerr << "[startup] ⚠ Some security checks failed (see warnings above)\n";
    }

    return ok;
}

void print_system_warnings() {
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)

    std::cout << "[startup] Checking network interfaces...\n";

    struct ifaddrs* ifaddr = nullptr;

    if (getifaddrs(&ifaddr) == 0) {
        bool found_external = false;

        for (auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;

            // Skip interfaces that are down
            if (!(ifa->ifa_flags & IFF_UP)) continue;
            if (!(ifa->ifa_flags & IFF_RUNNING)) continue;

            int family = ifa->ifa_addr->sa_family;

            char host[NI_MAXHOST];

            if (family == AF_INET || family == AF_INET6) {
                void* addr_ptr = nullptr;

                if (family == AF_INET) {
                    addr_ptr = &reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr;
                } else {
                    addr_ptr = &reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr)->sin6_addr;
                }

                if (inet_ntop(family, addr_ptr, host, sizeof(host))) {

                    std::string ip = host;

                    // Skip loopback
                    if (ip == "127.0.0.1" || ip == "::1") continue;

                    // Skip link-local (optional but useful)
                    if (ip.rfind("169.254.", 0) == 0) continue;
                    if (ip.rfind("fe80:", 0) == 0) continue;

                    if (family == AF_INET && !(ifa->ifa_flags & IFF_BROADCAST)) continue;

                    found_external = true;

                    std::cout
                        << "[warning] Active network interface: "
                        << ifa->ifa_name << " (" << ip << ")\n";
                }
            }
        }

        if (!found_external) {
            std::cout << "[startup] No active external network interfaces detected\n";
        } else {
            std::cerr
                << "[warning] System appears to be connected to a network.\n"
                << "          For high-security use, consider running offline.\n";
        }

        freeifaddrs(ifaddr);
    } else {
        std::cerr << "[warning] getifaddrs() failed — cannot inspect network interfaces\n";
    }

    // --- Root check ---
    std::cout << "[startup] Checking privileges...\n";

    if (geteuid() != 0) {
        std::cerr
            << "[warning] Not running as root.\n"
            << "          mlock() may be limited by RLIMIT_MEMLOCK.\n"
            << "          Running as root may increase limits (not guaranteed).\n";
    } else {
        std::cout << "[startup] Running as root (higher chance of successful mlock)\n";
    }

#endif
}