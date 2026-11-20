#include "rule_manager.h"

#include <algorithm>
#include <cctype>

namespace DPI {

namespace {
std::string normalizeDomain(std::string domain) {
    std::transform(domain.begin(), domain.end(), domain.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // A trailing DNS root dot is optional in textual hostnames.
    if (!domain.empty() && domain.back() == '.') {
        domain.pop_back();
    }
    return domain;
}

bool domainMatches(const std::string& hostname, const std::string& rule) {
    if (hostname == rule) return true;

    if (hostname.size() <= rule.size()) return false;

    const size_t suffix_start = hostname.size() - rule.size();
    return hostname.compare(suffix_start, rule.size(), rule) == 0 &&
           hostname[suffix_start - 1] == '.';
}
} // namespace

void RuleManager::blockIP(uint32_t ip) {
    blocked_ipv4.insert(ip);
}

void RuleManager::blockApp(AppType app) {
    blocked_apps.insert(app);
}

void RuleManager::blockDomain(const std::string& domain) {
    const std::string normalized = normalizeDomain(domain);
    if (!normalized.empty()) {
        blocked_domains.insert(normalized);
    }
}

bool RuleManager::shouldBlock(
    const IPAddress& source_ip,
    AppType app,
    const std::string& hostname
) const {
    if (source_ip.version == 4) {
        const uint32_t ipv4 =
            (static_cast<uint32_t>(source_ip.bytes[0]) << 24) |
            (static_cast<uint32_t>(source_ip.bytes[1]) << 16) |
            (static_cast<uint32_t>(source_ip.bytes[2]) << 8) |
             static_cast<uint32_t>(source_ip.bytes[3]);

        if (blocked_ipv4.count(ipv4)) return true;
    }

    if (blocked_apps.count(app)) return true;

    const std::string normalized_host = normalizeDomain(hostname);
    for (const std::string& rule : blocked_domains) {
        if (domainMatches(normalized_host, rule)) return true;
    }

    return false;
}

} // namespace DPI
