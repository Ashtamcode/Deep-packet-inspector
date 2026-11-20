#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include "app_classifier.h"
#include "types.h"

#include <cstdint>
#include <string>
#include <unordered_set>

namespace DPI {

class RuleManager {
private:
    // The existing --block-ip option currently accepts IPv4 addresses.
    std::unordered_set<uint32_t> blocked_ipv4;
    std::unordered_set<AppType> blocked_apps;
    std::unordered_set<std::string> blocked_domains;

public:
    void blockIP(uint32_t ip);
    void blockApp(AppType app);
    void blockDomain(const std::string& domain);

    bool shouldBlock(
        const IPAddress& source_ip,
        AppType app,
        const std::string& hostname
    ) const;
};

} // namespace DPI

#endif // RULE_MANAGER_H
