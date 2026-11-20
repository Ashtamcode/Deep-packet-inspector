#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace DPI {

// An IP address that can represent either IPv4 or IPv6.
// IPv4 uses bytes[0..3]; bytes[4..15] remain zero.
struct IPAddress {
    uint8_t version = 0; // 4 or 6
    std::array<uint8_t, 16> bytes{};

    bool operator==(const IPAddress& other) const {
        return version == other.version && bytes == other.bytes;
    }

    bool operator!=(const IPAddress& other) const {
        return !(*this == other);
    }
};

struct IPAddressHash {
    size_t operator()(const IPAddress& ip) const {
        size_t h = std::hash<uint8_t>{}(ip.version);
        for (uint8_t byte : ip.bytes) {
            h ^= std::hash<uint8_t>{}(byte) + 0x9e3779b9 +
                 (h << 6) + (h >> 2);
        }
        return h;
    }
};

// Five values uniquely identify a directional network flow.
struct FiveTuple {
    IPAddress src_ip;
    IPAddress dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0; // TCP=6, UDP=17

    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }

    FiveTuple reverse() const {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }

    FiveTuple canonical() const {
        // Compare address family, then address bytes, then ports.
        if (src_ip.version < dst_ip.version) return *this;
        if (src_ip.version > dst_ip.version) return reverse();

        if (src_ip.bytes < dst_ip.bytes) return *this;
        if (dst_ip.bytes < src_ip.bytes) return reverse();

        return (src_port <= dst_port) ? *this : reverse();
    }
};

struct FiveTupleHash {
    size_t operator()(const FiveTuple& tuple) const {
        size_t h = 0;
        auto combine = [&h](size_t value) {
            h ^= value + 0x9e3779b9 + (h << 6) + (h >> 2);
        };

        combine(IPAddressHash{}(tuple.src_ip));
        combine(IPAddressHash{}(tuple.dst_ip));
        combine(std::hash<uint16_t>{}(tuple.src_port));
        combine(std::hash<uint16_t>{}(tuple.dst_port));
        combine(std::hash<uint8_t>{}(tuple.protocol));
        return h;
    }
};

} // namespace DPI

#endif // DPI_TYPES_H
