#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "pcap_reader.h"
#include "types.h"

#include <cstddef>
#include <cstdint>

namespace PacketAnalyzer {

struct ParsedPacket {
    uint8_t src_mac[6]{};
    uint8_t dst_mac[6]{};

    DPI::IPAddress src_ip;
    DPI::IPAddress dst_ip;

    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t ether_type = 0;

    uint8_t protocol = 0;
    uint8_t ttl = 0; // IPv4 TTL or IPv6 Hop Limit
    uint8_t tcp_flags = 0;

    size_t ip_offset = 0;
    size_t transport_offset = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;

    bool is_ipv4 = false;
    bool is_ipv6 = false;
    bool is_tcp = false;
    bool is_udp = false;
    bool is_valid = false;
};

class PacketParser {
public:
    bool parse(const RawPacket& raw, ParsedPacket& parsed);

private:
    uint16_t read16(const uint8_t* data) const;
};

} // namespace PacketAnalyzer

#endif // PACKET_PARSER_H
