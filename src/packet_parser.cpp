#include "packet_parser.h"

#include <algorithm>
#include <cstring>

namespace PacketAnalyzer {

uint16_t PacketParser::read16(const uint8_t* data) const {
    return (static_cast<uint16_t>(data[0]) << 8) |
           static_cast<uint16_t>(data[1]);
}

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parsed = ParsedPacket{};

    const uint8_t* data = raw.data.data();
    const size_t length = raw.data.size();

    // Ethernet II header: destination MAC (6), source MAC (6), EtherType (2).
    if (length < 14) return false;

    std::memcpy(parsed.dst_mac, data, 6);
    std::memcpy(parsed.src_mac, data + 6, 6);
    parsed.ether_type = read16(data + 12);

    size_t offset = 14;

    // Support up to four stacked 802.1Q / 802.1ad VLAN tags.
    unsigned vlan_count = 0;
    while (parsed.ether_type == 0x8100 || parsed.ether_type == 0x88A8) {
        if (++vlan_count > 4 || offset > length || length - offset < 4) {
            return false;
        }
        parsed.ether_type = read16(data + offset + 2);
        offset += 4;
    }

    parsed.ip_offset = offset;

    size_t ip_end = 0;
    size_t transport = 0;
    uint8_t next_header = 0;

    // ---------------- IPv4 ----------------
    if (parsed.ether_type == 0x0800) {
        if (offset > length || length - offset < 20) return false;

        const uint8_t version = data[offset] >> 4;
        const uint8_t ihl = static_cast<uint8_t>((data[offset] & 0x0F) * 4);
        if (version != 4 || ihl < 20 || ihl > 60) return false;
        if (length - offset < ihl) return false;

        const uint16_t total_length = read16(data + offset + 2);
        if (total_length < ihl || total_length > length - offset) return false;

        // This first version deliberately declines fragmented IPv4 datagrams.
        const uint16_t fragment_field = read16(data + offset + 6);
        const bool more_fragments = (fragment_field & 0x2000) != 0;
        const uint16_t fragment_offset = fragment_field & 0x1FFF;
        if (more_fragments || fragment_offset != 0) return false;

        parsed.src_ip.version = 4;
        parsed.dst_ip.version = 4;
        std::copy(data + offset + 12, data + offset + 16,
                  parsed.src_ip.bytes.begin());
        std::copy(data + offset + 16, data + offset + 20,
                  parsed.dst_ip.bytes.begin());

        parsed.ttl = data[offset + 8];
        next_header = data[offset + 9];
        parsed.is_ipv4 = true;

        transport = offset + ihl;
        ip_end = offset + total_length;
    }
    // ---------------- IPv6 ----------------
    else if (parsed.ether_type == 0x86DD) {
        // Fixed IPv6 header is 40 bytes.
        if (offset > length || length - offset < 40) return false;

        const uint8_t version = data[offset] >> 4;
        if (version != 6) return false;

        const uint16_t payload_length = read16(data + offset + 4);
        // Payload length zero can indicate a jumbogram; not implemented here.
        if (payload_length == 0) return false;
        if (payload_length > length - offset - 40) return false;

        parsed.src_ip.version = 6;
        parsed.dst_ip.version = 6;
        std::copy(data + offset + 8, data + offset + 24,
                  parsed.src_ip.bytes.begin());
        std::copy(data + offset + 24, data + offset + 40,
                  parsed.dst_ip.bytes.begin());

        next_header = data[offset + 6];
        parsed.ttl = data[offset + 7]; // Hop Limit
        parsed.is_ipv6 = true;

        transport = offset + 40;
        ip_end = transport + payload_length;

        // Walk common IPv6 extension headers to find TCP or UDP.
        // Fragmented packets are rejected for now, except atomic fragments.
        unsigned extension_count = 0;
        while (true) {
            if (++extension_count > 16) return false;

            if (next_header == 0 ||   // Hop-by-Hop Options
                next_header == 43 ||  // Routing
                next_header == 60) {  // Destination Options
                if (transport > ip_end || ip_end - transport < 2) return false;

                const uint8_t following_header = data[transport];
                const size_t ext_length =
                    (static_cast<size_t>(data[transport + 1]) + 1) * 8;

                if (ext_length > ip_end - transport) return false;
                next_header = following_header;
                transport += ext_length;
                continue;
            }

            if (next_header == 44) { // Fragment header
                if (transport > ip_end || ip_end - transport < 8) return false;

                const uint8_t following_header = data[transport];
                const uint16_t fragment_field = read16(data + transport + 2);
                const uint16_t fragment_offset = fragment_field & 0xFFF8;
                const bool more_fragments = (fragment_field & 0x0001) != 0;

                if (fragment_offset != 0 || more_fragments) {
                    return false; // Reassembly is a later milestone.
                }

                next_header = following_header;
                transport += 8;
                continue;
            }

            if (next_header == 51) { // Authentication Header (AH)
                if (transport > ip_end || ip_end - transport < 2) return false;

                const uint8_t following_header = data[transport];
                const size_t ext_length =
                    (static_cast<size_t>(data[transport + 1]) + 2) * 4;

                if (ext_length > ip_end - transport) return false;
                next_header = following_header;
                transport += ext_length;
                continue;
            }

            // ESP (50), No Next Header (59), and unknown extension types
            // are not decoded by this parser yet.
            break;
        }
    }
    else {
        return false; // Not IPv4 or IPv6.
    }

    parsed.protocol = next_header;
    parsed.transport_offset = transport;

    // ---------------- TCP ----------------
    if (next_header == 6) {
        if (transport > ip_end || ip_end - transport < 20) return false;

        parsed.src_port = read16(data + transport);
        parsed.dst_port = read16(data + transport + 2);

        const uint8_t tcp_header_length =
            static_cast<uint8_t>((data[transport + 12] >> 4) * 4);

        if (tcp_header_length < 20 ||
            tcp_header_length > ip_end - transport) {
            return false;
        }

        parsed.tcp_flags = data[transport + 13];
        parsed.is_tcp = true;
        parsed.payload_offset = transport + tcp_header_length;
        parsed.payload_length = ip_end - parsed.payload_offset;
    }
    // ---------------- UDP ----------------
    else if (next_header == 17) {
        if (transport > ip_end || ip_end - transport < 8) return false;

        parsed.src_port = read16(data + transport);
        parsed.dst_port = read16(data + transport + 2);

        const uint16_t udp_length = read16(data + transport + 4);
        if (udp_length < 8 || udp_length > ip_end - transport) return false;

        parsed.is_udp = true;
        parsed.payload_offset = transport + 8;
        parsed.payload_length = udp_length - 8;
    }
    else {
        return false; // This version inspects TCP and UDP only.
    }

    parsed.is_valid = true;
    return true;
}

} // namespace PacketAnalyzer
