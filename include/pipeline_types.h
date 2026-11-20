#ifndef PIPELINE_TYPES_H
#define PIPELINE_TYPES_H

#include "packet_parser.h"
#include "pcap_reader.h"
#include "types.h"

#include <cstdint>

namespace DPI {

struct PacketJob {
    uint64_t packet_index = 0;
    PacketAnalyzer::RawPacket raw;
    PacketAnalyzer::ParsedPacket parsed;
    FiveTuple flow_key; // Always canonical: both directions share one worker.
};

struct PacketResult {
    uint64_t packet_index = 0;
    bool forward = false;
    PacketAnalyzer::RawPacket raw; // Used only when forward == true.
};

} // namespace DPI

#endif // PIPELINE_TYPES_H
