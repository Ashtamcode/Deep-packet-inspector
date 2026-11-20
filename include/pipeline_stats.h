#ifndef PIPELINE_STATS_H
#define PIPELINE_STATS_H

#include <atomic>
#include <cstdint>

namespace DPI {

struct PipelineStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> parsed_packets{0};
    std::atomic<uint64_t> passthrough_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> written_packets{0};
    std::atomic<uint64_t> write_errors{0};
    std::atomic<uint64_t> queue_errors{0};
};

} // namespace DPI

#endif // PIPELINE_STATS_H
