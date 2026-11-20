#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "connection_tracker.h"
#include "pipeline_stats.h"
#include "pipeline_types.h"
#include "rule_manager.h"
#include "thread_safe_queue.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>

namespace DPI {

class FastPathWorker {
public:
    FastPathWorker(
        std::size_t worker_id,
        std::size_t queue_capacity,
        const RuleManager& rules,
        ThreadSafeQueue<PacketResult>& output_queue,
        PipelineStats& stats);

    FastPathWorker(const FastPathWorker&) = delete;
    FastPathWorker& operator=(const FastPathWorker&) = delete;

    void start();
    bool enqueue(PacketJob job);
    void closeInput();
    void join();

    uint64_t processed() const;
    std::size_t flowCount() const;
    std::size_t id() const;

private:
    void run();
    void process(PacketJob job);

    const std::size_t worker_id_;
    const RuleManager& rules_;
    ThreadSafeQueue<PacketResult>& output_queue_;
    PipelineStats& stats_;
    ThreadSafeQueue<PacketJob> input_queue_;
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};
    ConnectionTracker tracker_;
};

} // namespace DPI

#endif // FAST_PATH_H
