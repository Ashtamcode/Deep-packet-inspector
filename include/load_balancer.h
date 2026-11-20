#ifndef LOAD_BALANCER_H
#define LOAD_BALANCER_H

#include "fast_path.h"
#include "pipeline_types.h"
#include "pipeline_stats.h"
#include "thread_safe_queue.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>

namespace DPI {

class LoadBalancer {
public:
    LoadBalancer(
        std::size_t lb_id,
        std::size_t queue_capacity,
        const std::vector<FastPathWorker*>& workers,
        PipelineStats& stats);

    LoadBalancer(const LoadBalancer&) = delete;
    LoadBalancer& operator=(const LoadBalancer&) = delete;

    void start();
    bool enqueue(PacketJob job);
    void closeInput();
    void join();

    uint64_t dispatched() const;
    std::size_t id() const;
    const std::vector<uint64_t>& workerDistribution() const;

private:
    void run();

    const std::size_t lb_id_;
    std::vector<FastPathWorker*> workers_;
    ThreadSafeQueue<PacketJob> input_queue_;
    PipelineStats& stats_;
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    std::vector<uint64_t> worker_distribution_;
};

} // namespace DPI

#endif // LOAD_BALANCER_H
