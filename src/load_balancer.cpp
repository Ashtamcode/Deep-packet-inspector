#include "load_balancer.h"

#include <utility>

namespace DPI {

LoadBalancer::LoadBalancer(
    std::size_t lb_id,
    std::size_t queue_capacity,
    const std::vector<FastPathWorker*>& workers,
    PipelineStats& stats)
    : lb_id_(lb_id),
      workers_(workers),
      input_queue_(queue_capacity),
      stats_(stats),
      worker_distribution_(workers.size(), 0) {}

void LoadBalancer::start() {
    thread_ = std::thread(&LoadBalancer::run, this);
}

bool LoadBalancer::enqueue(PacketJob job) {
    return input_queue_.push(std::move(job));
}

void LoadBalancer::closeInput() {
    input_queue_.close();
}

void LoadBalancer::join() {
    if (thread_.joinable()) {
        thread_.join();
    }
}

uint64_t LoadBalancer::dispatched() const {
    return dispatched_.load();
}

std::size_t LoadBalancer::id() const {
    return lb_id_;
}

const std::vector<uint64_t>& LoadBalancer::workerDistribution() const {
    // Read only after join(), once this thread has stopped updating it.
    return worker_distribution_;
}

void LoadBalancer::run() {
    PacketJob job;
    while (input_queue_.pop(job)) {
        // This load balancer serves only its own FP group. Every packet for
        // this canonical flow was already routed to this LB by the reader.
        const std::size_t worker_index =
            FiveTupleHash{}(job.flow_key) % workers_.size();

        if (workers_[worker_index]->enqueue(std::move(job))) {
            ++worker_distribution_[worker_index];
            dispatched_.fetch_add(1);
        } else {
            stats_.queue_errors.fetch_add(1);
        }
    }
}

} // namespace DPI
