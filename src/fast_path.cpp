#include "fast_path.h"

#include "app_classifier.h"
#include "sni_extractor.h"

#include <utility>

namespace DPI {

FastPathWorker::FastPathWorker(
    std::size_t worker_id,
    std::size_t queue_capacity,
    const RuleManager& rules,
    ThreadSafeQueue<PacketResult>& output_queue,
    PipelineStats& stats)
    : worker_id_(worker_id),
      rules_(rules),
      output_queue_(output_queue),
      stats_(stats),
      input_queue_(queue_capacity) {}

void FastPathWorker::start() {
    thread_ = std::thread(&FastPathWorker::run, this);
}

bool FastPathWorker::enqueue(PacketJob job) {
    return input_queue_.push(std::move(job));
}

void FastPathWorker::closeInput() {
    input_queue_.close();
}

void FastPathWorker::join() {
    if (thread_.joinable()) {
        thread_.join();
    }
}

uint64_t FastPathWorker::processed() const {
    return processed_.load();
}

std::size_t FastPathWorker::flowCount() const {
    // Called after join(), once this worker no longer mutates the tracker.
    return tracker_.size();
}

std::size_t FastPathWorker::id() const {
    return worker_id_;
}

void FastPathWorker::run() {
    PacketJob job;
    while (input_queue_.pop(job)) {
        process(std::move(job));
        processed_.fetch_add(1);
    }
}

void FastPathWorker::process(PacketJob job) {
    PacketResult result{};
    result.packet_index = job.packet_index;

    // flow_key was canonicalized by the reader thread. Every packet in
    // either direction of this connection is routed to this same worker.
    Flow& flow = tracker_.getflow(job.flow_key);
    flow.packet_count++;
    flow.byte_count += job.raw.data.size();

    if (flow.action == FlowAction::BLOCKED) {
        stats_.dropped_packets.fetch_add(1);
        result.forward = false;
        if (!output_queue_.push(std::move(result))) {
            stats_.queue_errors.fetch_add(1);
        }
        return;
    }

    const auto& parsed = job.parsed;
    std::optional<std::string> hostname;

    if (parsed.is_tcp && parsed.payload_length > 0 &&
        parsed.payload_offset <= job.raw.data.size() &&
        parsed.payload_length <= job.raw.data.size() - parsed.payload_offset) {

        const uint8_t* payload =
            job.raw.data.data() + parsed.payload_offset;

        hostname = SNIExtractor::extractTLS(
            payload, parsed.payload_length);

        if (!hostname) {
            hostname = SNIExtractor::extractHTTP(
                payload, parsed.payload_length);
        }
    }

    if (hostname) {
        flow.hostname = *hostname;
        const bool is_https =
            parsed.src_port == 443 || parsed.dst_port == 443;
        flow.app = AppClassifier::classify(flow.hostname, is_https);
    } else if (flow.app == AppType::UNKNOWN) {
        if (parsed.is_udp &&
            (parsed.src_port == 53 || parsed.dst_port == 53)) {
            flow.app = AppType::DNS;
        } else if (parsed.is_tcp &&
                   (parsed.src_port == 443 || parsed.dst_port == 443)) {
            flow.app = AppType::HTTPS;
        } else if (parsed.is_tcp &&
                   (parsed.src_port == 80 || parsed.dst_port == 80)) {
            flow.app = AppType::HTTP;
        }
    }

    if (rules_.shouldBlock(parsed.src_ip, flow.app, flow.hostname)) {
        flow.action = FlowAction::BLOCKED;
        stats_.dropped_packets.fetch_add(1);
        result.forward = false;
    } else {
        result.forward = true;
        result.raw = std::move(job.raw);
    }

    if (!output_queue_.push(std::move(result))) {
        stats_.queue_errors.fetch_add(1);
    }
}

} // namespace DPI
