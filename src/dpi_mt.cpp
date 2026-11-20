#include "fast_path.h"
#include "load_balancer.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "pcap_writer.h"
#include "pipeline_stats.h"
#include "pipeline_types.h"
#include "rule_manager.h"
#include "thread_safe_queue.h"
#include "types.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace PacketAnalyzer;
using namespace DPI;

namespace {

uint32_t parseIPv4(const std::string& text) {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    char dot1 = 0, dot2 = 0, dot3 = 0;
    std::istringstream input(text);

    if (!(input >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d) ||
        dot1 != '.' || dot2 != '.' || dot3 != '.' ||
        a > 255 || b > 255 || c > 255 || d > 255) {
        throw std::invalid_argument("Invalid IPv4 address: " + text);
    }

    input >> std::ws;
    if (!input.eof()) {
        throw std::invalid_argument("Invalid IPv4 address: " + text);
    }

    return (a << 24) | (b << 16) | (c << 8) | d;
}

std::size_t parseSize(const std::string& text, const std::string& option,
                      std::size_t min_value, std::size_t max_value) {
    std::size_t parsed_chars = 0;
    unsigned long long value = 0;
    try {
        value = std::stoull(text, &parsed_chars);
    } catch (const std::exception&) {
        throw std::invalid_argument("Invalid value for " + option + ": " + text);
    }

    if (parsed_chars != text.size() || value < min_value || value > max_value) {
        throw std::invalid_argument("Value for " + option + " must be between " +
                                    std::to_string(min_value) + " and " +
                                    std::to_string(max_value));
    }
    return static_cast<std::size_t>(value);
}

AppType parseApp(const std::string& value) {
    if (value == "YouTube" || value == "youtube") return AppType::YOUTUBE;
    if (value == "Google" || value == "google") return AppType::GOOGLE;
    if (value == "Facebook" || value == "facebook") return AppType::FACEBOOK;
    if (value == "Instagram" || value == "instagram") return AppType::INSTAGRAM;
    if (value == "Netflix" || value == "netflix") return AppType::NETFLIX;
    if (value == "GitHub" || value == "github") return AppType::GITHUB;
    if (value == "WhatsApp" || value == "whatsapp") return AppType::WHATSAPP;
    if (value == "Discord" || value == "discord") return AppType::DISCORD;
    if (value == "HTTP" || value == "http") return AppType::HTTP;
    if (value == "HTTPS" || value == "https") return AppType::HTTPS;
    if (value == "DNS" || value == "dns") return AppType::DNS;
    return AppType::UNKNOWN;
}

void printUsage(const char* exe) {
    std::cout
        << "Usage: " << exe << " input.pcap output.pcap [options]\n"
        << "Options:\n"
        << "  --block-domain DOMAIN       Block a domain and its subdomains\n"
        << "  --block-ip IPV4             Block packets sourced from an IPv4 address\n"
        << "  --block-app APP             Block an identified application\n"
        << "  --lbs N                     Number of load-balancer threads (default 2)\n"
        << "  --fps N                     Fast-path workers per LB (default 2)\n"
        << "  --queue-capacity N          Capacity of each bounded queue (default 2048)\n";
}

struct WriterState {
    bool failed = false;
    uint64_t next_packet_index = 1;
    std::map<uint64_t, PacketResult> pending;
};

void outputWriterLoop(PcapWriter& writer,
                      ThreadSafeQueue<PacketResult>& output_queue,
                      PipelineStats& stats) {
    WriterState state;
    PacketResult result;

    while (output_queue.pop(result)) {
        state.pending.emplace(result.packet_index, std::move(result));

        // Workers finish at different times. Reorder their results by the
        // original PCAP packet index so the output capture preserves order.
        for (;;) {
            auto it = state.pending.find(state.next_packet_index);
            if (it == state.pending.end()) break;

            PacketResult ready = std::move(it->second);
            state.pending.erase(it);

            if (ready.forward) {
                if (!state.failed && writer.write(ready.raw)) {
                    stats.written_packets.fetch_add(1);
                } else {
                    state.failed = true;
                    stats.write_errors.fetch_add(1);
                }
            }

            ++state.next_packet_index;
        }
    }

    // If every input packet produced a result, pending must be empty.
    // A non-empty map indicates an internal pipeline/queue error.
    if (!state.pending.empty()) {
        stats.queue_errors.fetch_add(state.pending.size());
    }

    writer.close();
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    const std::string input_file = argv[1];
    const std::string output_file = argv[2];

    if (input_file == output_file) {
        std::cerr << "Input and output PCAP paths must be different.\n";
        return 1;
    }

    std::size_t num_lbs = 2;
    std::size_t fps_per_lb = 2;
    std::size_t queue_capacity = 2048;
    RuleManager rules;

    try {
        for (int i = 3; i < argc; ++i) {
            const std::string option = argv[i];
            if (i + 1 >= argc) {
                throw std::invalid_argument("Missing value for " + option);
            }
            const std::string value = argv[++i];

            if (option == "--block-domain") {
                rules.blockDomain(value);
            } else if (option == "--block-ip") {
                rules.blockIP(parseIPv4(value));
            } else if (option == "--block-app") {
                const AppType app = parseApp(value);
                if (app == AppType::UNKNOWN) {
                    throw std::invalid_argument("Unknown application: " + value);
                }
                rules.blockApp(app);
            } else if (option == "--lbs") {
                num_lbs = parseSize(value, option, 1, 64);
            } else if (option == "--fps") {
                fps_per_lb = parseSize(value, option, 1, 128);
            } else if (option == "--queue-capacity") {
                queue_capacity = parseSize(value, option, 1, 1000000);
            } else {
                throw std::invalid_argument("Unknown option: " + option);
            }
        }
    } catch (const std::exception& error) {
        std::cerr << "Argument error: " << error.what() << '\n';
        printUsage(argv[0]);
        return 1;
    }

    PcapReader reader;
    if (!reader.open(input_file)) return 1;

    PcapWriter writer;
    if (!writer.open(output_file, reader.getGlobalHeader())) {
        std::cerr << "Could not open output file: " << output_file << '\n';
        reader.close();
        return 1;
    }

    const std::size_t total_fps = num_lbs * fps_per_lb;

    PipelineStats stats;
    ThreadSafeQueue<PacketResult> output_queue(queue_capacity);

    std::thread writer_thread(
        outputWriterLoop,
        std::ref(writer),
        std::ref(output_queue),
        std::ref(stats));

    // Fast-path workers each own their own connection table. A given flow is
    // always routed to exactly one worker, so that table needs no flow mutex.
    std::vector<std::unique_ptr<FastPathWorker>> fast_paths;
    std::vector<FastPathWorker*> fast_path_ptrs;
    fast_paths.reserve(total_fps);
    fast_path_ptrs.reserve(total_fps);

    for (std::size_t i = 0; i < total_fps; ++i) {
        fast_paths.emplace_back(std::make_unique<FastPathWorker>(
            i, queue_capacity, rules, output_queue, stats));
        fast_path_ptrs.push_back(fast_paths.back().get());
    }

    for (auto& worker : fast_paths) worker->start();

    std::vector<std::unique_ptr<LoadBalancer>> load_balancers;
    load_balancers.reserve(num_lbs);
    for (std::size_t lb_id = 0; lb_id < num_lbs; ++lb_id) {
        // Match the reference architecture: each LB owns a contiguous group
        // of fast-path workers (for example, LB0 -> FP0/FP1).
        std::vector<FastPathWorker*> workers_for_lb;
        workers_for_lb.reserve(fps_per_lb);
        const std::size_t first_fp = lb_id * fps_per_lb;
        for (std::size_t local_fp = 0; local_fp < fps_per_lb; ++local_fp) {
            workers_for_lb.push_back(fast_path_ptrs[first_fp + local_fp]);
        }

        load_balancers.emplace_back(std::make_unique<LoadBalancer>(
            lb_id, queue_capacity, workers_for_lb, stats));
    }
    for (auto& lb : load_balancers) lb->start();

    std::cout << "\n========== DPI MULTITHREADED ENGINE ==========\n"
              << "Load balancers: " << num_lbs << '\n'
              << "Fast-path workers per LB: " << fps_per_lb << '\n'
              << "Total fast-path workers: " << total_fps << '\n'
              << "Queue capacity: " << queue_capacity << '\n';

    PacketParser parser;
    RawPacket raw;
    ParsedPacket parsed;
    uint64_t packet_index = 0;
    bool dispatch_failed = false;

    while (reader.readNextPacket(raw)) {
        ++packet_index;
        stats.total_packets.fetch_add(1);

        if (!parser.parse(raw, parsed)) {
            // Unknown/non-TCP/UDP packet types are preserved unchanged.
            stats.passthrough_packets.fetch_add(1);
            PacketResult passthrough;
            passthrough.packet_index = packet_index;
            passthrough.forward = true;
            passthrough.raw = std::move(raw);
            if (!output_queue.push(std::move(passthrough))) {
                stats.queue_errors.fetch_add(1);
                dispatch_failed = true;
                break;
            }
            continue;
        }

        stats.parsed_packets.fetch_add(1);

        FiveTuple tuple{
            parsed.src_ip,
            parsed.dst_ip,
            parsed.src_port,
            parsed.dst_port,
            parsed.protocol
        };

        PacketJob job;
        job.packet_index = packet_index;
        job.raw = std::move(raw);
        job.parsed = parsed;
        job.flow_key = tuple.canonical();

        // First-level distribution: one LB owns all packets of this flow.
        const std::size_t lb_index =
            FiveTupleHash{}(job.flow_key) % load_balancers.size();

        if (!load_balancers[lb_index]->enqueue(std::move(job))) {
            stats.queue_errors.fetch_add(1);
            dispatch_failed = true;
            break;
        }
    }

    reader.close();

    // Shutdown order is important: drain LBs before closing worker queues.
    for (auto& lb : load_balancers) lb->closeInput();
    for (auto& lb : load_balancers) lb->join();

    for (auto& worker : fast_paths) worker->closeInput();
    for (auto& worker : fast_paths) worker->join();

    // All workers have now submitted their final result.
    output_queue.close();
    writer_thread.join();

    uint64_t total_flows = 0;
    for (const auto& worker : fast_paths) total_flows += worker->flowCount();

    std::cout << "\n========== PROCESSING REPORT ==========\n"
              << "Total packets:       " << stats.total_packets.load() << '\n'
              << "Parsed TCP/UDP:       " << stats.parsed_packets.load() << '\n'
              << "Passthrough packets:  " << stats.passthrough_packets.load() << '\n'
              << "Forwarded/written:    " << stats.written_packets.load() << '\n'
              << "Dropped:              " << stats.dropped_packets.load() << '\n'
              << "Tracked flows:        " << total_flows << '\n'
              << "Write errors:         " << stats.write_errors.load() << '\n'
              << "Queue errors:         " << stats.queue_errors.load() << '\n';

    std::cout << "\n========== LOAD BALANCER DISTRIBUTION ==========\n";
    for (const auto& lb : load_balancers) {
        std::cout << "LB" << lb->id()
                  << " dispatched: " << lb->dispatched() << " packets\n";
        const auto& distribution = lb->workerDistribution();
        const std::size_t first_fp = lb->id() * fps_per_lb;
        for (std::size_t local_fp = 0; local_fp < distribution.size(); ++local_fp) {
            std::cout << "  -> FP" << (first_fp + local_fp) << ": "
                      << distribution[local_fp] << " packets\n";
        }
    }

    std::cout << "\n========== FAST-PATH WORKERS ==========\n";
    for (const auto& worker : fast_paths) {
        std::cout << "FP" << worker->id()
                  << " processed: " << worker->processed()
                  << " packets, flows: " << worker->flowCount() << '\n';
    }

    if (dispatch_failed || stats.write_errors.load() != 0 ||
        stats.queue_errors.load() != 0) {
        std::cerr << "Pipeline completed with errors; inspect the report.\n";
        return 1;
    }

    return 0;
}
