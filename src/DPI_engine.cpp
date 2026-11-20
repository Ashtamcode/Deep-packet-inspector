
#include "pcap_reader.h"
#include "pcap_writer.h"
#include "packet_parser.h"
#include <cstddef>
#include "types.h"
#include "sni_extractor.h"
#include "app_classifier.h"
#include "rule_manager.h"
#include "connection_tracker.h"
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <string>

using namespace PacketAnalyzer;

using namespace DPI;

uint32_t parseIP(const std::string &ip)
{

    unsigned int a, b, c, d;
    char dot1, dot2, dot3;

    std::istringstream input(ip);

    if (!(input >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d) ||
        dot1 != '.' || dot2 != '.' || dot3 != '.' ||
        a > 255 || b > 255 || c > 255 || d > 255)
    {

        throw std::invalid_argument("Invalid IPv4 address");
    }

    return (a << 24) | (b << 16) | (c << 8) | d;
}

int main(int argc, char *argv[])
{

    if (argc < 3)
    {

        std::cout
            << "Usage: dpi_engine input.pcap output.pcap "
            << "[--block-domain domain] "
            << "[--block-ip address] "
            << "[--block-app name]\n";

        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    RuleManager rules;

    // Parse command-line blocking rules.
    for (int i = 3; i < argc; i++)
    {

        std::string option = argv[i];

        if (i + 1 >= argc)
        {
            std::cerr << "Missing value for " << option << '\n';
            return 1;
        }

        std::string value = argv[++i];

        if (option == "--block-domain")
        {

            rules.blockDomain(value);
        }

        else if (option == "--block-ip")
        {

            try
            {
                rules.blockIP(parseIP(value));
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << '\n';
                return 1;
            }
        }

        else if (option == "--block-app")
        {

            AppType app = AppType::UNKNOWN;

            if (value == "YouTube")
                app = AppType::YOUTUBE;
            else if (value == "Facebook")
                app = AppType::FACEBOOK;
            else if (value == "Netflix")
                app = AppType::NETFLIX;
            else if (value == "Instagram")
                app = AppType::INSTAGRAM;
            else if (value == "GitHub")
                app = AppType::GITHUB;

            if (app == AppType::UNKNOWN)
            {
                std::cerr << "Unknown application: " << value << '\n';
                return 1;
            }

            rules.blockApp(app);
        }

        else
        {
            std::cerr << "Unknown option: " << option << '\n';
            return 1;
        }
    }

    PcapReader reader;

    if (!reader.open(input_file))
    {
        return 1;
    }

    PcapWriter writer;

    if (!writer.open(output_file, reader.getGlobalHeader()))
    {
        std::cerr << "Could not open output file\n";
        return 1;
    }

    PacketParser parser;

    ConnectionTracker tracker;

    RawPacket raw;
    ParsedPacket parsed;

    uint64_t total = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;

    while (reader.readNextPacket(raw))
    {

        total++;

        if (!parser.parse(raw, parsed))
        {

            // Preserve unsupported or unparsed packets.
            if (!writer.write(raw))
            {

                std::cerr << "Failed to write packet "
                          << total << '\n';

                reader.close();
                writer.close();

                return 1;
            }

            forwarded++;

            continue;
        }

        FiveTuple tuple = {
            parsed.src_ip,
            parsed.dst_ip,
            parsed.src_port,
            parsed.dst_port,
            parsed.protocol};

        Flow &flow = tracker.getflow(tuple.canonical());

        flow.packet_count++;

        flow.byte_count += raw.data.size();

        if (flow.action == FlowAction::BLOCKED)
        {

            dropped++;
            continue;
        }

        const uint8_t *payload =
            raw.data.data() + parsed.payload_offset;

        std::optional<std::string> hostname;

        if (parsed.is_tcp)
        {

            hostname = SNIExtractor::extractTLS(
                payload,
                parsed.payload_length);

            if (!hostname)
            {

                hostname = SNIExtractor::extractHTTP(
                    payload,
                    parsed.payload_length);
            }
        }

        if (hostname)
        {

            flow.hostname = *hostname;

            flow.app = AppClassifier::classify(
                flow.hostname,
                parsed.dst_port == 443);
        }
        else if (flow.app == AppType::UNKNOWN)
        {

            if ((parsed.is_udp && parsed.src_port == 53 )||
                (parsed.is_udp && parsed.dst_port == 53))
            {

                flow.app = AppType::DNS;
            }
            else if (parsed.is_tcp && parsed.dst_port == 443)
            {

                flow.app = AppType::HTTPS;
            }
            else if (parsed.is_tcp && parsed.dst_port == 80)
            {

                flow.app = AppType::HTTP;
            }
        }

        if (rules.shouldBlock(
                parsed.src_ip,
                flow.app,
                flow.hostname))
        {

            flow.action = FlowAction::BLOCKED;

            dropped++;

            continue;
        }

        if (writer.write(raw))
        {
            forwarded++;
        }
    }

    writer.close();
    reader.close();

    std::cout << "\n========== DPI REPORT ==========\n";

    std::cout << "Total packets: " << total << '\n';
    std::cout << "Forwarded: " << forwarded << '\n';
    std::cout << "Dropped: " << dropped << '\n';

    std::cout << "Tracked flows: " << tracker.size() << '\n';

    return 0;
}
