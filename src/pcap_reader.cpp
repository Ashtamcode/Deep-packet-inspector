#include "pcap_reader.h"
#include <iostream>
#include <cstring>
#include <limits>

namespace PacketAnalyzer
{
    constexpr uint32_t PCAP_MAGIC = 0xa1b2c3d4; // Magic number to indetify a pcap file that contains packets in the standard format
    constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

    PcapReader::~PcapReader()
    {
        close();
    }

    uint16_t PcapReader::swap16(uint16_t value)
    { // byte swap
        return static_cast<uint16_t>(
            (value >> 8) | (value << 8));
    }

    uint32_t PcapReader::swap32(uint32_t value)
    {
        return ((value & 0xFF000000) >> 24) |
               ((value & 0x00FF0000) >> 8) |
               ((value & 0x0000FF00) << 8) |
               ((value & 0x000000FF) << 24);
    }

    bool PcapReader::open(const std::string &filename)
    {
            // Normalize magic number to host-order representation.
        global_header_.magic_number = PCAP_MAGIC;
        close();
        file_.open(filename, std::ios::binary);

        if (!file_.is_open())
        {
            std::cerr << "Cannot open:" << filename << '\n';
            return false;
        }

        file_.read(
            reinterpret_cast<char *>(&global_header_),
            sizeof(PcapGlobalHeader));

        if (file_.gcount() != sizeof(PcapGlobalHeader))
        {
            std::cerr << "Invalid or incomplete PCAP header \n";
            close();
            return false;
        }
        if (global_header_.magic_number == PCAP_MAGIC)
        {
            needs_byte_swap = false;
        }
        else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED)
        {
            needs_byte_swap = true;
        }
        else
        {
            std::cerr << "Invalid PCAP Magic number\n";
            close();
            return false;
        }

        if (needs_byte_swap)
        {
            global_header_.version_major = swap16(global_header_.version_major);
            global_header_.version_minor = swap16(global_header_.version_minor);
            global_header_.thiszone = static_cast<int32_t>(
                swap32(static_cast<uint32_t>(global_header_.thiszone)));
            global_header_.sigfigs =
                swap32(global_header_.sigfigs);

            global_header_.snaplen =
                swap32(global_header_.snaplen);

            global_header_.network =
                swap32(global_header_.network);
        }
        if (global_header_.version_major != 2 ||
            global_header_.version_minor != 4)
        {
            std::cerr << "Unsupported PCAP version\n";
            close();
            return false;
        }

        // Our first parser supports Ethernet captures only.
        if (global_header_.network != 1)
        {
            std::cerr << "Only Ethernet PCAP files are supported\n";
            close();
            return false;
        }

        if (global_header_.snaplen == 0 ||
            global_header_.snaplen > 16 * 1024 * 1024)
        {
            std::cerr << "Invalid PCAP snap length\n";
            close();
            return false;
        }

        std::cout << "PCAP opened successfully\n";
        std::cout << "Version: "
                  << global_header_.version_major << "."
                  << global_header_.version_minor << '\n';

        std::cout << "Snap length: "
                  << global_header_.snaplen << '\n';

        return true;
    }

    bool PcapReader::readNextPacket(RawPacket &packet)
    {

        if (!file_.is_open())
        {
            return false;
        }

        PcapPacketHeader header{};

        file_.read(
            reinterpret_cast<char *>(&header),
            sizeof(header));

        // A clean EOF is different from an incomplete packet header.
        if (file_.gcount() == 0 && file_.eof())
        {
            return false;
        }

        if (file_.gcount() != sizeof(header))
        {
            std::cerr << "Incomplete packet header\n";
            return false;
        }

        if (needs_byte_swap)
        {
            header.ts_sec = swap32(header.ts_sec);
            header.ts_usec = swap32(header.ts_usec);
            header.incl_len = swap32(header.incl_len);
            header.orig_len = swap32(header.orig_len);
        }

        if (header.incl_len > global_header_.snaplen ||
            header.incl_len > 65535 ||
            header.incl_len > header.orig_len ||
            header.ts_usec >= 1000000)
        {

            std::cerr << "Invalid packet metadata\n";
            return false;
        }

        packet.header = header;
        packet.data.resize(header.incl_len);

        if (header.incl_len > 0)
        {
            file_.read(
                reinterpret_cast<char *>(packet.data.data()),
                header.incl_len);

            if (file_.gcount() !=
                static_cast<std::streamsize>(header.incl_len))
            {

                std::cerr << "Incomplete packet data\n";
                return false;
            }
        }

        return true;
    }

    void PcapReader::close()
    {

        if (file_.is_open())
        {
            file_.close();
        }

        needs_byte_swap = false;
    }

    bool PcapReader::isOpen() const
    {
        return file_.is_open();
    }

    const PcapGlobalHeader &
    PcapReader::getGlobalHeader() const
    {
        return global_header_;
    }

}

