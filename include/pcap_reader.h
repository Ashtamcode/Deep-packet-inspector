#ifndef PCAP_READER_H
#define PCAP_READER_H

#include<cstdint>
#include<string>
#include<vector>
#include<fstream>

namespace PacketAnalyzer{
    // The global header of PCAP file (binary file the containes the information about the packets)

    struct PcapGlobalHeader
    {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    };

    // Each packet contains this 16-byte header

    struct PcapPacketHeader{
        uint32_t ts_sec=0;
        uint32_t ts_usec=0;
        uint32_t incl_len=0;
        uint32_t orig_len=0;
    };

    // Holds the packet metadat and actual raw bytes

    struct RawPacket{
        PcapPacketHeader header{};
        std::vector<uint8_t>data;
    };

    class PcapReader{
    private:
        std::ifstream file_;
        PcapGlobalHeader global_header_{};
        bool needs_byte_swap = false;

        uint16_t swap16(uint16_t value);
        uint32_t swap32(uint32_t value);
    public:
        PcapReader() =default;

        ~PcapReader();

        bool open(const std::string& filename);
        bool readNextPacket(RawPacket& packet);
        void close();
        bool isOpen() const;
        const PcapGlobalHeader& getGlobalHeader() const;

    };
    
}

#endif