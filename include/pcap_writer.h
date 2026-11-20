#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include "D:\Dpi engine\include\pcap_reader.h"
#include <fstream>

namespace PacketAnalyzer
{
    class PcapWriter
    {
    private:
        std::ofstream file_;
        bool swap_bytes_ = false;

    public:
        ~PcapWriter();
        bool open(const std::string &filename, const PcapGlobalHeader &header);
        bool write(const RawPacket &packet);
        void close();
    };
}
#endif