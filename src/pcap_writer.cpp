#include "D:\Dpi engine\include\pcap_writer.h"

namespace PacketAnalyzer
{
    PcapWriter::~PcapWriter()
    {
        close();
    }

    bool PcapWriter::open(const std::string &filename, const PcapGlobalHeader &header)
    {
        file_.open(filename, std::ios::binary);
        if (!file_)
        {
            return false;
        }

        PcapGlobalHeader output = header;

        const bool little_endian = []()
        {
            uint16_t x = 1;
            return *reinterpret_cast<uint8_t *>(&x) == 1;
        }();

        auto swap16 = [](uint16_t v)
        {
            return static_cast<uint16_t>((v >> 8) | (v << 8));
        };

        auto swap32 = [](uint32_t v)
        {
            return ((v & 0xFF000000) >> 24) |
                   ((v & 0x00FF0000) >> 8) |
                   ((v & 0x0000FF00) << 8) |
                   ((v & 0x000000FF) << 24);
        };

        if (!little_endian)
        {
            output.magic_number = swap32(output.magic_number);
            output.version_major = swap16(output.version_major);
            output.version_minor = swap16(output.version_minor);
            output.thiszone = static_cast<int32_t>(
                swap32(static_cast<uint32_t>(output.thiszone)));
            output.sigfigs = swap32(output.sigfigs);
            output.snaplen = swap32(output.snaplen);
            output.network = swap32(output.network);
        }

        file_.write(
            reinterpret_cast<const char*>(&output),
            sizeof(output)
        );
        if(!file_){
            close();
            return false;
        }
        return true;
    }
    bool PcapWriter::write(const RawPacket& packet){
        if(!file_.is_open()){
            return false;
        }
        const PcapPacketHeader header = packet.header;

        if(packet.data.size() != header.incl_len){
            return false;
        }
        file_.write(
            reinterpret_cast<const char*>(&header),
            sizeof(header)
        );
        if(!packet.data.empty()){
            file_.write(
                reinterpret_cast<const char*>(packet.data.data()),
                static_cast<std::streamsize>(packet.data.size())
            );
        }
        return static_cast<bool>(file_);
    }

    void PcapWriter::close(){
        if(file_.is_open()){
            file_.close();
        }
    }
}