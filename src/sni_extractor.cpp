#include "sni_extractor.h"

#include <algorithm>
#include <cctype>
#include <cstring>

static uint16_t readbE16(const uint8_t *data)
{
    return (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
}

static uint32_t readBE24(const uint8_t *data)
{
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           static_cast<uint32_t>(data[2]);
}
namespace DPI
{
    static std::string toLower(std::string value)
    {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            });
        return value;
    }

    std::optional<std::string> SNIExtractor::extractHTTP(
        const uint8_t *data,
        size_t length)
    {
        if (data == nullptr || length == 0)
        {
            return std::nullopt;
        }
        // Convert payload to string

        std::string request(
            reinterpret_cast<const char *>(data),
            length);

        // Find the end of the HTTP req line

        size_t line_end = request.find("\r\n");
        if (line_end == std::string::npos)
        {
            return std::nullopt;
        }

        // Only inspect know HTTP methods

        const std::string first_line = request.substr(0, line_end);
        const char *methods[] = {
            "GET",
            "POST",
            "HEAD",
            "PUT",
            "DELETE",
            "OPTIONS",
            "PATCH",
            "CONNECT"};

        bool valid_method = false;
        for (const char *method : methods)
        {
            if (first_line.rfind(method, 0) == 0)
            {
                valid_method = true;
                break;
            }
        }

        if (!valid_method)
        {
            return std::nullopt;
        }

        size_t postion = line_end + 2;
        while (postion < request.size())
        {
            size_t end = request.find("\r\n", postion);

            if (end == std::string::npos)
            {
                break;
            }
            if (end == postion)
                break;

            std::string line = request.substr(postion, end - postion);
            size_t colon = line.find(':');

            if (colon != std::string::npos)
            {
                std::string name =
                    toLower(line.substr(0, colon));

                if (name == "host")
                {

                    std::string host = line.substr(colon + 1);

                    size_t start = host.find_first_not_of(" \t");
                    size_t finish = host.find_last_not_of(" \t");

                    if (start == std::string::npos)
                    {
                        return std::nullopt;
                    }
                    host = host.substr(start, finish - start + 1);
                    return toLower(host);
                }
            }

            // Advance for every header line, including lines without a colon.
            postion = end + 2;
        }
        return std::nullopt;
    }
    std::optional<std::string> SNIExtractor::extractTLS(const uint8_t *data, size_t length)
    {
        if (data == nullptr || length < 9)
        {
            return std::nullopt;
        }

        if (data[0] != 0x16)
        {
            return std::nullopt;
        }

        size_t record_length = readbE16(data + 3);
        if (record_length > length - 5)
        {
            return std::nullopt;
        }

        if (data[5] != 0x01)
        {
            return std::nullopt;
        }

        size_t handshake_length = readBE24(data + 6);
        if (record_length < 4 ||
    handshake_length > record_length - 4) {

    return std::nullopt;
}

        size_t end = 9 + handshake_length;
        size_t offset = 9;

        if (offset + 34 > end)
        {
            return std::nullopt;
        }

        offset += 34;

        // session id
        if (offset + 1 > end)
        {
            return std::nullopt;
        }
        uint8_t session_length = data[offset++];
        if (session_length > end - offset)
        {
            return std::nullopt;
        }

        offset += session_length;

        // Cipher suites

        if (offset + 2 > end)
        {
            return std::nullopt;
        }

        uint16_t cipher_lenght = readbE16(data + offset);
        offset += 2;

        if (cipher_lenght > end - offset)
        {
            return std::nullopt;
        }
        offset += cipher_lenght;

        // Compression methods

        if (offset + 1 > end)
        {
            return std::nullopt;
        }

        uint8_t compression_length = data[offset++];
        if (compression_length > end - offset)
        {
            return std::nullopt;
        }
        offset += compression_length;

        if (offset == end)
        {
            return std::nullopt;
        }
        if (offset + 2 > end)
        {
            return std::nullopt;
        }

        uint16_t extensions_length = readbE16(data + offset);
        offset += 2;

        if (extensions_length > end - offset)
        {
            return std::nullopt;
        }

        size_t extensions_end = offset + extensions_length;

        while(offset + 4 <= extensions_end){
            uint16_t extension_type = readbE16(data+offset);
            uint16_t extension_length = readbE16(data+offset+2);
            offset+=4;

            if(extension_length > extensions_end - offset){
                return std::nullopt;
            }

            if(extension_type == 0x0000){
                if(extension_length<4){
                    return std::nullopt;
                }

                size_t ext_end = offset +extension_length;

                uint16_t list_length = readbE16(data+offset);
                offset+=2;

                if(list_length > ext_end - offset){
                    return std::nullopt;
                }

                size_t list_end = offset + list_length;
                while(offset + 3 <=list_end){
                    uint8_t name_type = data[offset++];
                    uint16_t name_length = readbE16(data+offset);
                    offset+=2;
                    if(name_length > list_end - offset){
                        return std::nullopt;
                    }
                    if(name_type == 0){
                        std::string hostname(
                            reinterpret_cast<const char*>(
                                data+offset
                            ),
                            name_length
                        );
                        return toLower(hostname);
                    }
                    offset+=name_length;
                }
                return std::nullopt;
            }
            offset +=extension_length;
        }

        return std::nullopt;
    }

}
