#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

namespace DPI
{
    class SNIExtractor
    {
    public:
        static std::optional<std::string> extractTLS(
            const uint8_t *data,
            size_t length);

        static std::optional<std::string> extractHTTP(
            const uint8_t *data,
            size_t length);
    };
}

#endif