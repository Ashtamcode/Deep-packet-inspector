
#include "D:\Dpi engine\include\sni_extractor.h"
#include "D:\Dpi engine\include\app_classifier.h"

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

using namespace DPI;

int main() {

    int passed = 0;
    int failed = 0;

    auto check = [&](const std::string& name, bool result) {

        if (result) {
            std::cout << "[PASS] " << name << '\n';
            passed++;
        }
        else {
            std::cout << "[FAIL] " << name << '\n';
            failed++;
        }
    };

    // =====================================
    // TEST 1: HTTP HOST EXTRACTION
    // =====================================

    std::string request =
        "GET / HTTP/1.1\r\n"
        "Host: www.youtube.com\r\n"
        "User-Agent: TestBrowser\r\n"
        "\r\n";

    auto host = SNIExtractor::extractHTTP(
        reinterpret_cast<const uint8_t*>(request.data()),
        request.size()
    );

    check(
        "HTTP Host Extraction",
        host && *host == "www.youtube.com"
    );

    // =====================================
    // TEST 2: TLS SNI EXTRACTION
    // =====================================

    // Construct a minimal TLS Client Hello
    // containing SNI = example.com.

    std::vector<uint8_t> tls = {
        0x16, 0x03, 0x01, 0x00, 0x43,
        0x01, 0x00, 0x00, 0x3f,
        0x03, 0x03
    };

    // 32-byte random value.
    for (int i = 0; i < 32; i++) {
        tls.push_back(0x00);
    }

    const uint8_t rest[] = {
        0x00,             // Session ID length
        0x00, 0x02,       // Cipher suites length
        0x13, 0x01,       // Cipher suite
        0x01, 0x00,       // Compression
        0x00, 0x14,       // Extensions length

        0x00, 0x00,       // SNI extension type
        0x00, 0x10,       // Extension length

        0x00, 0x0e,       // Server name list length
        0x00,             // Hostname type
        0x00, 0x0b        // Hostname length
    };

    tls.insert(
        tls.end(),
        std::begin(rest),
        std::end(rest)
    );

    std::string domain = "example.com";

    for (char c : domain) {
        tls.push_back(static_cast<uint8_t>(c));
    }

    auto sni = SNIExtractor::extractTLS(
        tls.data(),
        tls.size()
    );

    check(
        "TLS SNI Extraction",
        sni && *sni == "example.com"
    );

    // =====================================
    // TEST 3: APPLICATION CLASSIFICATION
    // =====================================

    check(
        "YouTube Classification",
        AppClassifier::classify(
            "www.youtube.com", true
        ) == AppType::YOUTUBE
    );

    check(
        "Facebook Classification",
        AppClassifier::classify(
            "www.facebook.com", true
        ) == AppType::FACEBOOK
    );

    check(
        "Netflix Classification",
        AppClassifier::classify(
            "www.netflix.com", true
        ) == AppType::NETFLIX
    );

    check(
        "GitHub Classification",
        AppClassifier::classify(
            "github.com", true
        ) == AppType::GITHUB
    );

    // =====================================
    // TEST 4: UNKNOWN DOMAIN
    // =====================================

    check(
        "Unknown HTTPS Domain",
        AppClassifier::classify(
            "example.org", true
        ) == AppType::HTTPS
    );

    // =====================================
    // TEST 5: APPLICATION NAME
    // =====================================

    check(
        "Application Name Conversion",
        AppClassifier::toString(
            AppType::YOUTUBE
        ) == "YouTube"
    );

    // =====================================
    // FINAL REPORT
    // =====================================

    std::cout << "\n========== TEST REPORT ==========\n";

    std::cout << "Passed: " << passed << '\n';
    std::cout << "Failed: " << failed << '\n';

    if (failed == 0) {
        std::cout << "\nALL TESTS PASSED!\n";
    }

    return failed == 0 ? 0 : 1;
}
