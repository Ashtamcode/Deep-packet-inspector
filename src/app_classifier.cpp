#include "D:\Dpi engine\include\app_classifier.h"
static bool matchesDomain(
    const std::string& host,
    const std::string& domain
) {

    return host == domain ||
        (
            host.size() > domain.size() &&
            host.compare(
                host.size() - domain.size(),
                domain.size(),
                domain
            ) == 0 &&
            host[host.size() - domain.size() - 1] == '.'
        );
}
namespace DPI
{
    AppType AppClassifier::classify(
    const std::string& hostname,
    bool is_https
) {

    if (hostname.empty()) {
        return is_https ? AppType::HTTPS : AppType::HTTP;
    }

    if (matchesDomain(hostname, "youtube.com") ||
        matchesDomain(hostname, "googlevideo.com")) {
        return AppType::YOUTUBE;
    }

    if (matchesDomain(hostname, "facebook.com")) {
        return AppType::FACEBOOK;
    }

    if (matchesDomain(hostname, "instagram.com")) {
        return AppType::INSTAGRAM;
    }

    if (matchesDomain(hostname, "netflix.com")) {
        return AppType::NETFLIX;
    }

    if (matchesDomain(hostname, "github.com")) {
        return AppType::GITHUB;
    }

    if (matchesDomain(hostname, "whatsapp.com")) {
        return AppType::WHATSAPP;
    }

    if (matchesDomain(hostname, "discord.com")) {
        return AppType::DISCORD;
    }

    if (matchesDomain(hostname, "google.com")) {
        return AppType::GOOGLE;
    }

    return is_https ? AppType::HTTPS : AppType::HTTP;
}
    std::string AppClassifier::toString(AppType app)
    {
        switch (app)
        {
        case AppType::YOUTUBE:
            return "YouTube";
        case AppType::GOOGLE:
            return "Google";
        case AppType::FACEBOOK:
            return "Facebook";
        case AppType::INSTAGRAM:
            return "Instagram";
        case AppType::NETFLIX:
            return "Netflix";
        case AppType::GITHUB:
            return "GitHub";
        case AppType::WHATSAPP:
            return "WhatsApp";
        case AppType::DISCORD:
            return "Discord";
        case AppType::DNS:
            return "DNS";
        case AppType::HTTP:
            return "HTTP";
        case AppType::HTTPS:
            return "HTTPS";

        default:
            return "Unknown";
        }
    }
}