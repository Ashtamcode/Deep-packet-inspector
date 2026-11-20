#ifndef APP_CLASSIFIER_H
#define APP_CLASSIFIER_H

#include<string>
namespace DPI{
enum class AppType{
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    YOUTUBE,
    GOOGLE,
    FACEBOOK,
    INSTAGRAM,
    NETFLIX,
    GITHUB,
    WHATSAPP,
    DISCORD
};

class AppClassifier{
public:
    static AppType classify(const std::string& hostname, bool is_https);
    static std::string toString(AppType app);
};
}
#endif