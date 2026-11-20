#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "D:\Dpi engine\include\types.h"
#include "D:\Dpi engine\include\app_classifier.h"

#include <unordered_map>
#include <string>

namespace DPI
{
    enum class FlowAction
    {
        FORWARD,
        BLOCKED
    };

    struct Flow
    {
        AppType app = AppType::UNKNOWN;
        std::string hostname;

        FlowAction action = FlowAction::FORWARD;

        uint64_t packet_count = 0;
        uint64_t byte_count = 0;
    };

    class ConnectionTracker
    {
    private:
        std::unordered_map<
            FiveTuple,
            Flow,
            FiveTupleHash>
            flows;
    public:
        Flow& getflow(const FiveTuple& tuple);
        size_t size() const;
    };
}

#endif