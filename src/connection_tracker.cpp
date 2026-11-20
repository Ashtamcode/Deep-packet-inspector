#include "D:\Dpi engine\include\connection_tracker.h"

namespace DPI{

    Flow& ConnectionTracker::getflow(const FiveTuple& tuple){
        auto it = flows.find(tuple);

        if(it == flows.end()){
            it = flows.emplace(tuple,Flow{}).first;
        }
        return it->second;
    }
    size_t ConnectionTracker::size()const{
        return flows.size();
    }
}