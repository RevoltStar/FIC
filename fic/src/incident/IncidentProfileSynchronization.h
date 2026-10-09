#pragma once
#include <mutex>

namespace fic::incident {
// In-process lock ordering: profile authority FIRST, controller transition
// mutex SECOND. Recursive because a controller transition invokes FIREWALL.
// This prevents a competing normal apply from crossing a severity publication.
inline std::recursive_mutex& incidentProfileMutex() {
    static std::recursive_mutex mutex;
    return mutex;
}
// Controller-owned stricter effective decision when persistence failed while
// an older valid token remains. Access only under incidentProfileMutex().
inline bool& incidentForcedNetworkQuarantine() {
    static bool required = false;
    return required;
}
}
