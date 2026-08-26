#ifndef FIC_DEVICE_LIFECYCLE_H
#define FIC_DEVICE_LIFECYCLE_H

#include <fic/device-db/DB.h>

#include <string>
#include <vector>

namespace fic::device_control {

struct DeviceRemovalResult {
    bool ok = false;
    bool alreadyRemoved = false;
    int deviceId = -1;
    std::vector<int> affectedIds;
    std::string error;
};

class DeviceLifecycle {
public:
    explicit DeviceLifecycle(DB& db);

    bool recordDenyResult(int deviceId,
                          bool enforced,
                          const std::string& details,
                          std::string& error);

    DeviceRemovalResult removeCurrentOccurrence(const std::string& devpath,
                                                 const std::string& subsystem,
                                                 const std::string& bootId);

    DeviceRemovalResult disconnectCurrentSubtree(int deviceId,
                                                 const std::string& bootId,
                                                 const std::string& eventDetails);

private:
    DeviceRemovalResult disconnectCurrentSubtreeInTransaction(
        int deviceId,
        const std::string& bootId,
        const std::string& eventDetails);

    DB& db_;
};

} // namespace fic::device_control

#endif
