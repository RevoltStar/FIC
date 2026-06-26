#include "BlockInfoCollector.h"

#include <cstdlib>
#include <string>
#include <vector>

namespace {
std::string envValue(const char *name)
{
    const char *value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

bool startsWith(const std::string &value, const std::string &prefix)
{
    return value.rfind(prefix, 0) == 0;
}

bool contains(const std::string &value, const std::string &needle)
{
    return value.find(needle) != std::string::npos;
}

std::vector<std::string> createBlockControlList()
{
    const std::string devtype = envValue("DEVTYPE");
    const std::string devname = envValue("DEVNAME");
    const std::string devpath = envValue("DEVPATH");
    const std::string dmUuid = envValue("DM_UUID");

    if (!dmUuid.empty() || startsWith(devname, "/dev/dm-") || contains(devpath, "/virtual/block/dm-"))
    {
        return {"DM_UUID", "DM_NAME", "DM_TYPE"};
    }

    if (startsWith(devname, "/dev/loop") || startsWith(devname, "/dev/ram") ||
        startsWith(devname, "/dev/zram") || contains(devpath, "/virtual/block/loop") ||
        contains(devpath, "/virtual/block/ram") || contains(devpath, "/virtual/block/zram"))
    {
        return {"DEVTYPE", "DEVPATH"};
    }

    if (devtype == "partition")
    {
        return {"DEVTYPE", "ID_PART_ENTRY_UUID", "ID_FS_UUID", "ID_PART_ENTRY_NUMBER",
                "ID_SERIAL"};
    }

    return {"DEVTYPE", "ID_WWN", "ID_SERIAL", "ID_SERIAL_SHORT",
            "ID_MODEL", "ID_VENDOR"};
}
}

BlockInfoCollector::BlockInfoCollector()
    : UDEVInfoCollector(createBlockControlList()) {}
