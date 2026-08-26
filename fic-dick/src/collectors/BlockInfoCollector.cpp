#include "BlockInfoCollector.h"

#include <string>
#include <vector>

namespace {
bool startsWith(const std::string &value, const std::string &prefix)
{
    return value.rfind(prefix, 0) == 0;
}

bool contains(const std::string &value, const std::string &needle)
{
    return value.find(needle) != std::string::npos;
}
}

BlockInfoCollector::BlockInfoCollector()
    : UDEVInfoCollector(std::vector<std::string>{}) {
    set_control_list(control_list_for_current_env());
}

std::vector<std::string> BlockInfoCollector::control_list_for_current_env() const
{
    const std::string devtype = get_env_value("DEVTYPE");
    const std::string devname = get_env_value("DEVNAME");
    const std::string devpath = get_env_value("DEVPATH");
    const std::string dmUuid = get_env_value("DM_UUID");

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
        if (!get_env_value("ID_PART_ENTRY_UUID").empty()) {
            return {"DEVTYPE", "ID_PART_ENTRY_UUID", "ID_SERIAL"};
        }
        if (!get_env_value("ID_FS_UUID").empty()) {
            return {"DEVTYPE", "ID_FS_UUID", "ID_SERIAL"};
        }
        if (!get_env_value("ID_PART_ENTRY_NUMBER").empty() && !get_env_value("ID_SERIAL").empty()) {
            return {"DEVTYPE", "ID_SERIAL", "ID_PART_ENTRY_NUMBER"};
        }
        if (!devname.empty()) {
            return {"DEVTYPE", "DEVNAME"};
        }
        if (!get_env_value("MAJOR").empty() && !get_env_value("MINOR").empty()) {
            return {"DEVTYPE", "MAJOR", "MINOR"};
        }
        return {"DEVTYPE", "DEVPATH"};
    }

    return {"DEVTYPE", "ID_WWN", "ID_SERIAL", "ID_SERIAL_SHORT",
            "ID_MODEL", "ID_VENDOR"};
}
