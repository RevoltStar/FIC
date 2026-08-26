#include "features/devices/services/DeviceService.h"

#include <fic/ipc/FicIpcClient.h>

QString DeviceService::currentBootId() const
{
    const auto response = fic::ipc::Client().request({{"command", "boot_id"}});
    if (!response.value("ok", false)) {
        return {};
    }
    return QString::fromStdString(response.value("boot_id", ""));
}
