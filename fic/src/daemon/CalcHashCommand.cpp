#include "daemon/CalcHashCommand.h"

#include <fic/core/integrity/CommandHashStore.h>
#include <fic/ipc/FicIpcClient.h>

nlohmann::json calcHashCommandResponse(const std::string& executable)
{
    std::string error;
    if (!CommandHashStore::saveHash(executable, error)) {
        return fic::ipc::make_error_response(
            error.empty() ? "failed to update command hash" : error);
    }
    return fic::ipc::make_ok_response("command hash updated");
}
