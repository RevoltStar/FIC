#ifndef DESKTOP_BACKEND_COMMAND_H
#define DESKTOP_BACKEND_COMMAND_H

#include <fic/core/process/ProcessExecutor.h>
#include "session/UserSession.h"

#include <optional>
#include <string>
#include <vector>

namespace desktop_backend {

std::string findExecutable(const std::vector<std::string>& paths);

bool execute(
    const UserSession& session,
    const SessionContext& context,
    const std::string& executable,
    const std::vector<std::string>& arguments,
    ProcessResult& result,
    std::string& error
);

std::string trim(std::string value);
std::optional<int> parseInteger(const std::string& value);
bool parseBoolean(const std::string& value, bool& result);

} // namespace desktop_backend

#endif // DESKTOP_BACKEND_COMMAND_H
