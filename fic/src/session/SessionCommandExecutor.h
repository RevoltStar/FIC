#ifndef SESSION_COMMAND_EXECUTOR_H
#define SESSION_COMMAND_EXECUTOR_H

#include <fic/core/process/ProcessExecutor.h>
#include "session/UserSession.h"

#include <string>
#include <optional>
#include <vector>

struct SessionEnvironmentOverride {
    std::string name;
    std::optional<std::string> value;
};

class SessionCommandExecutor {
public:
    static ProcessResult execute(
        const UserSession& session,
        const SessionContext& context,
        const std::string& executable,
        const std::vector<std::string>& arguments
    );

    static ProcessResult executeWithKdeConfigEnvironment(
        const UserSession& session,
        const SessionContext& context,
        const std::string& executable,
        const std::vector<std::string>& arguments,
        const std::vector<SessionEnvironmentOverride>& environmentOverrides
    );
};

#endif // SESSION_COMMAND_EXECUTOR_H
