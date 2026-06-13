#ifndef SESSION_COMMAND_EXECUTOR_H
#define SESSION_COMMAND_EXECUTOR_H

#include "session/ProcessExecutor.h"
#include "session/UserSession.h"

#include <string>
#include <vector>

class SessionCommandExecutor {
public:
    static ProcessResult execute(
        const UserSession& session,
        const SessionContext& context,
        const std::string& executable,
        const std::vector<std::string>& arguments
    );
};

#endif // SESSION_COMMAND_EXECUTOR_H
