#ifndef SESSION_COMMAND_EXECUTOR_INTERNAL_H
#define SESSION_COMMAND_EXECUTOR_INTERNAL_H

#include <fic/core/process/ProcessExecutor.h>
#include "session/UserSession.h"

#include <string>
#include <sys/types.h>

namespace session_command_executor_detail {

ProcessOptions buildOptions(const UserSession& session,
                            const SessionContext& context,
                            const std::string& homeDirectory,
                            gid_t primaryGroup);

} // namespace session_command_executor_detail

#endif // SESSION_COMMAND_EXECUTOR_INTERNAL_H
