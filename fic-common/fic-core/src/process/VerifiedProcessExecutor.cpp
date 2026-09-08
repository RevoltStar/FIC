#include <fic/core/process/VerifiedProcessExecutor.h>

#include "../integrity/CommandHashStoreInternal.h"

#include <string>

ProcessResult VerifiedProcessExecutor::execute(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    const ProcessOptions& options
) {
    ProcessResult result;
    std::string error;
    command_hash_store_detail::UniqueFd descriptor;
    if (!command_hash_store_detail::openVerifiedExecutable(
            executable, descriptor, error)) {
        result.error = error;
        return result;
    }

    return ProcessExecutor::executeImpl(
        executable, arguments, options, descriptor.get());
}
