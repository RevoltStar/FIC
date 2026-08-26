#include <fic/core/process/VerifiedProcessExecutor.h>

#include <fic/core/integrity/CommandHashStore.h>

#include <string>

ProcessResult VerifiedProcessExecutor::execute(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    const ProcessOptions& options
) {
    ProcessResult result;
    std::string error;
    if (!CommandHashStore::verifyHash(executable, error)) {
        result.error = error;
        return result;
    }

    return ProcessExecutor::execute(executable, arguments, options);
}
