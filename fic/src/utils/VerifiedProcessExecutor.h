#ifndef VERIFIED_PROCESS_EXECUTOR_H
#define VERIFIED_PROCESS_EXECUTOR_H

#include "utils/ProcessExecutor.h"

#include <string>
#include <vector>

class VerifiedProcessExecutor {
public:
    static ProcessResult execute(
        const std::string& executable,
        const std::vector<std::string>& arguments = {},
        const ProcessOptions& options = {}
    );
};

#endif // VERIFIED_PROCESS_EXECUTOR_H
