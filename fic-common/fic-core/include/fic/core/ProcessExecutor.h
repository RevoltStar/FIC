#ifndef PROCESS_EXECUTOR_H
#define PROCESS_EXECUTOR_H

#include <chrono>
#include <optional>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>

struct ProcessResult {
    bool started = false;
    bool timedOut = false;
    int exitCode = -1;
    std::string standardOutput;
    std::string standardError;
    std::string error;

    bool success() const {
        return started && !timedOut && exitCode == 0;
    }
};

struct ProcessOptions {
    std::chrono::milliseconds timeout{5000};
    bool clearEnvironment = false;
    std::vector<std::pair<std::string, std::string>> environment;
    std::optional<uid_t> uid;
    std::optional<gid_t> gid;
    std::string user;
    std::string workingDirectory;
};

class ProcessExecutor {
public:
    static ProcessResult execute(
        const std::string& executable,
        const std::vector<std::string>& arguments = {},
        const ProcessOptions& options = {}
    );
};

#endif // PROCESS_EXECUTOR_H
