#ifndef SYSCTLRUNTIME_H
#define SYSCTLRUNTIME_H

#include <filesystem>
#include <string>

struct SysctlRuntimeOptions {
    std::filesystem::path root = "/proc/sys";
};

struct SysctlRuntimeResult {
    bool ok = false;
    bool changed = false;
    std::string message;
};

// Reads and updates the live kernel sysctl view below /proc/sys.
// Keys are internal policy constants, not caller-provided filesystem paths.
class SysctlRuntime {
public:
    explicit SysctlRuntime(SysctlRuntimeOptions options = {});

    bool readValue(const std::string& key,
                   std::string& value,
                   std::string& error) const;
    SysctlRuntimeResult ensureValue(const std::string& key,
                                    const std::string& value) const;

private:
    SysctlRuntimeOptions options_;

    bool parameterPath(const std::string& key,
                       std::filesystem::path& path,
                       std::string& error) const;
};

#endif // SYSCTLRUNTIME_H
