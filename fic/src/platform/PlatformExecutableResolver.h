#ifndef FIC_PLATFORM_EXECUTABLE_RESOLVER_H
#define FIC_PLATFORM_EXECUTABLE_RESOLVER_H

#include "platform/PlatformProfile.h"

#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace fic::platform {

const char* executableIdName(ExecutableId id);
std::vector<ExecutableId> allExecutableIds();

const PlatformExecutableSpec* findExecutableSpec(
    const PlatformExecutables& executables,
    ExecutableId id);

struct PlatformExecutableResolverOptions {
    bool enforceTrustedOwnership = true;
};

class PlatformExecutableResolver {
public:
    explicit PlatformExecutableResolver(
        PlatformExecutables executables,
        PlatformExecutableResolverOptions options = {});

    bool resolve(ExecutableId id,
                 std::filesystem::path& executable,
                 std::string& error) const;

private:
    PlatformExecutables executables_;
    PlatformExecutableResolverOptions options_;
    mutable std::mutex cacheMutex_;
    mutable std::map<ExecutableId, std::filesystem::path> resolved_;

    bool validateCandidate(const std::filesystem::path& candidate,
                           std::string& error) const;
};

} // namespace fic::platform

#endif // FIC_PLATFORM_EXECUTABLE_RESOLVER_H
