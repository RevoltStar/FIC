#ifndef FIC_KDE_SYSTEM_BACKEND_H
#define FIC_KDE_SYSTEM_BACKEND_H

#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "platform/PlatformExecutableResolver.h"

#include <fic/core/process/ProcessExecutor.h>

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

struct KdeSystemBackendOptions {
    std::filesystem::path trustedRoot = "/etc";
    std::filesystem::path configPath = "/etc/xdg/kscreenlockerrc";
    std::filesystem::path temporaryRoot = "/tmp";
    uid_t trustedOwner = 0;
    gid_t trustedGroup = 0;
};

struct KdeSystemBackendDependencies {
    std::function<bool(fic::platform::ExecutableId,
                       std::filesystem::path&,
                       std::string&)> resolveExecutable;
    std::function<ProcessResult(const std::filesystem::path&,
                                const std::vector<std::string>&,
                                const ProcessOptions&)> execute;
};

class KdeSystemBackend final : public DesktopSystemBackend {
public:
    explicit KdeSystemBackend(
        const fic::platform::PlatformExecutableResolver& executables,
        KdeSystemBackendOptions options = {});
    KdeSystemBackend(KdeSystemBackendDependencies dependencies,
                     KdeSystemBackendOptions options);

    DesktopEnvironmentKind desktop() const override;
    std::string backendName() const override;
    bool ensureManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override;
    bool verifyManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override;

private:
    KdeSystemBackendDependencies dependencies_;
    KdeSystemBackendOptions options_;

    bool validateRequirements(const DesktopManagedSettings& required,
                              std::string& error) const;
    bool verifyWithExecutable(const DesktopManagedSettings& required,
                              const std::filesystem::path& kreadconfig,
                              std::string& error) const;
};

#endif
