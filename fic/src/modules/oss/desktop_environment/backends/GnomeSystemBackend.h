#ifndef FIC_GNOME_SYSTEM_BACKEND_H
#define FIC_GNOME_SYSTEM_BACKEND_H

#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "platform/PlatformExecutableResolver.h"

#include <fic/core/process/ProcessExecutor.h>

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

struct GnomeSystemBackendOptions {
    std::filesystem::path trustedRoot = "/etc";
    std::filesystem::path profilePath = "/etc/dconf/profile/user";
    std::filesystem::path databaseRoot = "/etc/dconf/db";
    std::string databaseName = "fic";
    std::string keyfileName = "99-fic.conf";
    std::string lockfileName = "99-fic";
    uid_t trustedOwner = 0;
    gid_t trustedGroup = 0;
};

struct GnomeSystemBackendDependencies {
    std::function<bool(fic::platform::ExecutableId,
                       std::filesystem::path&,
                       std::string&)> resolveExecutable;
    std::function<ProcessResult(const std::filesystem::path&,
                                const std::vector<std::string>&,
                                const ProcessOptions&)> execute;
};

class GnomeSystemBackend final : public DesktopSystemBackend {
public:
    explicit GnomeSystemBackend(
        const fic::platform::PlatformExecutableResolver& executables,
        GnomeSystemBackendOptions options = {});
    GnomeSystemBackend(GnomeSystemBackendDependencies dependencies,
                       GnomeSystemBackendOptions options);

    DesktopEnvironmentKind desktop() const override;
    std::string backendName() const override;
    bool ensureManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override;
    bool verifyManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override;

private:
    GnomeSystemBackendDependencies dependencies_;
    GnomeSystemBackendOptions options_;

    bool verifyWithExecutable(const DesktopManagedSettings& required,
                              const std::filesystem::path& gsettings,
                              std::string& error) const;
};

#endif
