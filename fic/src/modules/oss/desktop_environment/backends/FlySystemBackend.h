#ifndef FIC_FLY_SYSTEM_BACKEND_H
#define FIC_FLY_SYSTEM_BACKEND_H

#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"

#include <filesystem>

struct FlySystemBackendOptions {
    std::filesystem::path trustedRoot = "/";
    std::filesystem::path configPath =
        "/usr/share/fly-wm/theme.master/themerc";
    uid_t trustedOwner = 0;
    gid_t trustedGroup = 0;
};

class FlySystemBackend final : public DesktopSystemBackend {
public:
    explicit FlySystemBackend(FlySystemBackendOptions options = {});

    DesktopEnvironmentKind desktop() const override;
    std::string backendName() const override;
    bool ensureManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override;
    bool verifyManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override;

private:
    FlySystemBackendOptions options_;
};

#endif
