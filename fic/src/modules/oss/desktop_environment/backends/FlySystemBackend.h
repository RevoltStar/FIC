#ifndef FIC_FLY_SYSTEM_BACKEND_H
#define FIC_FLY_SYSTEM_BACKEND_H

#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "rollback/MutationJournal.h"

#include <filesystem>

struct FlySystemBackendOptions {
    std::filesystem::path trustedRoot = "/";
    std::filesystem::path configPath =
        "/usr/share/fly-wm/theme.master/themerc";
    uid_t trustedOwner = 0;
    gid_t trustedGroup = 0;
    std::filesystem::path lockPath; // Production: FicRuntimePaths::runtimeDir.
};

class FlySystemBackend final : public DesktopSystemBackend {
public:
    explicit FlySystemBackend(FlySystemBackendOptions options = {});

    DesktopEnvironmentKind desktop() const override;
    std::string backendName() const override;
    bool verifiedEnforcementAvailable(std::string& error) const override {
        error = "FLY effective runtime verification is unavailable; persistent inverse is available for release";
        return false;
    }
    bool ensureManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override;
    bool verifyManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override;

    // Staged API for the scope coordinator. preflight never writes the
    // protected file; every physical mutation has durable scalar provenance.
    bool preflightJournaled(const DesktopGlobalConfigRequirements& required,
                            fic::rollback::MutationJournal& journal,
                            std::string& error);
    bool reconcileJournaled(const DesktopGlobalConfigRequirements& required,
                            fic::rollback::MutationJournal& journal,
                            std::string& error);
    // Remove one policy reference; restore a scalar only after its last owner.
    bool releaseOwnerJournaled(const PolicyRef& owner,
                               fic::rollback::MutationJournal& journal,
                               std::string& error, bool preview = false);
    bool releaseJournaled(const fic::rollback::MutationRecord& record,
                          fic::rollback::MutationJournal& journal,
                          std::string& error);

private:
    FlySystemBackendOptions options_;
};

#endif
