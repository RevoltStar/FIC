#include "modules/identity_access/pam/PamTopologyManagerFactory.h"

#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"
#include "modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.h"
#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <grp.h>

#include <utility>

namespace fic::identity::pam {
namespace {

class StaticVerifyOnlyTopologyManager final : public PamTopologyManager {
public:
    StaticVerifyOnlyTopologyManager(
        fic::platform::PamPlatformConfig platformConfig,
        fic::platform::PamCapabilityConfig capability,
        std::vector<std::string> services)
        : platformConfig_(std::move(platformConfig)),
          capability_(std::move(capability)),
          services_(std::move(services)) {}

    bool inspect(PamTopologyStatus& status, std::string& error) override {
        PamConfiguration configuration(platformConfig_);
        PamCapabilityVerification verification;
        if (PamCapabilityVerifier::verify(
                configuration, platformConfig_, services_,
                capability_.capability, capability_.provider, verification,
                PamCapabilityVerificationMode::Structural)) {
            status = {PamTopologyState::Enabled, false, {}};
            error.clear();
            return true;
        }
        status = {PamTopologyState::Broken, false,
                  formatPamCapabilityVerification(verification)};
        error = status.detail;
        return false;
    }

    bool canEnable(std::string& error) const override {
        error = "static PAM topology is not mutable";
        return false;
    }
    bool enable(std::string& error) override { return canEnable(error); }
    bool disable(std::string& error) override { return canEnable(error); }

private:
    fic::platform::PamPlatformConfig platformConfig_;
    fic::platform::PamCapabilityConfig capability_;
    std::vector<std::string> services_;
};

} // namespace

std::unique_ptr<PamTopologyManager> createPamTopologyManager(
    const fic::platform::PamPlatformConfig& platformConfig,
    const fic::platform::PamCapabilityConfig& capability,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    std::string& error) {
    switch (capability.topology) {
    case fic::platform::PamTopologyStrategyKind::PamAuthUpdate:
        error.clear();
        return std::make_unique<PamAuthUpdateTopologyManager>(
            platformConfig, capability, services, executables);
    case fic::platform::PamTopologyStrategyKind::StaticVerifyOnly:
        error.clear();
        return std::make_unique<StaticVerifyOnlyTopologyManager>(
            platformConfig, capability, services);
    case fic::platform::PamTopologyStrategyKind::AltTcbManaged: {
        const auto& paths = fic::core::FicRuntimePaths::get();
        if (capability.capability ==
            fic::platform::PamCapability::AuthenticationLockout) {
            AltPamFaillockTopologyOptions options;
            options.lockFilePath =
                paths.runtimeDir / "pam-alt-faillock-topology.lock";
            options.lockDebugLogPath = paths.lockDebugLogFile;
            error.clear();
            return std::make_unique<AltPamFaillockTopologyManager>(
                platformConfig, std::move(options));
        }
        if (capability.capability ==
            fic::platform::PamCapability::PasswordHistory) {
            const struct group* shadowGroup = ::getgrnam("shadow");
            if (shadowGroup == nullptr) {
                error = "ALT pam_pwhistory requires the shadow group";
                return nullptr;
            }
            AltPamPasswordHistoryTopologyOptions options;
            options.lockFilePath =
                paths.runtimeDir / "pam-alt-pwhistory-topology.lock";
            options.lockDebugLogPath = paths.lockDebugLogFile;
            options.storageGroup = shadowGroup->gr_gid;
            error.clear();
            return std::make_unique<AltPamPasswordHistoryTopologyManager>(
                platformConfig, std::move(options));
        }
        error = "ALT managed PAM topology does not support this capability";
        return nullptr;
    }
    }
    error = "unsupported PAM topology activation strategy";
    return nullptr;
}

} // namespace fic::identity::pam
