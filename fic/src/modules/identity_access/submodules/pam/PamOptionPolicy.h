#ifndef FIC_IDENTITY_ACCESS_PAM_OPTION_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_OPTION_POLICY_H

#include "modules/identity_access/submodules/pam/PamPolicy.h"
#include "modules/identity_access/submodules/pam/PamProviderInspector.h"
#include "platform/PlatformProfile.h"

#include <filesystem>
#include <string>
#include <vector>

class PamOptionPolicy : public PamPolicy {
public:
    ~PamOptionPolicy() override = default;

protected:
    PamOptionPolicy(
        fic::platform::PamPlatformConfig platformConfig,
        fic::identity::pam::PamCapability capability,
        fic::identity::pam::PamProviderKind provider,
        std::filesystem::path optionFile,
        std::string option,
        std::vector<std::string> services);

    bool applyPam(const std::string& expectedValue) override;

private:
    fic::platform::PamPlatformConfig platformConfig_;
    fic::identity::pam::PamCapability capability_;
    fic::identity::pam::PamProviderKind provider_;
    std::filesystem::path optionFile_;
    std::string option_;
    std::vector<std::string> services_;
};

#endif // FIC_IDENTITY_ACCESS_PAM_OPTION_POLICY_H
