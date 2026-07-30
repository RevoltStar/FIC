#ifndef FIC_AUTH_PAM_OPTION_POLICY_H
#define FIC_AUTH_PAM_OPTION_POLICY_H

#include "modules/auth/AUTH.h"
#include "modules/auth/pam/PamProviderInspector.h"
#include "platform/PlatformProfile.h"

#include <filesystem>
#include <string>
#include <vector>

class PamOptionPolicy : public Auth {
public:
    bool apply() override;
    ~PamOptionPolicy() override = default;

protected:
    PamOptionPolicy(
        fic::platform::PamPlatformConfig platformConfig,
        fic::auth::PamCapability capability,
        fic::auth::PamProviderKind provider,
        std::filesystem::path optionFile,
        std::string option,
        std::vector<std::string> services);

private:
    fic::platform::PamPlatformConfig platformConfig_;
    fic::auth::PamCapability capability_;
    fic::auth::PamProviderKind provider_;
    std::filesystem::path optionFile_;
    std::string option_;
    std::vector<std::string> services_;
};

#endif // FIC_AUTH_PAM_OPTION_POLICY_H
