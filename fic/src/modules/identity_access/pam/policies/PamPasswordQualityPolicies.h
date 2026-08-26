#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_QUALITY_POLICIES_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_QUALITY_POLICIES_H

#include "modules/identity_access/pam/PamOptionPolicy.h"

class PamPasswordCheckUsernamePolicy final : public PamOptionPolicy {
public:
    explicit PamPasswordCheckUsernamePolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswordCheckGecosPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswordCheckGecosPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswordQualityEnforceForRootPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswordQualityEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswordMinChangedCharactersPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswordMinChangedCharactersPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswordMinimumCreditPolicy : public PamOptionPolicy {
protected:
    PamPasswordMinimumCreditPolicy(
        const fic::platform::PamPlatformConfig& platformConfig,
        std::string policyName,
        std::string option);
};

class PamPasswordMinLowercasePolicy final
    : public PamPasswordMinimumCreditPolicy {
public:
    explicit PamPasswordMinLowercasePolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswordMinUppercasePolicy final
    : public PamPasswordMinimumCreditPolicy {
public:
    explicit PamPasswordMinUppercasePolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswordMinDigitsPolicy final
    : public PamPasswordMinimumCreditPolicy {
public:
    explicit PamPasswordMinDigitsPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswordMinOtherPolicy final
    : public PamPasswordMinimumCreditPolicy {
public:
    explicit PamPasswordMinOtherPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_QUALITY_POLICIES_H
