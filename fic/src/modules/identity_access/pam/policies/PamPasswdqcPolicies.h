#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWDQC_POLICIES_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWDQC_POLICIES_H

#include "modules/identity_access/pam/PamOptionPolicy.h"

class PamPasswdqcStrengthThresholdsPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswdqcStrengthThresholdsPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswdqcPassphraseWordsPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswdqcPassphraseWordsPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswdqcMatchLengthPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswdqcMatchLengthPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswdqcSimilarPasswordPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswdqcSimilarPasswordPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

class PamPasswdqcRetryCountPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswdqcRetryCountPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWDQC_POLICIES_H
