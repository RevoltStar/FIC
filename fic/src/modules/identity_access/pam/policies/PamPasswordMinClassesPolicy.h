#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_MIN_CLASSES_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_MIN_CLASSES_POLICY_H

#include "modules/identity_access/pam/PamOptionPolicy.h"

class PamPasswordMinClassesPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswordMinClassesPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_MIN_CLASSES_POLICY_H
