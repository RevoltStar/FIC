#ifndef FIC_AUTH_PASSWORD_MIN_CLASSES_H
#define FIC_AUTH_PASSWORD_MIN_CLASSES_H

#include "modules/auth/PamOptionPolicy.h"

class AUTH_password_min_classes : public PamOptionPolicy {
public:
    explicit AUTH_password_min_classes(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_AUTH_PASSWORD_MIN_CLASSES_H
