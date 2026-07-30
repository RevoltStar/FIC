#ifndef FIC_AUTH_PASSWORD_MIN_LENGTH_H
#define FIC_AUTH_PASSWORD_MIN_LENGTH_H

#include "modules/auth/PamOptionPolicy.h"

class AUTH_password_min_length : public PamOptionPolicy {
public:
    explicit AUTH_password_min_length(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_AUTH_PASSWORD_MIN_LENGTH_H
