#ifndef FIC_AUTH_FAILED_AUTHENTICATION_ATTEMPTS_H
#define FIC_AUTH_FAILED_AUTHENTICATION_ATTEMPTS_H

#include "modules/auth/PamOptionPolicy.h"

class AUTH_failed_authentication_attempts : public PamOptionPolicy {
public:
    explicit AUTH_failed_authentication_attempts(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_AUTH_FAILED_AUTHENTICATION_ATTEMPTS_H
