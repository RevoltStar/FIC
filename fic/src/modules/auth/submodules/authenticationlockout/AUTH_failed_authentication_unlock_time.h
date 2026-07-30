#ifndef FIC_AUTH_FAILED_AUTHENTICATION_UNLOCK_TIME_H
#define FIC_AUTH_FAILED_AUTHENTICATION_UNLOCK_TIME_H

#include "modules/auth/PamOptionPolicy.h"

class AUTH_failed_authentication_unlock_time : public PamOptionPolicy {
public:
    explicit AUTH_failed_authentication_unlock_time(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_AUTH_FAILED_AUTHENTICATION_UNLOCK_TIME_H
