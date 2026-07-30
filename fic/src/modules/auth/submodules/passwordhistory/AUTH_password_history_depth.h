#ifndef FIC_AUTH_PASSWORD_HISTORY_DEPTH_H
#define FIC_AUTH_PASSWORD_HISTORY_DEPTH_H

#include "modules/auth/PamOptionPolicy.h"

class AUTH_password_history_depth : public PamOptionPolicy {
public:
    explicit AUTH_password_history_depth(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_AUTH_PASSWORD_HISTORY_DEPTH_H
