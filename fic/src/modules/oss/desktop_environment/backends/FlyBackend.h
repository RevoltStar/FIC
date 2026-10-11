#ifndef FLY_BACKEND_H
#define FLY_BACKEND_H

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

class FlyBackend final : public DesktopEnvironmentBackend {
public:
    FlyBackend(const UserSession& session, const SessionContext& context);

    const char* name() const override { return "FLY"; }

};

#endif // FLY_BACKEND_H
