#ifndef XFCE_BACKEND_H
#define XFCE_BACKEND_H

#include "modules/oss/submodules/DesktopEnvironment/backends/DesktopEnvironmentBackend.h"

class XfceBackend final : public DesktopEnvironmentBackend {
public:
    using DesktopEnvironmentBackend::DesktopEnvironmentBackend;

    const char* name() const override { return "XFCE"; }

    bool setProperty(
        const std::string& channel,
        const std::string& property,
        const std::string& type,
        const std::string& value,
        std::string& error
    ) const;

    bool getProperty(
        const std::string& channel,
        const std::string& property,
        std::string& value,
        std::string& error
    ) const;
};

#endif // XFCE_BACKEND_H
