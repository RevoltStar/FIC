#ifndef GNOME_BACKEND_H
#define GNOME_BACKEND_H

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

class GnomeBackend final : public DesktopEnvironmentBackend {
public:
    using DesktopEnvironmentBackend::DesktopEnvironmentBackend;

    const char* name() const override { return "GNOME"; }

    bool setSetting(
        const std::string& schema,
        const std::string& key,
        const std::string& value,
        std::string& error
    ) const;

    bool getSetting(
        const std::string& schema,
        const std::string& key,
        std::string& value,
        std::string& error
    ) const;
};

#endif // GNOME_BACKEND_H
