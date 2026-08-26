#ifndef KDE_BACKEND_H
#define KDE_BACKEND_H

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

class KdeBackend final : public DesktopEnvironmentBackend {
public:
    using DesktopEnvironmentBackend::DesktopEnvironmentBackend;

    const char* name() const override { return "KDE Plasma"; }

    bool writeConfig(
        const std::string& file,
        const std::string& group,
        const std::string& key,
        const std::string& value,
        std::string& error
    ) const;

    bool writeConfig(
        const std::string& file,
        const std::vector<std::string>& groups,
        const std::string& key,
        const std::string& value,
        std::string& error
    ) const;

    bool readConfig(
        const std::string& file,
        const std::string& group,
        const std::string& key,
        std::string& value,
        std::string& error
    ) const;

    bool readConfig(
        const std::string& file,
        const std::vector<std::string>& groups,
        const std::string& key,
        std::string& value,
        std::string& error
    ) const;

    bool callDbusMethod(
        const std::string& service,
        const std::string& path,
        const std::string& interface,
        const std::string& method,
        std::string& error
    ) const;
};

#endif // KDE_BACKEND_H
