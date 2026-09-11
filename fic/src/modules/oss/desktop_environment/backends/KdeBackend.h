#ifndef KDE_BACKEND_H
#define KDE_BACKEND_H

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/desktop_environment/KdeSessionTopology.h"
#include "modules/oss/desktop_environment/backends/KdeScreenLockerRuntimeContextResolver.h"

#include <functional>
#include <memory>
#include <optional>

struct KdeBackendDependencies {
    std::shared_ptr<KdeScreenLockerRuntimeContextResolver> resolver;
    std::function<std::string(const std::vector<std::string>&)> findExecutable;
    std::function<ProcessResult(
        const UserSession&, const SessionContext&, const std::string&,
        const std::vector<std::string>&,
        const std::vector<SessionEnvironmentOverride>&)> execute;
};

class KdeBackend final : public DesktopEnvironmentBackend {
public:
    KdeBackend(const UserSession& session, const SessionContext& context,
               const KdeSessionTopologyInfo& sameUidKdeTopology);
    KdeBackend(const UserSession& session, const SessionContext& context,
               const KdeSessionTopologyInfo& sameUidKdeTopology,
               KdeBackendDependencies dependencies);

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

    bool validateRuntimeContext(std::string& error) const;

private:
    bool ensureRuntimeContext(std::string& error) const;
    bool executeWithKConfigEnvironment(
        const std::string& executable,
        const std::vector<std::string>& arguments,
        std::string& output,
        std::string& error) const;

    UserSession session_;
    SessionContext context_;
    KdeSessionTopologyInfo sameUidKdeTopology_;
    KdeBackendDependencies dependencies_;
    mutable std::optional<KdeScreenLockerRuntimeContext> runtimeContext_;
};

#endif // KDE_BACKEND_H
