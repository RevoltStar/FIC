#pragma once
#include "service/VerifiedConfigSystemd.h"
#include "modules/net/ssh/SshRuntime.h"

namespace fic::service::ssh::detail {
// Closed Ubuntu lifecycle/proof only: no snapshot/copy/mount implementation.
// All mutations run inside the existing engine's published RO input phase.
class UbuntuSshSocketFlow {
    struct Snapshot {
        fic::service::detail::LaunchContract unit;
        std::map<std::string,std::uint64_t> listeners;
        std::string generator;
        bool operator==(const Snapshot& other) const {return unit==other.unit&&listeners==other.listeners&&generator==other.generator;}
    };
    std::chrono::steady_clock::time_point deadline_;
    Snapshot original_, activated_, promoted_;
    fic::service::detail::Fd connection_;
    bool promotedKnown_=false;
    static Snapshot observe(std::chrono::steady_clock::time_point);
    void command(const std::vector<std::string>&) const;
public:
    explicit UbuntuSshSocketFlow(std::chrono::steady_clock::time_point);
    static void prepareRuntimeDirectory();
    static void requireOffline(std::chrono::steady_clock::time_point);
    static std::vector<std::string> effectiveEndpoints(SshRuntime&);
    static std::string parseEndpoint(const std::string&);
    std::map<std::string,std::string> combined(const fic::service::detail::ServiceState&) const;
    const fic::service::detail::LaunchContract& socketContract() const {return original_.unit;}
    void activate(SshRuntime&,fic::service::detail::SystemdActivation&,
                  const fic::service::detail::ServiceState& originalService);
    void ready(const fic::service::detail::ServiceState&);
    void confirm(const fic::service::detail::ServiceState&);
};
}
