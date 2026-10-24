#pragma once
#include "service/VerifiedConfigSystemd.h"
#include "modules/net/ssh/SshRuntime.h"
namespace fic::service::ssh::detail {
// Closed ALT simple-service observation. No copy/mount/activation implementation.
class AltSshServiceFlow {
    std::chrono::steady_clock::time_point deadline_;
    std::map<std::string,std::uint64_t> original_, promoted_;
    std::vector<std::string> expected_;
    std::string keygen_, candidate_;
    bool promotedKnown_=false;
public:
    AltSshServiceFlow(const fic::service::detail::ServiceState&,std::chrono::steady_clock::time_point);
    static bool initiallyReady(const fic::service::detail::ServiceState&);
    static std::map<std::string,std::string> combined(const fic::service::detail::ServiceState&,std::chrono::steady_clock::time_point);
    static void requireOffline(std::chrono::steady_clock::time_point);
    void published(SshRuntime&);
    bool readyCandidate(const fic::service::detail::ServiceState&,std::chrono::steady_clock::time_point);
    void ready(const fic::service::detail::ServiceState&);
    void confirm(const fic::service::detail::ServiceState&) const;
};
}
