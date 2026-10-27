#pragma once
#include "service/VerifiedConfigLaunchContract.h"
#include <chrono>

namespace fic::service::detail {
struct ServiceState {
    std::map<std::string, std::string> properties;
    std::string at(const std::string& key) const;
};
class SystemdActivation {
    ActivationProfile profile_;
    std::string executable_, unit_, namespace_, originalInvocation_, job_;
    std::map<std::string, std::string> configuration_;
    std::vector<ControlledPath> targets_;
    std::chrono::steady_clock::time_point deadline_;
    ServiceState query(std::chrono::milliseconds timeout) const;
    void verifyConfiguration(const ServiceState&) const;
public:
    SystemdActivation(const std::string& unit, std::chrono::steady_clock::time_point deadline,
                      const std::vector<ControlledPath>& targets = {},
                      ActivationProfile profile = ActivationProfile::ActiveNotifyService);
    std::chrono::milliseconds remaining() const;
    ServiceState preflight();
    // Closed configuration-validation path: stable active OR proven stopped,
    // never permission to restart/start a stopped service.
    ServiceState preflightSnapshotValidation();
    void restart();
    ServiceState current() const;
    bool ready(const ServiceState&) const;
    void confirm(const ServiceState&) const;
    std::string cancelPendingJob();
};
} // namespace fic::service::detail
