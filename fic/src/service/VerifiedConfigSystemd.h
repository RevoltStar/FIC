#pragma once
#include "service/VerifiedConfigMountSupport.h"
#include <chrono>

namespace fic::service::detail {
struct ServiceState {
    std::map<std::string, std::string> properties;
    std::string at(const std::string& key) const;
};
class SystemdActivation {
    std::string executable_, unit_, namespace_, originalInvocation_, job_;
    std::map<std::string, std::string> configuration_;
    std::chrono::steady_clock::time_point deadline_;
    ServiceState query(std::chrono::milliseconds timeout) const;
    void verifyConfiguration(const ServiceState&) const;
public:
    SystemdActivation(const std::string& unit, std::chrono::steady_clock::time_point deadline);
    std::chrono::milliseconds remaining() const;
    ServiceState preflight();
    void restart();
    ServiceState current() const;
    bool ready(const ServiceState&) const;
    void confirm(const ServiceState&) const;
    std::string cancelPendingJob();
};
} // namespace fic::service::detail
