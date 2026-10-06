#pragma once

#include "incident/IncidentAccessClient.h"
#include "modules/identity_access/pam/PamEffectiveGroupMembership.h"
#include "platform/PlatformProfile.h"

#include <functional>
#include <string>

namespace fic::incident {

struct PamAccessContext {
    std::string user;
    std::string service;
    std::string remoteHost;
};

enum class AccessGateDisposition { Neutral, Pass, Deny };

struct AccessGateDecision {
    AccessGateDisposition disposition = AccessGateDisposition::Deny;
    std::string diagnostic;
};

struct AccessGateDependencies {
    std::function<bool(const std::string&,
                       ::fic::identity::pam::PamUserIdentity&,
                       std::string&)> resolveIdentity;
    std::function<bool(std::string&)> recoveryEnabled;
    std::function<bool(const ::fic::identity::pam::PamUserIdentity&,
                       const std::string&, bool&, std::string&)> groupMembership;
    std::function<IncidentAccessReply()> requestDaemon;
};

AccessGateDecision decideIncidentAccess(
    const PamAccessContext& context,
    const ::fic::platform::PamPlatformConfig::IncidentAccessGateConfig& config,
    const AccessGateDependencies& dependencies);

AccessGateDecision decideProductionIncidentAccess(const PamAccessContext& context);
bool isProductionControlledIncidentService(const std::string& service);

} // namespace fic::incident
