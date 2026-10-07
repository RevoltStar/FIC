#include "incident/IncidentAccessGateCore.h"

#include "incident/IncidentRecoveryConfigReader.h"

#include <algorithm>

namespace fic::incident {
namespace {
bool contains(const std::vector<std::string>& services, const std::string& service) {
    return std::find(services.begin(), services.end(), service) != services.end();
}
} // namespace

AccessGateDecision decideIncidentAccess(
    const PamAccessContext& context,
    const ::fic::platform::PamPlatformConfig::IncidentAccessGateConfig& config,
    const AccessGateDependencies& dependencies) {
    const auto mode = dependencies.resolveMode
        ? dependencies.resolveMode()
        : IncidentResponseModeResult{};
    if (mode.mode != IncidentResponseMode::Active)
        return {AccessGateDisposition::Neutral, mode.diagnostic};
    if (!contains(config.controlledServices, context.service)) {
        return {AccessGateDisposition::Neutral, "service is not controlled"};
    }
    ::fic::identity::pam::PamUserIdentity identity;
    std::string diagnostic;
    const bool identityProven = !context.user.empty() &&
        dependencies.resolveIdentity(context.user, identity, diagnostic);
    if (identityProven && identity.uid == 0 && context.remoteHost.empty() &&
        contains(config.trustedLocalRootServices, context.service)) {
        return {AccessGateDisposition::Pass, "local root recovery"};
    }
    if (identityProven && dependencies.recoveryEnabled(diagnostic)) {
        bool member = false;
        if (dependencies.groupMembership(identity, config.recoveryGroup,
                                         member, diagnostic) && member) {
            return {AccessGateDisposition::Pass, "fic group recovery"};
        }
    }
    const IncidentAccessReply reply = dependencies.requestDaemon();
    return {reply.allowed ? AccessGateDisposition::Pass : AccessGateDisposition::Deny,
            reply.diagnostic};
}

AccessGateDecision decideProductionIncidentAccess(const PamAccessContext& context) {
    return decideProductionIncidentAccess(
        context, IncidentResponseModeResolver::production());
}

AccessGateDecision decideProductionIncidentAccess(
    const PamAccessContext& context, IncidentResponseModeResult mode) {
    const auto profile = ::fic::platform::makeBuildPlatformProfile();
    const AccessGateDependencies dependencies{
        ::fic::identity::pam::resolvePamUserIdentity,
        IncidentRecoveryConfigReader::ficMemberExemptionEnabled,
        ::fic::identity::pam::isPamUserMemberOfGroup,
        IncidentAccessClient::query,
        [mode = std::move(mode)] { return mode; }
    };
    return decideIncidentAccess(context, profile.pam.incidentAccessGate,
                                dependencies);
}

bool isProductionControlledIncidentService(const std::string& service) {
    const auto profile = ::fic::platform::makeBuildPlatformProfile();
    return contains(profile.pam.incidentAccessGate.controlledServices, service);
}

} // namespace fic::incident
