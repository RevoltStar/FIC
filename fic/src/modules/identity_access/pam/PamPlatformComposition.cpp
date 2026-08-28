#include "modules/identity_access/pam/PamPlatformComposition.h"

#include <algorithm>

namespace fic::identity::pam {

const fic::platform::PamCapabilityConfig* capabilityConfig(
    const fic::platform::PamPlatformConfig& platform,
    fic::platform::PamCapability capability)
{
    const auto found = std::find_if(
        platform.capabilities.begin(), platform.capabilities.end(),
        [capability](const auto& candidate) {
            return candidate.capability == capability;
        });
    return found == platform.capabilities.end() ? nullptr : &*found;
}

const fic::platform::PamScopeConfig* scopeConfig(
    const fic::platform::PamPlatformConfig& platform,
    fic::platform::PamScope scope)
{
    const auto found = std::find_if(
        platform.scopes.begin(), platform.scopes.end(),
        [scope](const auto& candidate) { return candidate.scope == scope; });
    return found == platform.scopes.end() ? nullptr : &*found;
}

bool resolveCapability(
    const fic::platform::PamPlatformConfig& platform,
    fic::platform::PamCapability capability,
    const fic::platform::PamCapabilityConfig*& capabilityResult,
    const std::vector<std::string>*& servicesResult,
    std::string& error)
{
    capabilityResult = capabilityConfig(platform, capability);
    if (capabilityResult == nullptr) {
        error = "PAM capability is not configured for this platform";
        return false;
    }
    const auto* scope = scopeConfig(platform, capabilityResult->scope);
    if (scope == nullptr || scope->services.empty()) {
        error = "PAM capability references an unavailable or empty scope";
        return false;
    }
    servicesResult = &scope->services;
    error.clear();
    return true;
}

} // namespace fic::identity::pam
