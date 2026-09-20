#ifndef FIC_IDENTITY_ACCESS_PAM_PLATFORM_COMPOSITION_H
#define FIC_IDENTITY_ACCESS_PAM_PLATFORM_COMPOSITION_H

#include "platform/PlatformProfile.h"

#include <string>
#include <vector>

namespace fic::identity::pam {

const fic::platform::PamCapabilityConfig* capabilityConfig(
    const fic::platform::PamPlatformConfig& platform,
    fic::platform::PamCapability capability);

const fic::platform::PamScopeConfig* scopeConfig(
    const fic::platform::PamPlatformConfig& platform,
    fic::platform::PamScope scope);

bool resolveCapability(
    const fic::platform::PamPlatformConfig& platform,
    fic::platform::PamCapability capability,
    const fic::platform::PamCapabilityConfig*& capabilityResult,
    const std::vector<std::string>*& servicesResult,
    std::string& error);

// Complete FIC-owned pam-auth-update identifier domain for a capability,
// including every declared faillock strategy.
std::vector<std::string> activationIdentifiers(
    const fic::platform::PamCapabilityConfig& capability);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PLATFORM_COMPOSITION_H
