#include "modules/dac/submodules/sudo/DAC_sudo_require_authentication.h"

DAC_sudo_require_authentication::DAC_sudo_require_authentication(
    const fic::platform::SudoPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Sudo(platformConfig, executables) {
    this->policyName = "sudo_require_authentication";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool DAC_sudo_require_authentication::apply() {
    return this->applyRequireAuthentication();
}
