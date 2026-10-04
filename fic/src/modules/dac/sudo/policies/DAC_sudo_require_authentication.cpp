#include "modules/dac/sudo/policies/DAC_sudo_require_authentication.h"

DAC_sudo_require_authentication::DAC_sudo_require_authentication(
    const fic::platform::SudoPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Sudo(platformConfig, executables) {
    this->policyName = "sudo_require_authentication";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
    // This policy owns NOPASSWD -> PASSWD and !authenticate -> authenticate.
    // exempt_group is owned by sudo_exempt_group_disable, so a contextual
    // `Defaults:alice exempt_group=...` must not be able to restore the bypass.
    addRequiredDependency({"DAC", "SudoEdit", "sudo_exempt_group_disable"});
}

bool DAC_sudo_require_authentication::apply() {
    return this->applyRequireAuthentication();
}
