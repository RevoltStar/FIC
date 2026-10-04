#include "modules/dac/sudo/policies/DAC_sudo_exempt_group_disable.h"

DAC_sudo_exempt_group_disable::DAC_sudo_exempt_group_disable(
    const fic::platform::SudoPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Sudo(platformConfig, executables) {
    // `exempt_group` is a flag-like Defaults key: the managed override is the
    // plain `Defaults !exempt_group` global entry in zzzz-fic, so the existing
    // SingleDefaultsSudoersParam + ensureManagedGlobalDefault() path applies
    // unchanged. FIC never edits a FOREIGN global Defaults entry for this.
    this->Sudo::sudoParameter = std::make_unique<SingleDefaultsSudoersParam>(
        "Defaults", "", "", "exempt_group", 0);
    this->policyName = "sudo_exempt_group_disable";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
    addRequiredDependency({"DAC", "SudoEdit", "sudo_disable_scoped_defaults"});
}

DAC_sudo_exempt_group_disable::~DAC_sudo_exempt_group_disable() {

}

bool DAC_sudo_exempt_group_disable::apply() {
    const auto configured = this->getValue();
    if (!configured || *configured != "DISABLE") {
        this->log("Эталон политики запрета exempt_group не равен DISABLE",
                  logLevel::ERROR);
        return false;
    }
    this->log("Запрещаем exempt_group", logLevel::INFO);
    return this->Sudo::apply();
}
