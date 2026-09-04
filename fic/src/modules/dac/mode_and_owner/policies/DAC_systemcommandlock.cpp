#include "modules/dac/mode_and_owner/policies/DAC_systemcommandlock.h"
#include <sstream>
#include <vector>



DAC_systemcommandlock::DAC_systemcommandlock(
    const fic::platform::DacPlatformConfig& platformConfig)
    : ModeAndOwner(
          MissingFilePolicy::Ignore,
          PolicyPathResolution::Standard,
          ModeEnforcement::MaximumAllowed) {
    for (const fic::platform::FileAccessRule& rule :
         platformConfig.protectedSystemCommands) {
        this->ModeAndOwner::addExpectedRule(
            rule.path,
            rule.owner,
            rule.group,
            static_cast<mode_t>(rule.permissions),
            rule.allowedFinalSymlinkTargets);
    }
    this->policyName = "systemcommandlock";
    this->policyTypeValue = std::make_unique<FileAccessRulesPolicyTypeValue>(
        platformConfig.protectedSystemCommands);
}

bool DAC_systemcommandlock::apply(){
    return this->ModeAndOwner::apply();
}
