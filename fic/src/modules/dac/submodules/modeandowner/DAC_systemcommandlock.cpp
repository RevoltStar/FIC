#include "modules/dac/submodules/modeandowner/DAC_systemcommandlock.h"
#include <sstream>
#include <vector>



DAC_systemcommandlock::DAC_systemcommandlock(
    const fic::platform::DacPlatformConfig& platformConfig) {
    for (const fic::platform::FileAccessRule& rule :
         platformConfig.protectedSystemCommands) {
        this->ModeAndOwner::expected.emplace(
            rule.path.string(),
            FileStats(rule.owner, rule.group, static_cast<mode_t>(rule.permissions))
        );
    }
    this->policyName = "systemcommandlock";
    this->policyTypeValue = std::make_unique<FileAccessRulesPolicyTypeValue>(
        platformConfig.protectedSystemCommands);
}

bool DAC_systemcommandlock::apply(){
    return this->ModeAndOwner::apply();
}
