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
        this->ModeAndOwner::addExpectedRule(rule);
    }
    this->policyName = "systemcommandlock";
    this->policyTypeValue = std::make_unique<FileAccessRulesPolicyTypeValue>(
        platformConfig.protectedSystemCommands);
}

bool DAC_systemcommandlock::apply(){
    // ENABLE applies the enforced hardening state only; disable-time
    // rollback transitions to the platform profile baseline (never to the
    // pre-FIC state) and is driven by the recorded journal provenance.
    return this->ModeAndOwner::applyWithBaselineJournalProvenance();
}
