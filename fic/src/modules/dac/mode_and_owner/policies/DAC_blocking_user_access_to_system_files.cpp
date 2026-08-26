#include "modules/dac/mode_and_owner/policies/DAC_blocking_user_access_to_system_files.h"

DAC_blocking_user_access_to_system_files::DAC_blocking_user_access_to_system_files(
    const fic::platform::DacPlatformConfig& platformConfig)
    : ModeAndOwner(MissingFilePolicy::Ignore)
{
    for (const fic::platform::FileAccessRule& rule :
         platformConfig.protectedSystemFiles) {
        this->ModeAndOwner::addExpectedRule(
            rule.path,
            rule.owner,
            rule.group,
            static_cast<mode_t>(rule.permissions),
            rule.allowedFinalSymlinkTargets);
    }
    this->policyName = "blocking_user_access_to_system_files";
    this->policyTypeValue = std::make_unique<FileAccessRulesPolicyTypeValue>(
        platformConfig.protectedSystemFiles);
}

bool DAC_blocking_user_access_to_system_files::apply(){
        return this->ModeAndOwner::apply();
}
