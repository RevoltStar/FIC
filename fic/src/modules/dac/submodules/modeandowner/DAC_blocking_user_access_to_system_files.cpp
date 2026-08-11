#include "modules/dac/submodules/modeandowner/DAC_blocking_user_access_to_system_files.h"

DAC_blocking_user_access_to_system_files::DAC_blocking_user_access_to_system_files(
    const fic::platform::DacPlatformConfig& platformConfig)
    : ModeAndOwner(MissingFilePolicy::Ignore)
{
    for (const fic::platform::FileAccessRule& rule :
         platformConfig.protectedSystemFiles) {
        this->ModeAndOwner::expected.emplace(
            rule.path.string(),
            FileStats(rule.owner, rule.group, static_cast<mode_t>(rule.permissions))
        );
    }
    this->policyName = "blocking_user_access_to_system_files";
    this->policyTypeValue = std::make_unique<FileAccessRulesPolicyTypeValue>(
        platformConfig.protectedSystemFiles);
}

bool DAC_blocking_user_access_to_system_files::apply(){
        return this->ModeAndOwner::apply();
}
