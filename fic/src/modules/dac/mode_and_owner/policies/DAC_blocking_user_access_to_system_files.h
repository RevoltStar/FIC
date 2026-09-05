#ifndef DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
#define DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
#include <optional>

#include "modules/dac/mode_and_owner/ModeAndOwner.h"
#include "platform/PlatformProfile.h"

class DAC_blocking_user_access_to_system_files : public ModeAndOwner
{
protected:
     void applyAdditionalRules(ApplyCounters& counters) override;

public:
     explicit DAC_blocking_user_access_to_system_files(
         const fic::platform::DacPlatformConfig& platformConfig);
     bool apply () override;

private:
     std::optional<fic::platform::TcbCredentialStorageConfig>
         tcbCredentialStorage_;
};

#endif // DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
