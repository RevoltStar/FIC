#ifndef DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
#define DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
#include <optional>
#include <string>

#include "modules/dac/mode_and_owner/ModeAndOwner.h"
#include "platform/PlatformProfile.h"

// Result of the TCB platform-baseline rollback. Counts are per collected
// TCB object (root directory, account entry directories, credential files).
struct TcbBaselineRollbackReport {
    int applied = 0;    // objects transitioned to the platform baseline
    int compliant = 0;  // objects already at the baseline (idempotent no-op)
    int failed = 0;     // objects that could not be transitioned safely
    std::string firstError;
};

// Platform-baseline rollback for the ALT TCB credential storage: transitions
// every valid object of the actually existing TCB tree to the baseline
// metadata declared by the profile. Missing accounts are never reconstructed;
// unknown or unsafe objects fail closed. The TCB topology must stay stable
// between collection and mutation (same proof as during apply).
TcbBaselineRollbackReport rollbackTcbTreeToBaseline(
    const fic::platform::TcbCredentialStorageConfig& config);

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
