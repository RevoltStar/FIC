#ifndef MODE_ADN_OWNER_H
#define MODE_ADN_OWNER_H

#include "modules/dac/DAC.h"
#include "platform/PlatformProfile.h"
#include <fic/core/fs/FileStats.h>
#include <map>
#include <optional>
#include <vector>

class FileAccessRulesPolicyTypeValue : public FixedPolicyTypeValue
{
public:
    explicit FileAccessRulesPolicyTypeValue(
        std::vector<fic::platform::FileAccessRule> rules,
        std::optional<fic::platform::TcbCredentialStorageConfig>
            tcbCredentialStorage = std::nullopt);

    std::string getPolicyRestrictionInfo() override;

private:
    std::vector<fic::platform::FileAccessRule> rules_;
    std::optional<fic::platform::TcbCredentialStorageConfig>
        tcbCredentialStorage_;
};

enum class MissingFilePolicy {
    Ignore,
    Fail
};

enum class ModeEnforcement {
    Exact,
    MaximumAllowed
};

struct ModeAndOwnerExpectation {
    FileStats stats;
    std::vector<std::filesystem::path> allowedFinalSymlinkTargets;
    std::vector<fic::platform::ProviderManagedFileTarget>
        providerManagedFinalSymlinkTargets;
};

//Класс для работы правами/владельцами файлов и каталогов
class ModeAndOwner : public DAC
{
protected:
    struct ApplyCounters {
        int total = 0;
        int success = 0;
        int failed = 0;
        int fixed = 0;
    };

    //Переменная с эталонными правами
    std::map<std::string, ModeAndOwnerExpectation> expected;
    MissingFilePolicy missingFilePolicy_;
    PolicyPathResolution pathResolution_;
    ModeEnforcement modeEnforcement_;
    // counters.fixed of the most recent apply(); -1 before the first apply.
    int lastApplyFixedCount_ = -1;
    void addExpectedRule(const fic::platform::FileAccessRule& rule);
    // Convenience overload for policies that do not use the platform
    // baseline model (e.g. custom_mode_and_owner): enforced == baseline.
    void addExpectedRule(
        const std::filesystem::path& path,
        const std::string& owner,
        const std::string& group,
        mode_t permissions);
    void applyOpenedRule(const std::string& diagnosticPath,
                         const FileStats& expectedStats,
                         FileStats currentStats,
                         bool validateOnly,
                         ApplyCounters& counters,
                         mode_t requiredPermissions = 0);
    virtual void applyAdditionalRules(ApplyCounters& counters);

    // Crash-safe journal provenance wrapper for platform-baseline rollback
    // (see docs/rollback.md, "Platform-baseline rollback"). Records a
    // Prepared DAC undo before the enforced-state mutation, commits it after
    // a state-changing successful apply, discards it when apply changed no
    // system state, and keeps the record active on apply failure so that a
    // later disable can still resolve provenance. This is persistent
    // disable-time provenance, NOT apply-time transactional compensation.
    bool applyWithBaselineJournalProvenance();
public:
    explicit ModeAndOwner(
        MissingFilePolicy missingFilePolicy,
        PolicyPathResolution pathResolution = PolicyPathResolution::Standard,
        ModeEnforcement modeEnforcement = ModeEnforcement::Exact);
    virtual ~ModeAndOwner() = default;
    bool apply () override;
    // True if the most recent apply() modified system state
    // (fixed at least one managed object).
    bool lastApplyChangedSystemState() const {
        return lastApplyFixedCount_ > 0;
    }
};

#endif // MODE_ADN_OWNER_H
