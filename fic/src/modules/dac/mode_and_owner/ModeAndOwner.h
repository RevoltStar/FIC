#ifndef MODE_ADN_OWNER_H
#define MODE_ADN_OWNER_H

#include "modules/dac/DAC.h"
#include "platform/PlatformProfile.h"
#include <fic/core/fs/FileStats.h>
#include <map>
#include <optional>
#include <vector>

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
    std::vector<fic::platform::DacPlatformConfig::ProviderTarget>
        providerManagedFinalSymlinkTargets;
    fic::platform::DacPlatformConfig::ObjectType objectType =
        fic::platform::DacPlatformConfig::ObjectType::RegularFile;
    bool required = false;
    ModeEnforcement modeEnforcement = ModeEnforcement::Exact;
    bool validateOnly = false;
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
    void addExpectedRule(
        const std::filesystem::path& path,
        const fic::platform::DacPlatformConfig::PathContract& contract);
    void applyOpenedRule(const std::string& diagnosticPath,
                         const FileStats& expectedStats,
                         FileStats currentStats,
                         bool validateOnly,
                         ApplyCounters& counters,
                         mode_t requiredPermissions = 0);
    virtual void applyAdditionalRules(ApplyCounters& counters);
    void applyTcbCredentialTree(
        const fic::platform::TcbCredentialStorageConfig& config,
        ApplyCounters& counters);

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
