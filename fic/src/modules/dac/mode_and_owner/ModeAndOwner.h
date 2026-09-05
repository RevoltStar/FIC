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
    void addExpectedRule(
        const std::filesystem::path& path,
        const std::string& owner,
        const std::string& group,
        mode_t permissions,
        std::vector<std::filesystem::path> allowedFinalSymlinkTargets = {},
        std::vector<fic::platform::ProviderManagedFileTarget>
            providerManagedFinalSymlinkTargets = {});
    void applyOpenedRule(const std::string& diagnosticPath,
                         const FileStats& expectedStats,
                         FileStats currentStats,
                         bool validateOnly,
                         ApplyCounters& counters,
                         mode_t requiredPermissions = 0);
    virtual void applyAdditionalRules(ApplyCounters& counters);
public:
    explicit ModeAndOwner(
        MissingFilePolicy missingFilePolicy,
        PolicyPathResolution pathResolution = PolicyPathResolution::Standard,
        ModeEnforcement modeEnforcement = ModeEnforcement::Exact);
    virtual ~ModeAndOwner() = default;
    bool apply () override;
};

#endif // MODE_ADN_OWNER_H
