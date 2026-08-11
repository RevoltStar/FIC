#ifndef MODE_ADN_OWNER_H
#define MODE_ADN_OWNER_H

#include "modules/dac/DAC.h"
#include "platform/PlatformProfile.h"
#include <fic/core/FileStats.h>
#include <map>
#include <vector>

class FileAccessRulesPolicyTypeValue : public FixedPolicyTypeValue
{
public:
    explicit FileAccessRulesPolicyTypeValue(
        std::vector<fic::platform::FileAccessRule> rules);

    std::string getPolicyRestrictionInfo() override;

private:
    std::vector<fic::platform::FileAccessRule> rules_;
};

enum class MissingFilePolicy {
    Ignore,
    Fail
};

struct ModeAndOwnerExpectation {
    FileStats stats;
    std::vector<std::filesystem::path> allowedFinalSymlinkTargets;
};

//Класс для работы правами/владельцами файлов и каталогов
class ModeAndOwner : public DAC
{
protected:
    //Переменная с эталонными правами
    std::map<std::string, ModeAndOwnerExpectation> expected;
    MissingFilePolicy missingFilePolicy_;
    void addExpectedRule(
        const std::filesystem::path& path,
        const std::string& owner,
        const std::string& group,
        mode_t permissions,
        std::vector<std::filesystem::path> allowedFinalSymlinkTargets = {});
public:
    explicit ModeAndOwner(MissingFilePolicy missingFilePolicy);
    virtual ~ModeAndOwner() = default;
    bool apply () override;
};

#endif // MODE_ADN_OWNER_H
