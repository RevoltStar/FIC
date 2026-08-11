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

//Класс для работы правами/владельцами файлов и каталогов
class ModeAndOwner : public DAC
{
protected:
    //Переменная с эталонными правами
    std::map<std::string, FileStats> expected;
    MissingFilePolicy missingFilePolicy_;
public:
    explicit ModeAndOwner(MissingFilePolicy missingFilePolicy);
    virtual ~ModeAndOwner() = default;
    bool apply () override;
};

#endif // MODE_ADN_OWNER_H
