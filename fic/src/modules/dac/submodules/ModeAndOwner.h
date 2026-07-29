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

//Класс для работы правами/владельцами файлов и каталогов
class ModeAndOwner : public DAC
{
protected:
    //Переменная с эталонными правами
    std::map<std::string, FileStats> expected;
public:
    ModeAndOwner();
    virtual ~ModeAndOwner() = default;
    bool apply () override;
};

#endif // MODE_ADN_OWNER_H
