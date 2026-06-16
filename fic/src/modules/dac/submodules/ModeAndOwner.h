#ifndef MODE_ADN_OWNER_H
#define MODE_ADN_OWNER_H

#include "modules/dac/DAC.h"
#include "utils/FileStats.h"
#include <map>

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
