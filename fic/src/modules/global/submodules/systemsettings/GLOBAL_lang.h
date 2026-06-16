#ifndef GLOBAL_LANG_H
#define GLOBAL_LANG_H

#include "modules/global/submodules/SystemSettings.h"

class GLOBAL_lang : public SystemSettings
{
public:
    GLOBAL_lang();
    virtual ~GLOBAL_lang() = default;

    bool apply() override;
};

#endif // GLOBAL_LANG_H
