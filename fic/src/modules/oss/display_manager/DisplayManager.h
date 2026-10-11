#ifndef DISPLAYMANAGER_H
#define DISPLAYMANAGER_H
#include "modules/oss/OSS.h"
class DisplayManager : public OSS {
public:
    DisplayManager();
    bool apply() override;
};
#endif
