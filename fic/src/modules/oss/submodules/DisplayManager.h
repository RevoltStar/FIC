#ifndef DISPLAYMANAGER_H
#define DISPLAYMANAGER_H

#include "modules/oss/OSS.h"

#include <string>

class DisplayManager : public OSS
{
protected:
    std::string detectDisplayManager() const;
public:
    DisplayManager();
    virtual ~DisplayManager() = default;

    bool apply() override;
};

#endif // DISPLAYMANAGER_H
