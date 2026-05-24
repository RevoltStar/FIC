#ifndef DISPLAYMANAGER_H
#define DISPLAYMANAGER_H

#include "modules/oss/OSS.h"

#include <string>

class DisplayManager : public OSS
{
protected:
    std::string sddmConf = "/etc/sddm.conf";
    std::string lightdmConf = "/etc/lightdm/lightdm.conf";
    std::string gdmConf = "/etc/gdm/custom.conf";
    std::string gdm3Conf = "/etc/gdm3/custom.conf";

    bool fileExists(const std::string& path) const;
    std::string detectDisplayManager() const;
public:
    DisplayManager();
    virtual ~DisplayManager() = default;

    bool check_and_fix() override;
};

#endif // DISPLAYMANAGER_H
