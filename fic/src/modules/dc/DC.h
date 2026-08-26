#ifndef DC_H
#define DC_H

#include <fic/policy/Policy.h>
#include <fic/core/config/ConfigFileHandler.h>
#include <iostream>

// Общие настройки контроля устройств. Само дерево устройств и исполнение
// обслуживает fic-dick device daemon.
class DC : public Policy
{
protected:
    explicit DC(const std::string& policy);
    
public:
    bool apply () override;
};

class DC_block_usb_storage : public DC
{
public:
    DC_block_usb_storage();
};

class DC_block_printers_scanners : public DC
{
public:
    DC_block_printers_scanners();
};

class DC_block_optical_drives : public DC
{
public:
    DC_block_optical_drives();
};

#endif // D_H
