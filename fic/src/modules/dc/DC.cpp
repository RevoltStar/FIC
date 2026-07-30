#include "modules/dc/DC.h"
#include <exception>

DC::DC(const std::string& policy)
    :Policy() {
    this->moduleName = "DC";
    this->submoduleName = "DeviceControl";
    this->policyName = policy;
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>("true");
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}


bool DC::apply (){
    if (!this->moduleConf || !this->moduleConf->loadConfig()) {
        return false;
    }

    return this->getValue() != std::nullopt;
}

DC_block_usb_storage::DC_block_usb_storage()
    : DC("block_usb_storage")
{
}

DC_block_printers_scanners::DC_block_printers_scanners()
    : DC("block_printers_scanners")
{
}

DC_block_optical_drives::DC_block_optical_drives()
    : DC("block_optical_drives")
{
}
