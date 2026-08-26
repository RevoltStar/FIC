 // USBInfoCollector.h
#ifndef USBINFOCOLLECTOR_H
#define USBINFOCOLLECTOR_H

#include <map>
#include <string>
#include <vector>
#include "UDEVInfoCollector.h"

class USBInfoCollector : public UDEVInfoCollector {
public:
    USBInfoCollector();

protected:
    std::vector<std::string> control_list_for_current_env() const override;
    std::map<std::string, std::string> extra_device_attributes() const override;
    std::string device_note_suffix() const override;
};

#endif // USBINFOCOLLECTOR_H
