// PCIInfoCollector.h
#ifndef PCIINFOCOLLECTOR_H
#define PCIINFOCOLLECTOR_H

#include "UDEVInfoCollector.h"

class PCIInfoCollector : public UDEVInfoCollector {
protected:
   std::vector<std::string> control_list_for_current_env() const override;
   std::map<std::string, std::string> extra_device_attributes() const override;
   std::string device_note_suffix() const override;

public:
   PCIInfoCollector();
};

#endif // PCIINFOCOLLECTOR_H
