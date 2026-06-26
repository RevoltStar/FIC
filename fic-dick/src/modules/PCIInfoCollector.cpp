 
#include "PCIInfoCollector.h"

PCIInfoCollector::PCIInfoCollector()
    : UDEVInfoCollector({"PCI_CLASS", "PCI_ID", "PCI_SUBSYS_ID"}) {}
