#include "PCIInfoCollector.h"

namespace {
std::string pci_disambiguator_name(const PCIInfoCollector& collector)
{
    if (!collector.get_env_value("PCI_SLOT_NAME").empty()) {
        return "PCI_SLOT_NAME";
    }
    if (!collector.get_env_value("DEVPATH").empty()) {
        return "DEVPATH";
    }
    return "";
}
}

PCIInfoCollector::PCIInfoCollector()
    : UDEVInfoCollector(std::vector<std::string>{}) {
    set_control_list(control_list_for_current_env());
}

std::vector<std::string> PCIInfoCollector::control_list_for_current_env() const
{
    std::vector<std::string> controlList{"PCI_CLASS", "PCI_ID", "PCI_SUBSYS_ID"};

    const std::string disambiguator = pci_disambiguator_name(*this);
    if (!disambiguator.empty()) {
        controlList.push_back(disambiguator);
    }

    return controlList;
}

std::map<std::string, std::string> PCIInfoCollector::extra_device_attributes() const
{
    const std::string disambiguator = pci_disambiguator_name(*this);
    if (disambiguator.empty()) {
        return {};
    }

    return {
        {"FIC_IDENTITY_STRENGTH", "weak"},
        {"FIC_IDENTITY_DISAMBIGUATOR", disambiguator}
    };
}

std::string PCIInfoCollector::device_note_suffix() const
{
    const std::string disambiguator = pci_disambiguator_name(*this);
    if (disambiguator.empty()) {
        return "";
    }

    return "; weak PCI identity disambiguated by " + disambiguator;
}
