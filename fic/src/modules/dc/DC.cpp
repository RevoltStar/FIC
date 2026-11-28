#include "modules/dc/DC.h"
#include <exception>
#include <fic/ipc/FicIpcClient.h>

DC::DC(const std::string& policy)
    :Policy() {
    this->moduleName = "DC";
    this->submoduleName = "DeviceControl";
    this->policyName = policy;
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"all", "new"});
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}


bool DC::reconcile(std::string& error) {
    ModuleConfigFileHandler configuration("DC");
    if (!configuration.loadConfig()) { error = "cannot load DC.conf"; return false; }
    nlohmann::json request{{"command", "device_regenerate_policy"}};
    for (const auto* name : {"block_usb_storage", "block_printers_scanners", "block_optical_drives"}) {
        const auto status = configuration.getPolicyStatus(name);
        const auto value = configuration.getPolicyValue(name);
        if (status != "ENABLE" && status != "DISABLE") {
            error = std::string("invalid DC status: ") + name; return false;
        }
        if (value != "new" && value != "all") {
            error = std::string("invalid DC value: ") + name; return false;
        }
        request[name] = status == "DISABLE" ? "disabled" : value;
    }
    const auto response = fic::ipc::Client(fic::ipc::Endpoint::DeviceDaemon).request(request);
    if (!response.value("ok", false)) {
        error = response.value("message", "device daemon reconciliation failed"); return false;
    }
    return true;
}

bool DC::apply() {
    // Detector severity settings are not udev configuration: their apply only
    // proves that the configured value is valid and readable. They never
    // regenerate udev rules and never require the device daemon to be ready.
    if (policyName == "permanent_device_missing_severity" ||
        policyName == "static_device_present_severity" ||
        policyName == "device_block_failed_severity")
        return moduleConf && moduleConf->loadConfig() && getValue().has_value();
    std::string error;
    const bool ok = reconcile(error);
    if (!ok) std::cerr << error << std::endl;
    return ok;
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

DC_permanent_device_missing_severity::DC_permanent_device_missing_severity()
    : DC("permanent_device_missing_severity")
{
    // The detector reaction is a severity token, chosen by the administrator.
    // STANDARD first keeps the generated default, the rest are selectable.
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"STANDARD", "NONE", "SOFT", "HARD", "ISOLATE"});
}

DC_static_device_present_severity::DC_static_device_present_severity()
    : DC("static_device_present_severity")
{
    // Factory default NONE: blocking static hardware is an administrative
    // decision, and the factory configuration must not contain the host.
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"NONE", "SOFT", "STANDARD", "HARD", "ISOLATE"});
}

DC_device_block_failed_severity::DC_device_block_failed_severity()
    : DC("device_block_failed_severity")
{
    // Factory default STANDARD: a forbidden dynamic device that could not be
    // restricted is a real violation of the configured policy.
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"STANDARD", "NONE", "SOFT", "HARD", "ISOLATE"});
}
