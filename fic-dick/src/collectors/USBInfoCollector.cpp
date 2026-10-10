#include "USBInfoCollector.h"

#include <string>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {
bool startsWith(const std::string& value, const std::string& prefix)
{
    return value.rfind(prefix, 0) == 0;
}

std::string usbFunctionFromInterface(const std::string& interface)
{
    if (startsWith(interface, "7/")) {
        return "printer";
    }
    if (startsWith(interface, "6/")) {
        return "scanner";
    }
    if (startsWith(interface, "8/")) {
        return "storage";
    }
    if (startsWith(interface, "3/")) {
        return "hid";
    }
    if (startsWith(interface, "255/") || startsWith(interface, "ff/") || startsWith(interface, "FF/")) {
        return "vendor-specific";
    }
    return "";
}
}

USBInfoCollector::USBInfoCollector()
    : UDEVInfoCollector(std::vector<std::string>{}) {
    set_control_list(control_list_for_current_env());
}

std::vector<std::string> USBInfoCollector::control_list_for_current_env() const
{
    const std::string devtype = get_env_value("DEVTYPE");

    if (devtype == "usb_interface") {
        return {"DEVTYPE", "PRODUCT", "INTERFACE", "TYPE", "MODALIAS"};
    }

    if (devtype == "usb_device") {
        return {"DEVTYPE", "ID_VENDOR_ID", "ID_MODEL_ID", "ID_SERIAL",
                "PRODUCT", "TYPE", "ID_USB_INTERFACES"};
    }

    return {"DEVTYPE", "PRODUCT", "TYPE", "MODALIAS", "DEVPATH"};
}

std::map<std::string, std::string> USBInfoCollector::extra_device_attributes() const
{
    const std::string devtype = get_env_value("DEVTYPE");
    const std::string interface = get_env_value("INTERFACE");
    const std::string function = usbFunctionFromInterface(interface);

    std::map<std::string, std::string> attributes;
    if (!function.empty()) {
        attributes["FIC_USB_FUNCTION"] = function;
    }
    if (devtype == "usb_interface" || devtype == "usb_device") {
        // Physical parent fields do not participate in the legacy occurrence
        // hash. They prove category epoch membership independently of ports.
        const auto devpath = get_env_value("DEVPATH");
        auto current = (std::filesystem::path("/sys") / devpath.substr(devpath.empty() ? 0 : 1)).lexically_normal();
        if (devpath.rfind("/devices/", 0) == 0 && current.string().rfind("/sys/devices/", 0) == 0) {
            while (current.string().rfind("/sys/devices/", 0) == 0) {
                std::ifstream vendor(current / "idVendor"), model(current / "idProduct"), serial(current / "serial");
                std::string v, m, n;
                if (std::getline(vendor, v) && std::getline(model, m)) {
                    std::getline(serial, n);
                    attributes["FIC_PHYSICAL_VENDOR"] = v;
                    attributes["FIC_PHYSICAL_MODEL"] = m;
                    attributes["FIC_PHYSICAL_SERIAL"] = n;
                    break;
                }
                current = current.parent_path();
            }
        }
    }
    if (devtype == "usb_interface") {
        attributes["FIC_USB_IDENTITY_SCOPE"] = "interface";
    } else if (devtype == "usb_device") {
        attributes["FIC_USB_IDENTITY_SCOPE"] = "device";
    }
    return attributes;
}

std::string USBInfoCollector::device_note_suffix() const
{
    const std::string devtype = get_env_value("DEVTYPE");
    const std::string interface = get_env_value("INTERFACE");
    const std::string function = usbFunctionFromInterface(interface);

    if (devtype == "usb_interface" && !function.empty()) {
        return "; USB function=" + function;
    }
    return "";
}
