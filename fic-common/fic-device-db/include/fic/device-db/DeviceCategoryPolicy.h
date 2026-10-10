#pragma once

#include <fic/device-db/DB.h>
#include <fnmatch.h>
#include <optional>
#include <stdexcept>

namespace fic::device_control {

using DeviceIdentityTerms = std::map<std::string, std::string>;
struct CategoryPredicate {
    std::string subsystem;
    DeviceIdentityTerms attributes;
};

inline const std::map<std::string, std::vector<CategoryPredicate>>& categoryPredicates()
{
    static const auto predicates = [] {
        std::map<std::string, std::vector<CategoryPredicate>> predicates{
            {"block_usb_storage", {
                {"block", {{"ID_BUS", "usb"}}},
                {"block", {{"DEVPATH", "*/usb*/*"}}},
                {"usb", {{"ID_USB_INTERFACES", "*:08*"}}},
                {"usb", {{"TYPE", "8/*"}}},
                {"usb", {{"INTERFACE", "8/*"}}}}},
            {"block_printers_scanners", {
                {"usb", {{"ID_USB_INTERFACES", "*:06*|*:07*"}}},
                {"usb", {{"TYPE", "6/*|7/*"}}},
                {"usb", {{"INTERFACE", "6/*|7/*"}}},
                {"usb", {{"MODALIAS", "*ic06*|*ic07*"}}}}},
            {"block_optical_drives", {
                {"block", {{"ID_CDROM", "1"}}},
                {"block", {{"ID_CDROM_CD", "1"}}},
                {"block", {{"ID_TYPE", "cd"}}}}}
        };
        // Preserve the existing category coverage on other managed subsystems,
        // requiring the same USB bus/type evidence (never a global USB ban).
        const auto usbPrinterPredicates = predicates.at("block_printers_scanners");
        for (const auto* subsystem : {"usbmisc", "pci", "block"}) {
            for (auto predicate : usbPrinterPredicates) {
                predicate.subsystem = subsystem;
                predicate.attributes["ID_BUS"] = "usb";
                predicates["block_printers_scanners"].push_back(std::move(predicate));
            }
            if (std::string(subsystem) != "block")
                predicates["block_usb_storage"].push_back({subsystem, {{"DEVTYPE", "disk"}, {"ID_BUS", "usb"}}});
        }
        return predicates;
    }();
    return predicates;
}

inline bool udevPatternMatches(const std::string& pattern, const std::string& value)
{
    std::size_t start = 0;
    do {
        const auto end = pattern.find('|', start);
        if (::fnmatch(pattern.substr(start, end - start).c_str(), value.c_str(), 0) == 0) return true;
        if (end == std::string::npos) return false;
        start = end + 1;
    } while (true);
}

// Physical identity excludes filesystem/partition UUIDs: cloning media is not
// proof that the physical device was present at the epoch. Missing serial/WWN
// leaves a device unknown, with category-scoped DENY in new mode.
inline std::optional<DeviceIdentityTerms> physicalIdentityTerms(
    const std::string& subsystem, const DeviceIdentityTerms& attributes)
{
    const auto value = [&](const std::string& key) {
        auto it = attributes.find(key);
        return it == attributes.end() ? std::string{} : it->second;
    };
    DeviceIdentityTerms terms;
    if (subsystem == "usb") {
        if (value("DEVTYPE") == "usb_device") {
            // usb_id can normalize serial strings. An ENV exemption must
            // describe exactly the same raw serial as the ATTRS parent rule.
            if (attributes.count("FIC_PHYSICAL_SERIAL") &&
                (value("FIC_PHYSICAL_SERIAL") != value("ID_SERIAL_SHORT") ||
                 value("FIC_PHYSICAL_VENDOR") != value("ID_VENDOR_ID") ||
                 value("FIC_PHYSICAL_MODEL") != value("ID_MODEL_ID"))) return std::nullopt;
            terms["idVendor"] = value("ID_VENDOR_ID");
            terms["idProduct"] = value("ID_MODEL_ID");
            terms["serial"] = value("ID_SERIAL_SHORT");
        } else if (value("DEVTYPE") == "usb_interface") {
            terms["idVendor"] = value("FIC_PHYSICAL_VENDOR");
            terms["idProduct"] = value("FIC_PHYSICAL_MODEL");
            terms["serial"] = value("FIC_PHYSICAL_SERIAL");
        } else return std::nullopt;
    } else if (subsystem == "block") {
        if (!value("ID_WWN").empty()) terms["ID_WWN"] = value("ID_WWN");
        else {
            for (const auto* key : {"ID_SERIAL_SHORT", "ID_VENDOR", "ID_MODEL"}) terms[key] = value(key);
        }
    } else return std::nullopt;
    for (const auto& [key, entry] : terms)
        if (entry.empty() || entry.find_first_of("*?[|\\\"\n\r\t$%") != std::string::npos ||
            entry.find('\0') != std::string::npos) return std::nullopt;
    for (const auto& [key, entry] : terms)
        for (const auto ch : entry) if (static_cast<unsigned char>(ch) < 0x20 || ch == 0x7f) return std::nullopt;
    return terms;
}

inline std::string categoryMode(const DeviceCategoryPolicyState& state, const std::string& category)
{
    if (category == "block_usb_storage") return state.block_usb_storage;
    if (category == "block_printers_scanners") return state.block_printers_scanners;
    if (category == "block_optical_drives") return state.block_optical_drives;
    throw std::invalid_argument("unknown device category: " + category);
}

inline bool categoryMatches(const std::string& category, const DeviceInfo& device,
                            DeviceIdentityTerms attributes)
{
    attributes["DEVPATH"] = device.devpath;
    for (const auto& predicate : categoryPredicates().at(category)) {
        if (predicate.subsystem != device.subsystem) continue;
        bool matches = true;
        for (const auto& [key, pattern] : predicate.attributes)
            matches = matches && udevPatternMatches(pattern, attributes[key]);
        if (matches) return true;
    }
    return false;
}

inline bool knownAtCategoryEpoch(const DeviceCategoryPolicyState& state,
                                const std::string& category, const DeviceInfo& device,
                                const DeviceIdentityTerms& attributes)
{
    const auto terms = physicalIdentityTerms(device.subsystem, attributes);
    if (!terms) return false;
    const auto known = state.known.find(category);
    if (known == state.known.end()) return false;
    for (const auto& identity : known->second)
        if (identity.subsystem == device.subsystem &&
            physicalIdentityTerms(identity.subsystem, identity.attributes) == terms) return true;
    return false;
}

struct DeviceCategoryDecision { std::string category; std::string mode; };
inline std::optional<DeviceCategoryDecision> categoryDenial(
    const DeviceCategoryPolicyState& state, const DeviceInfo& device,
    const DeviceIdentityTerms& attributes, bool hardOnly)
{
    // all has priority over every overlapping new category.
    for (const auto* mode : {"all", "new"}) {
        if (hardOnly && std::string(mode) != "all") continue;
        for (const auto& [category, predicates] : categoryPredicates())
            if (categoryMode(state, category) == mode && categoryMatches(category, device, attributes) &&
                (std::string(mode) == "all" || !knownAtCategoryEpoch(state, category, device, attributes)))
                return DeviceCategoryDecision{category, mode};
    }
    return std::nullopt;
}
}
