#include "models/ModuleDescriptor.h"

#include <set>

#include <nlohmann/json.hpp>

bool parseModuleDescriptors(
    const nlohmann::json& response,
    std::vector<ModuleDescriptor>& modules,
    std::string& error)
{
    modules.clear();
    error.clear();
    if (!response.value("ok", false)) {
        error = response.value("message", "failed to load modules");
        return false;
    }
    if (!response.contains("modules") || !response["modules"].is_array()) {
        error = "daemon response does not contain a modules array";
        return false;
    }

    std::set<std::string> names;
    for (const auto& item : response["modules"]) {
        if (!item.is_object() || !item.contains("name") ||
            !item["name"].is_string() || !item.contains("view") ||
            !item["view"].is_string()) {
            error = "invalid module descriptor";
            modules.clear();
            return false;
        }

        ModuleDescriptor descriptor;
        descriptor.name = item["name"].get<std::string>();
        const std::string view = item["view"].get<std::string>();
        if (descriptor.name.empty()) {
            error = "module descriptor has an empty name";
            modules.clear();
            return false;
        }
        if (view == "standard") {
            descriptor.view = ModuleView::Standard;
        } else if (view == "device") {
            descriptor.view = ModuleView::Device;
        } else if (view == "audit") {
            descriptor.view = ModuleView::Audit;
        } else {
            error = "unknown module view: " + view;
            modules.clear();
            return false;
        }
        if (!names.insert(descriptor.name).second) {
            error = "duplicate module descriptor: " + descriptor.name;
            modules.clear();
            return false;
        }
        modules.push_back(std::move(descriptor));
    }
    return true;
}
