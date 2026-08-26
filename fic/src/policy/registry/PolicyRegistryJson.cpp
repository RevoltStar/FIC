#include "policy/registry/PolicyRegistryJson.h"

#include <nlohmann/json.hpp>

nlohmann::json moduleDescriptorsJson(const PolicyRegistry& registry)
{
    nlohmann::json modules = nlohmann::json::array();
    for (const auto& [name, module] : registry) {
        modules.push_back({
            {"name", name},
            {"view", moduleViewName(module.view)},
            {"display_order", module.displayOrder}
        });
    }
    return modules;
}
