#ifndef MODULE_DESCRIPTOR_H
#define MODULE_DESCRIPTOR_H

#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

enum class ModuleView {
    Standard,
    Device,
    Audit
};

struct ModuleDescriptor {
    std::string name;
    ModuleView view = ModuleView::Standard;
    int displayOrder = 0;
};

bool parseModuleDescriptors(
    const nlohmann::json& response,
    std::vector<ModuleDescriptor>& modules,
    std::string& error);

#endif // MODULE_DESCRIPTOR_H
