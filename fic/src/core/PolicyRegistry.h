#ifndef POLICY_REGISTRY_H
#define POLICY_REGISTRY_H

#include <map>
#include <memory>
#include <string>
#include <string_view>

#include <fic/policy/Policy.h>

enum class ModuleView {
    Standard,
    Device,
    Audit
};

inline std::string_view moduleViewName(ModuleView view)
{
    switch (view) {
    case ModuleView::Standard:
        return "standard";
    case ModuleView::Device:
        return "device";
    case ModuleView::Audit:
        return "audit";
    }
    return {};
}

inline ModuleView moduleViewForName(std::string_view moduleName)
{
    if (moduleName == "DC") {
        return ModuleView::Device;
    }
    if (moduleName == "AUDIT") {
        return ModuleView::Audit;
    }
    return ModuleView::Standard;
}

using PolicyEntryMap = std::map<std::string, std::unique_ptr<Policy>>;
using SubmoduleMap = std::map<std::string, PolicyEntryMap>;

struct PolicyModule {
    ModuleView view = ModuleView::Standard;
    SubmoduleMap submodules;
};

using PolicyRegistry = std::map<std::string, PolicyModule>;

#endif // POLICY_REGISTRY_H
