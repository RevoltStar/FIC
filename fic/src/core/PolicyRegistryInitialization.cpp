#include "core/PolicyRegistryInitialization.h"

#include <utility>

bool buildPolicyRegistry(
    std::vector<std::unique_ptr<Policy>> policies,
    PolicyRegistry& registry,
    std::string& error)
{
    error.clear();
    PolicyRegistry candidate;
    const std::pair<const char*, ModuleView> modules[] = {
        {"DAC", ModuleView::Standard},
        {"IDENTITY_ACCESS", ModuleView::Standard},
        {"SYSCTL", ModuleView::Standard},
        {"OSS", ModuleView::Standard},
        {"NET", ModuleView::Standard},
        {"FIREWALL", ModuleView::Standard},
        {"DC", ModuleView::Device},
        {"AUDIT", ModuleView::Audit},
        {"GLOBAL", ModuleView::Standard}
    };

    for (const auto& [name, view] : modules) {
        if (!candidate.addModule(name, view, error)) {
            return false;
        }
    }
    for (auto& policy : policies) {
        if (!candidate.addPolicy(std::move(policy), error)) {
            return false;
        }
    }

    registry = std::move(candidate);
    return true;
}
