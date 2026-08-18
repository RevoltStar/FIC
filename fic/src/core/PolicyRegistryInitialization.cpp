#include "core/PolicyRegistryInitialization.h"

#include <utility>

bool buildPolicyRegistry(
    PolicyList policies,
    PolicyRegistry& registry,
    std::string& error)
{
    try {
        error.clear();
        PolicyRegistry candidate;
        struct ModuleRegistration {
            const char* name;
            ModuleView view;
            int displayOrder;
        };

        const ModuleRegistration modules[] = {
            {"DAC",             ModuleView::Standard, 10},
            {"IDENTITY_ACCESS", ModuleView::Standard, 20},
            {"SYSCTL",          ModuleView::Standard, 30},
            {"OSS",             ModuleView::Standard, 40},
            {"NET",             ModuleView::Standard, 50},
            {"FIREWALL",        ModuleView::Standard, 60},
            {"DC",              ModuleView::Device,   70},
            {"AUDIT",           ModuleView::Audit,    80},
            {"GLOBAL",          ModuleView::Standard, 90}
        };

        for (const ModuleRegistration& module : modules) {
            if (!candidate.addModule(
                    module.name,
                    module.view,
                    module.displayOrder,
                    error)) {
                return false;
            }
        }
        for (auto& policy : policies) {
            if (!candidate.addPolicy(std::move(policy), error)) {
                return false;
            }
        }

        registry.swap(candidate);
        return true;
    } catch (const std::exception& exception) {
        error = "PolicyRegistry registration failed: " +
            std::string(exception.what());
        return false;
    } catch (...) {
        error = "PolicyRegistry registration failed: unknown exception";
        return false;
    }
}
