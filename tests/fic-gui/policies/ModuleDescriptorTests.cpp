#include "features/policies/models/ModuleDescriptor.h"

#include <nlohmann/json.hpp>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <vector>

int main()
{
    std::vector<ModuleDescriptor> modules;
    std::string error;
    assert(parseModuleDescriptors({
        {"ok", true},
        {"modules", nlohmann::json::array({
            {
                {"name", "DAC"},
                {"view", "standard"},
                {"display_order", 10}
            },
            {
                {"name", "DC"},
                {"view", "device"},
                {"display_order", 70}
            },
            {
                {"name", "AUDIT"},
                {"view", "audit"},
                {"display_order", 80}
            }
        })}
    }, modules, error));
    assert(modules.size() == 3);
    assert(modules[0].view == ModuleView::Standard);
    assert(modules[1].view == ModuleView::Device);
    assert(modules[2].view == ModuleView::Audit);
    assert(modules[0].displayOrder == 10);
    assert(modules[1].displayOrder == 70);
    assert(modules[2].displayOrder == 80);
    assert(!parseModuleDescriptors({
        {"ok", true},
        {"modules", nlohmann::json::array({
            {
                {"name", "FUTURE"},
                {"view", "unknown"},
                {"display_order", 100}
            }
        })}
    }, modules, error));
    assert(error == "unknown module view: unknown");
    assert(modules.empty());
    return 0;
}
