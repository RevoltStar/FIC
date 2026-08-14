#include "models/ModuleDescriptor.h"

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
            {{"name", "DAC"}, {"view", "standard"}},
            {{"name", "DC"}, {"view", "device"}},
            {{"name", "AUDIT"}, {"view", "audit"}}
        })}
    }, modules, error));
    assert(modules.size() == 3);
    assert(modules[0].view == ModuleView::Standard);
    assert(modules[1].view == ModuleView::Device);
    assert(modules[2].view == ModuleView::Audit);

    assert(!parseModuleDescriptors({
        {"ok", true},
        {"modules", nlohmann::json::array({
            {{"name", "FUTURE"}, {"view", "unknown"}}
        })}
    }, modules, error));
    assert(error == "unknown module view: unknown");
    assert(modules.empty());
    return 0;
}
