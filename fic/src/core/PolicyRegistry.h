#ifndef POLICY_REGISTRY_H
#define POLICY_REGISTRY_H

#include <cstddef>
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

using PolicyEntryMap = std::map<std::string, std::unique_ptr<Policy>>;
using SubmoduleMap = std::map<std::string, PolicyEntryMap>;

struct PolicyModule {
    ModuleView view = ModuleView::Standard;
    SubmoduleMap submodules;
};

class PolicyRegistry {
public:
    using ModuleMap = std::map<std::string, PolicyModule>;
    using iterator = ModuleMap::iterator;
    using const_iterator = ModuleMap::const_iterator;

    bool addModule(const std::string& name, ModuleView view, std::string& error)
    {
        if (name.empty()) {
            error = "module name must not be empty";
            return false;
        }

        const auto existing = modules_.find(name);
        if (existing != modules_.end()) {
            if (existing->second.view != view) {
                error = "conflicting view for module: " + name;
                return false;
            }
            return true;
        }

        modules_.emplace(name, PolicyModule{view, {}});
        return true;
    }

    bool addPolicy(std::unique_ptr<Policy> policy, std::string& error)
    {
        if (policy == nullptr) {
            error = "policy must not be null";
            return false;
        }
        if (policy->moduleName.empty() || policy->submoduleName.empty() ||
            policy->policyName.empty()) {
            error = "policy module, submodule and name must not be empty";
            return false;
        }

        const auto module = modules_.find(policy->moduleName);
        if (module == modules_.end()) {
            error = "policy references unknown module: " + policy->moduleName;
            return false;
        }

        PolicyEntryMap& policies = module->second.submodules[policy->submoduleName];
        if (policies.find(policy->policyName) != policies.end()) {
            error = "duplicate policy registration: " + policy->moduleName + "/" +
                policy->submoduleName + "/" + policy->policyName;
            return false;
        }
        policies.emplace(policy->policyName, std::move(policy));
        return true;
    }

    iterator begin() { return modules_.begin(); }
    const_iterator begin() const { return modules_.begin(); }
    iterator end() { return modules_.end(); }
    const_iterator end() const { return modules_.end(); }
    iterator find(const std::string& name) { return modules_.find(name); }
    const_iterator find(const std::string& name) const { return modules_.find(name); }
    PolicyModule& at(const std::string& name) { return modules_.at(name); }
    const PolicyModule& at(const std::string& name) const { return modules_.at(name); }
    void swap(PolicyRegistry& other) noexcept { modules_.swap(other.modules_); }
    void clear() { modules_.clear(); }
    bool empty() const { return modules_.empty(); }
    std::size_t size() const { return modules_.size(); }

private:
    ModuleMap modules_;
};

#endif // POLICY_REGISTRY_H
