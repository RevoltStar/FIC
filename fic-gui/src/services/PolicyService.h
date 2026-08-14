#ifndef POLICY_SERVICE_H
#define POLICY_SERVICE_H

#include <string>
#include <vector>

#include <QString>
#include <nlohmann/json_fwd.hpp>

#include "models/ModuleDescriptor.h"
#include "models/PolicyDescriptor.h"

struct PolicyChange {
    std::string policyName;
    std::string value;
    bool enabled = false;
    bool valueConfigurable = false;
};

class PolicyService
{
public:
    bool loadModules(std::vector<ModuleDescriptor>& modules, QString& error) const;
    bool loadPolicies(const std::string& module,
                      std::vector<PolicyDescriptor>& policies,
                      QString& error) const;
    bool applyChanges(const std::string& module,
                      const std::vector<PolicyChange>& changes,
                      nlohmann::json& applyResponse,
                      QString& error) const;
};

#endif // POLICY_SERVICE_H
