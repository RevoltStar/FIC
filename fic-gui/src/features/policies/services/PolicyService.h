#ifndef POLICY_SERVICE_H
#define POLICY_SERVICE_H

#include <functional>
#include <string>
#include <vector>

#include <QString>
#include <nlohmann/json.hpp>

#include "features/policies/models/ModuleDescriptor.h"
#include "features/policies/models/PolicyDescriptor.h"

struct PolicyChange {
    std::string policyName;
    std::string value;
    bool enabled = false;
    bool valueConfigurable = false;
};

class PolicyService
{
public:
    using RequestFunction = std::function<nlohmann::json(const nlohmann::json&)>;

    explicit PolicyService(RequestFunction request = {});

    bool loadModules(std::vector<ModuleDescriptor>& modules, QString& error) const;
    bool loadPolicies(const std::string& module,
                      std::vector<PolicyDescriptor>& policies,
                      QString& error) const;
    bool saveChanges(const std::string& module,
                     const std::vector<PolicyChange>& changes,
                     QString& error) const;
    bool saveAndApplyChanges(const std::string& module,
                             const std::vector<PolicyChange>& changes,
                             nlohmann::json& applyResponse,
                             QString& error) const;

private:
    nlohmann::json request(const nlohmann::json& payload) const;

    RequestFunction request_;
};

#endif // POLICY_SERVICE_H
