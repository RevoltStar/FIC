#ifndef POLICY_SERVICE_H
#define POLICY_SERVICE_H

#include <functional>
#include <string>
#include <vector>

#include <QString>
#include <nlohmann/json.hpp>

#include <fic/ipc/FicIpcClient.h>

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
    enum class ApplyStatus {
        Completed,
        ServiceError
    };

    struct ApplyResult {
        ApplyStatus status = ApplyStatus::ServiceError;
        nlohmann::json response;
        QString error;
    };

    using RequestResult = fic::ipc::Client::RequestResult;
    using RequestFunction = std::function<RequestResult(const nlohmann::json&)>;

    explicit PolicyService(RequestFunction request = {});

    bool loadModules(std::vector<ModuleDescriptor>& modules, QString& error) const;
    bool loadPolicies(const std::string& module,
                      std::vector<PolicyDescriptor>& policies,
                      QString& error) const;
    bool saveChanges(const std::string& module,
                     const std::vector<PolicyChange>& changes,
                     QString& error) const;
    ApplyResult saveAndApplyChanges(
        const std::string& module,
        const std::vector<PolicyChange>& changes) const;

private:
    RequestResult request(const nlohmann::json& payload) const;

    RequestFunction request_;
};

#endif // POLICY_SERVICE_H
