#ifndef POLICY_CONFIG_H
#define POLICY_CONFIG_H

#include <optional>
#include <string>

class PolicyConfig
{
public:
    static std::optional<std::string> getEnabledValue(
        const std::string& module,
        const std::string& policy);
};

#endif // POLICY_CONFIG_H
