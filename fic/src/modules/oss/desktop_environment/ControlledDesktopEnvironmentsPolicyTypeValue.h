#ifndef FIC_CONTROLLED_DESKTOP_ENVIRONMENTS_POLICY_TYPE_VALUE_H
#define FIC_CONTROLLED_DESKTOP_ENVIRONMENTS_POLICY_TYPE_VALUE_H

#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"

#include <fic/policy/PolicyTypeValue.h>

class ControlledDesktopEnvironmentsPolicyTypeValue final
    : public PolicyTypeValue {
public:
    ControlledDesktopEnvironmentsPolicyTypeValue();

    PolicyEditorSpec getEditorSpec() const override;
    bool validate(const std::string& value) override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
    std::string getPolicyRestrictionInfo() override;

    static bool parse(const std::string& value,
                      DesktopEnvironmentSet& environments);

private:
    static std::vector<std::string> tokens(const std::string& value);
};

#endif // FIC_CONTROLLED_DESKTOP_ENVIRONMENTS_POLICY_TYPE_VALUE_H
