#ifndef FIC_CONTROLLED_DISPLAY_MANAGERS_VALUE_H
#define FIC_CONTROLLED_DISPLAY_MANAGERS_VALUE_H
#include <fic/policy/PolicyTypeValue.h>
#include <vector>
class ControlledDisplayManagersPolicyTypeValue final : public PolicyTypeValue {
public:
    ControlledDisplayManagersPolicyTypeValue();
    PolicyEditorSpec getEditorSpec() const override;
    bool validate(const std::string&) override;
    std::string postProcessingValue(const std::string&) override;
    std::string reverse_postProcessingValue(const std::string&) override;
    std::string getPolicyRestrictionInfo() override;
    static bool parse(const std::string&, std::vector<std::string>&);
};
#endif
