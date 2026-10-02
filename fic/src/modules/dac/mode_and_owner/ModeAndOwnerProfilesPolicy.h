#ifndef FIC_MODE_AND_OWNER_PROFILES_POLICY_H
#define FIC_MODE_AND_OWNER_PROFILES_POLICY_H

#include "modules/dac/mode_and_owner/ModeAndOwner.h"

class ModeAndOwnerProfilesPolicyTypeValue final : public PolicyTypeValue {
public:
    using Selection = std::map<std::string,
        fic::platform::DacPlatformConfig::Profile>;

    explicit ModeAndOwnerProfilesPolicyTypeValue(
        const fic::platform::DacPlatformConfig& platform);
    PolicyEditorSpec getEditorSpec() const override;
    bool validate(const std::string& value) override;
    std::string postProcessingValue(const std::string& value) override;
    std::string reverse_postProcessingValue(const std::string& value) override;
    std::string getPolicyRestrictionInfo() override;
    bool parse(const std::string& value, Selection& selection,
               std::string& error) const;

private:
    const fic::platform::DacPlatformConfig& platform_;
};

class DAC_mode_and_owner_profiles final : public ModeAndOwner {
public:
    explicit DAC_mode_and_owner_profiles(
        const fic::platform::DacPlatformConfig& platform);
    bool apply() override;

private:
    void applyAdditionalRules(ApplyCounters& counters) override;
    const fic::platform::DacPlatformConfig& platform_;
    std::optional<fic::platform::TcbCredentialStorageConfig> selectedTcb_;
};

#endif
