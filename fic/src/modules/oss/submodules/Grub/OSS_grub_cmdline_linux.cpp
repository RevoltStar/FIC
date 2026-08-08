#include "modules/oss/submodules/Grub/OSS_grub_cmdline_linux.h"
#include "modules/oss/submodules/GrubConfiguration.h"

#include <utility>

namespace {

class GrubCmdlinePolicyTypeValue final
    : public MultiLineTextPolicyTypeValue {
public:
    GrubCmdlinePolicyTypeValue()
        : MultiLineTextPolicyTypeValue(",", " ", "") {
    }

    bool validate(const std::string& value) override {
        return value.find_first_of("\r\n") == std::string::npos &&
            value.find('\0') == std::string::npos;
    }

    std::string postProcessingValue(const std::string& value) override {
        if (value.empty()) {
            return json::array().dump();
        }
        return json::array({value}).dump();
    }
};

} // namespace

OSS_grub_cmdline_linux::OSS_grub_cmdline_linux(
    fic::platform::GrubPlatformConfig platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Grub(std::move(platformConfig), executables) {
    this->policyName = "grub_cmdline_linux";
    this->policyTypeValue =
        std::make_unique<GrubCmdlinePolicyTypeValue>();
}

bool OSS_grub_cmdline_linux::applyGrub(const std::string& expectedValue) {
    return this->applyGrubValue("GRUB_CMDLINE_LINUX", expectedValue);
}
