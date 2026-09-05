#include "modules/dac/sudo/SudoSecurePathPolicyTypeValue.h"

#include <stdexcept>
#include <string>

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}
} // namespace

int main() {
    const std::string defaultValue =
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    SudoSecurePathPolicyTypeValue value(defaultValue);

    require(value.getDefaultValue() == defaultValue,
            "platform secure_path default was not preserved");
    require(value.validate("/opt/company.v2/bin:/usr/local/libexec.d/bin"),
            "dots inside ordinary path components were rejected");
    require(value.validate("/opt/release./bin:/opt/.../bin"),
            "ordinary dotted component names were rejected");
    require(value.validate("/usr/sbin, /usr/bin\r\n/bin"),
            "supported list separators were rejected");

    require(!value.validate("/opt/./bin"),
            "an exact dot component was accepted");
    require(!value.validate("/opt/../bin"),
            "an exact dot-dot component was accepted");
    require(!value.validate("relative/bin"),
            "a relative path was accepted");
    require(!value.validate(":"), "an empty secure_path was accepted");
    require(!value.validate("/usr/bin::/bin"),
            "an empty middle component was accepted");
    require(!value.validate(":/usr/bin") &&
                !value.validate("/usr/bin:"),
            "an empty edge component was accepted");
    require(!value.validate("/usr//bin") &&
                !value.validate("/usr/bin/"),
            "a non-normalized path was accepted");
    require(!value.validate("/usr/bin;/tmp"),
            "a dangerous separator was accepted");

    const std::string dotted =
        "/opt/company.v2/bin:/usr/local/libexec.d/bin";
    require(value.postProcessingValue(dotted) ==
                "[\"/opt/company.v2/bin\",\"/usr/local/libexec.d/bin\"]",
            "secure_path JSON serialization is incorrect");
    require(value.reverse_postProcessingValue(
                "[\"/opt/company.v2/bin\",\"/usr/local/libexec.d/bin\"]") ==
                dotted,
            "secure_path JSON deserialization is incorrect");
    require(value.postProcessingValue("/usr/bin::/bin").empty(),
            "invalid secure_path was serialized");
    return 0;
}
