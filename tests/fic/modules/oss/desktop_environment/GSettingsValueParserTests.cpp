#include "modules/oss/desktop_environment/backends/GSettingsValueParser.h"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void requireValue(const std::string& input, std::uint32_t expected) {
    const std::optional<std::uint32_t> actual =
        gnome_backend::parseGSettingsUInt32(input);
    require(actual.has_value(), "valid value was rejected: " + input);
    require(actual.value() == expected,
            "value was parsed incorrectly: " + input);
}

void requireRejected(const std::string& input) {
    require(!gnome_backend::parseGSettingsUInt32(input).has_value(),
            "malformed value was accepted: " + input);
}
} // namespace

int main() {
    requireValue("uint32 600", 600U);
    requireValue("uint32 0", 0U);
    requireValue(" uint32 600\n", 600U);
    requireValue("uint32 4294967295", UINT32_MAX);

    for (const std::string& malformed : std::vector<std::string>{
             "",
             "uint32",
             "uint32 abc",
             "uint32 600 garbage",
             "uint32600",
             "foo32 600",
             "32foo",
             "-1",
             "uint32 -1",
             "uint32 4294967296",
             "600",
             "0"}) {
        requireRejected(malformed);
    }
    return 0;
}
