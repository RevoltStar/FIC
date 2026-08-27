#include "modules/oss/desktop_environment/backends/GSettingsValueParser.h"

#include <charconv>
#include <cctype>
#include <string_view>
#include <system_error>

namespace gnome_backend {
namespace {
std::string_view trim(std::string_view value) {
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
    }
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
    }
    return value;
}
} // namespace

std::optional<std::uint32_t> parseGSettingsUInt32(const std::string& value) {
    constexpr std::string_view typeName = "uint32";
    std::string_view input = trim(value);
    if (input.size() <= typeName.size() ||
        input.substr(0, typeName.size()) != typeName ||
        !std::isspace(static_cast<unsigned char>(input[typeName.size()]))) {
        return std::nullopt;
    }

    input.remove_prefix(typeName.size());
    input = trim(input);
    if (input.empty()) {
        return std::nullopt;
    }

    std::uint32_t parsed = 0;
    const char* begin = input.data();
    const char* end = begin + input.size();
    const auto result = std::from_chars(begin, end, parsed, 10);
    if (result.ec != std::errc() || result.ptr != end) {
        return std::nullopt;
    }
    return parsed;
}

} // namespace gnome_backend
