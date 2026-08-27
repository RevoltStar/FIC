#ifndef GSETTINGS_VALUE_PARSER_H
#define GSETTINGS_VALUE_PARSER_H

#include <cstdint>
#include <optional>
#include <string>

namespace gnome_backend {

std::optional<std::uint32_t> parseGSettingsUInt32(const std::string& value);

} // namespace gnome_backend

#endif // GSETTINGS_VALUE_PARSER_H
