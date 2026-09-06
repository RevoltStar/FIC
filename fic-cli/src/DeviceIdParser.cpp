#include "DeviceIdParser.h"

#include <charconv>
#include <system_error>

namespace fic::cli {

bool parseDeviceId(const std::string& text, int& value, std::string& error)
{
    int parsed = 0;
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto result = std::from_chars(begin, end, parsed, 10);
    if (text.empty() || result.ec != std::errc{} || result.ptr != end ||
        parsed <= 0) {
        error = "Invalid device ID: " + text;
        return false;
    }

    value = parsed;
    error.clear();
    return true;
}

} // namespace fic::cli
