#include "modules/dac/sudo/SudoersScopedDefaults.h"

#include <cctype>

namespace fic::sudoers {
namespace {

constexpr std::string_view kDefaults = "Defaults";

// True when the line is entirely a comment (starts with '#' that is not part
// of an include directive). Such a line can never be a Defaults entry.
bool isCommentLine(std::string_view trimmed) {
    return !trimmed.empty() && trimmed.front() == '#';
}

bool isScopeCharacter(char c) {
    return c == ':' || c == '@' || c == '>' || c == '!';
}

} // namespace

std::string scopedDefaultsScope(std::string_view logicalLine) {
    std::size_t begin = 0;
    while (begin < logicalLine.size() &&
           std::isspace(static_cast<unsigned char>(logicalLine[begin])) != 0) {
        ++begin;
    }
    const std::string_view trimmed = logicalLine.substr(begin);
    if (isCommentLine(trimmed)) {
        return {};
    }
    if (trimmed.size() <= kDefaults.size() ||
        trimmed.compare(0, kDefaults.size(), kDefaults) != 0) {
        return {};
    }
    // sudoers forbids whitespace between "Defaults" and the scope character,
    // so the character at exactly this offset is the scope.
    const char scope = trimmed[kDefaults.size()];
    if (!isScopeCharacter(scope)) {
        return {};
    }
    return std::string(1, scope);
}

std::string scopedDefaultsLocation(const ScopedDefaultsEntry& entry) {
    return entry.source.string() + ":" + std::to_string(entry.firstLine);
}

} // namespace fic::sudoers
