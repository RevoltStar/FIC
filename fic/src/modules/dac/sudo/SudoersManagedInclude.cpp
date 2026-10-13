#include "modules/dac/sudo/SudoersManagedInclude.h"

#include <stdexcept>

namespace fic::sudoers {
namespace {
constexpr const char* begin = "#@FIC_INCLUDE_BEGIN";
constexpr const char* end = "#@FIC_INCLUDE_END";

bool safePath(const std::filesystem::path& path) {
    const auto text = path.string();
    return path.is_absolute() && path == path.lexically_normal() &&
        text.find_first_of(" \t\r\n\\\"#%") == std::string::npos &&
        text.find('\0') == std::string::npos;
}
}

std::string managedIncludeBlock(const std::filesystem::path& path) {
    if (!safePath(path))
        throw std::invalid_argument("Ambiguous managed sudoers include path");
    return std::string(begin) + "\n@include " + path.string() + "\n" + end + "\n";
}

ManagedIncludeInspection inspectManagedInclude(
    const std::string& content, const std::filesystem::path& path) {
    if (!safePath(path))
        return {ManagedIncludeState::Conflict, 0, "Ambiguous managed include path"};
    const auto marker = content.find("#@FIC_INCLUDE");
    if (marker == std::string::npos)
        return {ManagedIncludeState::Absent, content.size(), {}};
    if ((marker != 0 && content[marker - 1] != '\n') ||
        content.find("#@FIC_INCLUDE", marker + 1) !=
            content.find(end, marker + 1))
        return {ManagedIncludeState::Conflict, marker, "Malformed managed include markers"};
    const auto block = managedIncludeBlock(path);
    // An unterminated closing marker is accepted. Every other block byte is
    // canonical; CRLF, extra spaces, duplicate blocks and unknown markers are
    // refused rather than silently repaired. Only trailing LF is permitted.
    const auto required = block.substr(0, block.size() - 1);
    if (content.compare(marker, required.size(), required) != 0)
        return {ManagedIncludeState::Conflict, marker, "Managed include content drift"};
    const auto suffix = marker + required.size();
    if (content.find_first_not_of('\n', suffix) != std::string::npos)
        return {ManagedIncludeState::Conflict, marker, "Foreign content follows managed include"};
    return {ManagedIncludeState::Present, marker, {}};
}
} // namespace fic::sudoers
