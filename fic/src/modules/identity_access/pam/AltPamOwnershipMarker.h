#pragma once

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

namespace fic::identity::pam {

inline std::string altPamMarkerSuffix(std::uint64_t id,
                                      const std::filesystem::path& target) {
    return " v1 id=" + std::to_string(id) + " target=" + target.string();
}

// Normalize only the recognized boundary comments for the existing strict
// block parser. Line numbers and the original snapshot used by CAS stay intact.
template<class Lines>
bool inspectAltPamMarkers(Lines& lines, const std::filesystem::path& target,
                          std::string_view module,
                          std::initializer_list<std::string_view> boundaries,
                          std::optional<std::uint64_t>& ownership,
                          std::string& error) {
    ownership.reset();
    bool legacy = false;
    const std::string begin = "# BEGIN FIC " + std::string(module);
    const std::string end = "# END FIC " + std::string(module);
    for (auto& line : lines) {
        const auto start = line.text.find_first_not_of(" \t");
        if (start == std::string::npos ||
            (line.text.compare(start, begin.size(), begin) != 0 &&
             line.text.compare(start, end.size(), end) != 0))
            continue;
        const auto version = line.text.find(" v1 id=");
        const std::string_view boundary(line.text.data(),
            version == std::string::npos ? line.text.size() : version);
        bool known = false;
        for (const auto candidate : boundaries)
            known |= boundary == candidate;
        if (start != 0 || !known) {
            error = "unknown ALT PAM ownership marker";
            return false;
        }
        if (version == std::string::npos) {
            legacy = true;
            continue;
        }
        const auto* first = line.text.data() + version + std::string_view(" v1 id=").size();
        std::uint64_t id = 0;
        const auto parsed = std::from_chars(first, line.text.data() + line.text.size(), id);
        if (parsed.ec != std::errc{} || id == 0 ||
            line.text.substr(version) != altPamMarkerSuffix(id, target) ||
            (ownership && *ownership != id)) {
            error = "invalid or inconsistent ALT PAM ownership marker";
            return false;
        }
        ownership = id;
        line.text.resize(version);
    }
    if (legacy && ownership) {
        error = "mixed legacy and journal-bound ALT PAM ownership markers";
        return false;
    }
    return true;
}

} // namespace fic::identity::pam
