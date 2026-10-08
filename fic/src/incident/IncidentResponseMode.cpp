#include "incident/IncidentResponseMode.h"

#include <fic/core/config/ConfigAuthority.h>
#include <fic/core/runtime/FicPathDefaults.h>

#include <cctype>
#include <set>

namespace fic::incident {
namespace {

IncidentResponseModeResult unproven(std::string reason) {
    return {IncidentResponseMode::Active, false,
            "fallback ACTIVE: " + std::move(reason)};
}

} // namespace

const char* incidentResponseModeToken(IncidentResponseMode mode) {
    switch (mode) {
        case IncidentResponseMode::Off: return "OFF";
        case IncidentResponseMode::Passive: return "PASSIVE";
        case IncidentResponseMode::Active: return "ACTIVE";
    }
    return "ACTIVE";
}

IncidentResponseModeResult IncidentResponseModeResolver::production() {
    ::fic::core::ConfigAuthorityIdentity identity;
    std::string error;
    if (!::fic::core::productionConfigAuthority(identity, error))
        return unproven(error);
    return read(std::filesystem::path(::fic::core::path_defaults::CONFIG_DIR) /
                    "GLOBAL.conf",
                ::fic::core::configAuthorityExpectation(identity));
}

IncidentResponseModeResult IncidentResponseModeResolver::read(
    const std::filesystem::path& path,
    const ::fic::core::SecureStateFileExpectation& expectation) {
    std::string error;
    if (!::fic::core::proveSafeParentDirectory(
            path.parent_path().parent_path(), expectation, error))
        return unproven(error);
    const auto file = ::fic::core::readSecureFileBounded(
        path, expectation, ::fic::core::MAX_WORKING_CONFIG_BYTES);
    if (file.status != ::fic::core::SecureStateReadStatus::Proven)
        return unproven(file.detail.empty() ? "GLOBAL.conf is not proven" : file.detail);

    std::string status, value;
    std::set<std::string> seen;
    std::size_t cursor = 0;
    while (cursor < file.content.size()) {
        const auto end = file.content.find('\n', cursor);
        const std::string line = file.content.substr(
            cursor, end == std::string::npos ? std::string::npos : end - cursor);
        cursor = end == std::string::npos ? file.content.size() : end + 1;
        if (line.empty() || line.front() == '#') continue;
        if (line.find_first_of("\r\0", 0, 2) != std::string::npos)
            return unproven("malformed GLOBAL.conf control character");
        const auto equal = line.find('=');
        if (equal == std::string::npos || equal == 0 ||
            line.find('=', equal + 1) != std::string::npos)
            return unproven("malformed GLOBAL.conf assignment");
        const auto key = line.substr(0, equal);
        const auto item = line.substr(equal + 1);
        // The module config parser removes whitespace from keys. Never allow
        // it to interpret a second spelling of this security authority.
        std::string normalizedKey;
        for (const unsigned char ch : key)
            if (!std::isspace(ch)) normalizedKey.push_back(ch);
        if (normalizedKey != key &&
            (normalizedKey == "_schema_version" ||
             normalizedKey == "incident_response_mode.status" ||
             normalizedKey == "incident_response_mode.value"))
            return unproven("ambiguous GLOBAL.conf response mode key");
        if (!seen.insert(key).second)
            return unproven("duplicate GLOBAL.conf assignment");
        if (key == "_schema_version" && item != "1")
            return unproven("unsupported GLOBAL.conf schema version");
        if (key == "incident_response_mode.status") {
            if (!status.empty()) return unproven("duplicate response mode status");
            status = item;
        } else if (key == "incident_response_mode.value") {
            if (!value.empty()) return unproven("duplicate response mode value");
            value = item;
        }
    }
    if (!seen.count("_schema_version"))
        return unproven("GLOBAL.conf schema version is missing");
    if (status != "ENABLE" && status != "DISABLE")
        return unproven("missing or invalid response mode status");
    if (value != "PASSIVE" && value != "ACTIVE")
        return unproven("missing or invalid response mode value");
    const auto mode = status == "DISABLE" ? IncidentResponseMode::Off :
        value == "PASSIVE" ? IncidentResponseMode::Passive :
                              IncidentResponseMode::Active;
    return {mode, true, std::string("configured ") +
                            incidentResponseModeToken(mode), value};
}

} // namespace fic::incident
