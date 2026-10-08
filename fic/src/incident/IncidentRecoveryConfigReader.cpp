#include "incident/IncidentRecoveryConfigReader.h"

#include <fic/core/config/ConfigAuthority.h>
#include <fic/core/runtime/FicPathDefaults.h>

namespace fic::incident {
namespace {
constexpr const char* Key = "lock_exempt_fic_members.status";

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r");
    return value.substr(first, last - first + 1U);
}
} // namespace

bool IncidentRecoveryConfigReader::ficMemberExemptionEnabled(std::string& diagnostic) {
    return ficMemberExemptionStatus(diagnostic).value_or(false);
}

std::optional<bool> IncidentRecoveryConfigReader::ficMemberExemptionStatus(
    std::string& diagnostic) {
    ::fic::core::ConfigAuthorityIdentity identity;
    if (!::fic::core::productionConfigAuthority(identity, diagnostic)) {
        return std::nullopt;
    }
    const auto expectation = ::fic::core::configAuthorityExpectation(identity);
    return readStatus(
        std::filesystem::path(::fic::core::path_defaults::CONFIG_DIR) / "GLOBAL.conf",
        expectation, diagnostic);
}

bool IncidentRecoveryConfigReader::read(
    const std::filesystem::path& path,
    const ::fic::core::SecureStateFileExpectation& expectation,
    std::string& diagnostic) {
    return readStatus(path, expectation, diagnostic).value_or(false);
}

std::optional<bool> IncidentRecoveryConfigReader::readStatus(
    const std::filesystem::path& path,
    const ::fic::core::SecureStateFileExpectation& expectation,
    std::string& diagnostic) {
    if (!::fic::core::proveSafeParentDirectory(
            path.parent_path().parent_path(), expectation, diagnostic)) {
        return std::nullopt;
    }
    const auto secure = ::fic::core::readSecureFileBounded(
        path, expectation, ::fic::core::MAX_WORKING_CONFIG_BYTES);
    if (secure.status != ::fic::core::SecureStateReadStatus::Proven) {
        diagnostic = secure.detail.empty() ? "GLOBAL.conf is not proven" : secure.detail;
        return std::nullopt;
    }
    bool seen = false;
    bool enabled = false;
    std::size_t cursor = 0;
    while (cursor < secure.content.size()) {
        const auto end = secure.content.find('\n', cursor);
        const std::string line = trim(secure.content.substr(
            cursor, end == std::string::npos ? std::string::npos : end - cursor));
        cursor = end == std::string::npos ? secure.content.size() : end + 1U;
        if (line.empty() || line.front() == '#') continue;
        const auto separator = line.find('=');
        const std::string key = trim(line.substr(0, separator));
        if (key != Key) {
            if (line.find(Key) != std::string::npos) {
                diagnostic = "malformed recovery key";
                return std::nullopt;
            }
            continue;
        }
        if (seen || separator == std::string::npos ||
            line.find('=', separator + 1U) != std::string::npos) {
            diagnostic = "duplicate or malformed recovery key";
            return std::nullopt;
        }
        const std::string value = trim(line.substr(separator + 1U));
        if (value != "ENABLE" && value != "DISABLE") {
            diagnostic = "invalid recovery value";
            return std::nullopt;
        }
        seen = true;
        enabled = value == "ENABLE";
    }
    if (!seen) {
        diagnostic = "recovery key is missing";
        return std::nullopt;
    }
    diagnostic = enabled ? "recovery enabled" : "recovery disabled";
    return enabled;
}

} // namespace fic::incident
