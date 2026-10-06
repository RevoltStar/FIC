#include "incident/IncidentRecoveryConfigReader.h"

#include <fic/core/runtime/FicPathDefaults.h>

#include <grp.h>
#include <cerrno>
#include <unistd.h>

#include <vector>

namespace fic::incident {
namespace {
constexpr const char* Key = "lock_exempt_fic_members.status";

bool groupId(gid_t& id) {
    std::vector<char> buffer(16384);
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        group record{};
        group* found = nullptr;
        const int rc = ::getgrnam_r("fic", &record, buffer.data(), buffer.size(), &found);
        if (rc == ERANGE) {
            buffer.resize(buffer.size() * 2U);
            continue;
        }
        if (rc != 0 || found == nullptr) return false;
        id = found->gr_gid;
        return true;
    }
    return false;
}

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r");
    return value.substr(first, last - first + 1U);
}
} // namespace

bool IncidentRecoveryConfigReader::ficMemberExemptionEnabled(std::string& diagnostic) {
    gid_t ficGroup = 0;
    if (!groupId(ficGroup)) {
        diagnostic = "fic group cannot be proven";
        return false;
    }
    ::fic::core::SecureStateFileExpectation expectation;
    expectation.owner = 0;
    expectation.group = ficGroup;
    expectation.exactMode = 0640;
    expectation.maxSize = ::fic::core::SECURE_STATE_READ_HARD_MAX_BYTES;
    expectation.requireSingleLink = true;
    expectation.parentOwner = 0;
    expectation.parentGroup = ficGroup;
    expectation.exactParentMode = 02750;
    return read(std::filesystem::path(::fic::core::path_defaults::CONFIG_DIR) / "GLOBAL.conf",
                expectation, diagnostic);
}

bool IncidentRecoveryConfigReader::read(
    const std::filesystem::path& path,
    const ::fic::core::SecureStateFileExpectation& expectation,
    std::string& diagnostic) {
    if (!::fic::core::proveSafeParentDirectory(
            path.parent_path().parent_path(), expectation, diagnostic)) {
        return false;
    }
    const auto secure = ::fic::core::readSecureStateFile(path, expectation);
    if (secure.status != ::fic::core::SecureStateReadStatus::Proven) {
        diagnostic = secure.detail.empty() ? "GLOBAL.conf is not proven" : secure.detail;
        return false;
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
                return false;
            }
            continue;
        }
        if (seen || separator == std::string::npos ||
            line.find('=', separator + 1U) != std::string::npos) {
            diagnostic = "duplicate or malformed recovery key";
            return false;
        }
        const std::string value = trim(line.substr(separator + 1U));
        if (value != "ENABLE" && value != "DISABLE") {
            diagnostic = "invalid recovery value";
            return false;
        }
        seen = true;
        enabled = value == "ENABLE";
    }
    if (!seen) {
        diagnostic = "recovery key is missing";
        return false;
    }
    diagnostic = enabled ? "recovery enabled" : "recovery disabled";
    return enabled;
}

} // namespace fic::incident
