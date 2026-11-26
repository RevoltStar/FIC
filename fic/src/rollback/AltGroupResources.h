#ifndef FIC_ALT_GROUP_RESOURCES_H
#define FIC_ALT_GROUP_RESOURCES_H

#include "rollback/MutationRecord.h"

#include <string_view>

namespace fic::identity::alt_groups {

using fic::rollback::MutationBackend;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::UndoAltGroupConfig;
using fic::rollback::UndoAltRoleFile;

inline const PolicyRef ldapPolicy{"IDENTITY_ACCESS", "USER_CREATION", "alt_ldap_users_default_groups"};
inline const PolicyRef rolePolicy{"IDENTITY_ACCESS", "NSS", "alt_role_groups"};
inline constexpr char ldapPath[] = "/usr/lib/alterator/backend3/ldap-users";
inline constexpr char rolePath[] = "/etc/role";
inline constexpr char roleDirectory[] = "/etc/role.d";
inline constexpr std::string_view dropInPrefix = "role.d/";

inline std::string hexEncode(std::string_view bytes) {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        encoded += digits[byte >> 4];
        encoded += digits[byte & 15];
    }
    return encoded;
}

inline std::optional<std::string> hexDecode(std::string_view encoded) {
    static constexpr std::string_view digits = "0123456789abcdef";
    if (encoded.size() % 2 != 0) return std::nullopt;
    std::string bytes;
    bytes.reserve(encoded.size() / 2);
    for (std::size_t i = 0; i < encoded.size(); i += 2) {
        const auto high = digits.find(encoded[i]);
        const auto low = digits.find(encoded[i + 1]);
        if (high == digits.npos || low == digits.npos) return std::nullopt;
        bytes += static_cast<char>((high << 4) | low);
    }
    return bytes;
}

inline bool isRoleName(std::string_view name) {
    return (name.size() >= 5 && name.substr(name.size() - 5) == ".role") && name.find('/') == name.npos &&
           name.find('\0') == name.npos;
}

inline std::optional<std::string> roleName(std::string_view resource) {
    if (resource.substr(0, dropInPrefix.size()) != dropInPrefix) return std::nullopt;
    auto name = hexDecode(resource.substr(dropInPrefix.size()));
    if (!name || !isRoleName(*name)) return std::nullopt;
    return name;
}

inline bool sameState(const std::optional<AtomicTargetState>& a,
                      const std::optional<AtomicTargetState>& b) {
    if (!a || !b) return a.has_value() == b.has_value();
    return a->identity.device == b->identity.device &&
           a->identity.inode == b->identity.inode && a->content == b->content &&
           a->owner == b->owner && a->group == b->group && a->mode == b->mode;
}

inline bool validAssignment(std::string_view value) {
    constexpr std::string_view prefix = "default_groups=\"";
    if (value.substr(0, prefix.size()) != prefix || value.size() <= prefix.size() ||
        value.back() != '"') return false;
    const auto list = value.substr(prefix.size(), value.size() - prefix.size() - 1);
    for (std::size_t i = 0; i < list.size(); ++i) {
        const unsigned char c = list[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == ' ' || c == '_' || c == '-' || c == '.') continue;
        if (c == '$' && (i == list.size() - 1 || list[i + 1] == ' ')) continue;
        return false;
    }
    return true;
}

inline bool validRecord(const MutationRecord& record, std::string& error) {
    const auto* config = std::get_if<UndoAltGroupConfig>(&record.undo.payload);
    const auto* dropIn = std::get_if<UndoAltRoleFile>(&record.undo.payload);
    if (record.undo.backend != MutationBackend::AltGroups && !config && !dropIn &&
        record.policy != ldapPolicy && record.policy != rolePolicy) return true;
    if (record.undo.backend == MutationBackend::AltGroups) {
        if (config) {
            const bool ldap = record.policy == ldapPolicy && record.resource == ldapPath;
            const bool role = record.policy == rolePolicy && record.resource == rolePath;
            const auto validState = [&](const std::optional<AtomicTargetState>& state) {
                return !state || (state->identity.inode != 0 &&
                    state->owner == 0 && (state->mode & 07022) == 0 &&
                    state->content.size() <= 1024 * 1024 &&
                    (!ldap || validAssignment(state->content)));
            };
            if ((ldap || role) && (!ldap || (config->original && config->before && config->published)) &&
                (config->beforeOwned || (role && !config->releasing)) &&
                validState(config->original) && validState(config->before) &&
                validState(config->published) &&
                (config->releasing
                    ? (record.status != MutationStatus::Applied &&
                       config->original.has_value() == config->published.has_value() &&
                       (!config->original || config->original->content == config->published->content))
                    : config->published.has_value())) return true;
        } else if (dropIn && record.policy == rolePolicy && roleName(record.resource) &&
                   dropIn->fileInode && dropIn->linkInode &&
                   dropIn->fileInode != dropIn->linkInode &&
                   (!dropIn->releasing || record.status != MutationStatus::Applied)) {
            return true;
        }
    }
    error = "Invalid ALT group policy ownership";
    return false;
}

} // namespace fic::identity::alt_groups
#endif
