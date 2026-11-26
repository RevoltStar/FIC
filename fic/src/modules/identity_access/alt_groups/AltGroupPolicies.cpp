#include "modules/identity_access/alt_groups/AltGroupPolicies.h"

#include "modules/identity_access/alt_groups/AltGroupTransaction.h"
#include "modules/identity_access/user_creation/UserCreationPolicies.h"
#include "rollback/DaemonMutationJournal.h"

#include <algorithm>
#include <set>
#include <stdexcept>

namespace fic::identity::alt_groups {
namespace {

bool validRoleGroup(std::string_view name) {
    if (name.empty() || name.front() == ' ' || name.back() == ' ') return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == ' ' || c == '_' || c == '-' ||
               c == '.' || c == '@' || c >= 128;
    });
}

json parseRoleGroups(const std::string& value) {
    std::set<std::string> keys;
    bool duplicate = false;
    const auto groups = json::parse(value,
        [&](int depth, json::parse_event_t event, json& parsed) {
            if (depth == 1 && event == json::parse_event_t::key) {
                duplicate |= !keys.insert(parsed.get<std::string>()).second;
            }
            return true;
        });
    if (!groups.is_object() || duplicate) {
        throw std::invalid_argument("Expected a JSON object with unique role names");
    }
    for (const auto& entry : groups.items()) {
        if (!validRoleGroup(entry.key()) || !entry.value().is_array()) {
            throw std::invalid_argument("Each role requires a valid name and a group array");
        }
        std::set<std::string> seen;
        for (const auto& value : entry.value()) {
            const auto group = value.get<std::string>();
            if (!validRoleGroup(group) || !seen.insert(group).second) {
                throw std::invalid_argument("Expected unique valid group names");
            }
        }
    }
    return groups;
}

std::string roleConfig(const json& groups) {
    std::string content;
    for (const auto& entry : groups.items()) {
        if (entry.value().empty()) continue;
        content += entry.key() + ':';
        bool firstGroup = true;
        for (const auto& group : entry.value()) {
            if (!firstGroup) content += ',';
            content += group.get_ref<const std::string&>();
            firstGroup = false;
        }
        content += '\n';
    }
    return content;
}

class RoleGroupsValue final : public PolicyTypeValue {
public:
    RoleGroupsValue() { defaultValue = "{}"; }

    PolicyEditorSpec getEditorSpec() const override {
        PolicyEditorSpec editor;
        editor.editor = "textedit";
        return editor;
    }

    bool validate(const std::string& value) override {
        try {
            parseRoleGroups(value);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    std::string postProcessingValue(const std::string& value) override {
        return parseRoleGroups(value).dump();
    }

    std::string reverse_postProcessingValue(const std::string& value) override {
        return parseRoleGroups(value).dump();
    }

    std::string getPolicyRestrictionInfo() override {
        return "JSON object mapping unique role names to arrays of unique group names";
    }
};

} // namespace

AltLdapUsersDefaultGroupsPolicy::AltLdapUsersDefaultGroupsPolicy()
    : IdentityAccessPolicy(ldapPolicy.submoduleName.c_str()) {
    policyName = ldapPolicy.policyName;
    policyTypeValue = std::make_unique<GroupListPolicyTypeValue>();
}

bool AltLdapUsersDefaultGroupsPolicy::apply() {
    try {
        const auto value = getValue();
        if (!value || !policyTypeValue->validate(*value)) return false;
        const auto groups = json::parse(policyTypeValue->postProcessingValue(*value));
        std::string line = "default_groups=\"";
        for (std::size_t i = 0; i < groups.size(); ++i) {
            if (i != 0) line += ' ';
            line += groups[i].get_ref<const std::string&>();
        }
        line += '"';
        const std::lock_guard lock(configurationMutex());
        std::string error;
        auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
        if (journal && alt_groups::apply(ldapPolicy, line, *journal, error)) return true;
        log(error, logLevel::ERROR);
    } catch (const std::exception& error) {
        log(error.what(), logLevel::ERROR);
    }
    return false;
}

AltRoleGroupsPolicy::AltRoleGroupsPolicy()
    : IdentityAccessPolicy(rolePolicy.submoduleName.c_str()) {
    policyName = rolePolicy.policyName;
    policyTypeValue = std::make_unique<RoleGroupsValue>();
}

bool AltRoleGroupsPolicy::apply() {
    try {
        const auto value = getValue();
        if (!value) return false;
        const auto content = roleConfig(parseRoleGroups(*value));
        const std::lock_guard lock(configurationMutex());
        std::string error;
        auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
        if (journal && alt_groups::apply(rolePolicy, content, *journal, error)) return true;
        log(error, logLevel::ERROR);
    } catch (const std::exception& error) {
        log(error.what(), logLevel::ERROR);
    }
    return false;
}

} // namespace fic::identity::alt_groups
