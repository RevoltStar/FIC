#include "modules/identity_access/user_creation/UserCreationManagedConfig.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>

namespace fic::identity::user_creation {
namespace {

constexpr const char* kPolicyBegin = "#@FIC_POLICY_BEGIN name=";
constexpr const char* kPolicyEnd = "#@FIC_POLICY_END name=";

std::vector<std::pair<std::string, std::size_t>> linesWithOffsets(
    const std::string& content) {
    std::vector<std::pair<std::string, std::size_t>> result;
    std::size_t start = 0;
    while (start < content.size()) {
        const std::size_t newline = content.find('\n', start);
        const std::size_t end = newline == std::string::npos
            ? content.size() : newline;
        std::string line = content.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        result.emplace_back(std::move(line), start);
        if (newline == std::string::npos) break;
        start = newline + 1;
    }
    return result;
}

bool parseMarkerName(const std::string& line, const char* prefix,
                     std::string& name) {
    const std::string p(prefix);
    if (line.rfind(p, 0) != 0 || line.size() <= p.size() + 1 ||
        line.back() != '@') return false;
    name = line.substr(p.size(), line.size() - p.size() - 1);
    return !name.empty() && name.find_first_of(" \t\r\n=@") ==
        std::string::npos;
}

bool parseManagedAssignment(const std::string& line, ConfigKind kind,
                            Assignment& assignment) {
    assignment = {};
    if (line.empty() || line[0] == '#' ||
        std::isspace(static_cast<unsigned char>(line[0]))) return false;
    if (kind == ConfigKind::LoginDefs) {
        const std::size_t split = line.find_first_of(" \t");
        if (split == std::string::npos) return false;
        const std::size_t valueStart = line.find_first_not_of(" \t", split);
        if (valueStart == std::string::npos) return false;
        assignment.key = line.substr(0, split);
        const std::string value = line.substr(valueStart);
        if (value.find_first_of("\r\n") != std::string::npos) return false;
    } else {
        const std::size_t equal = line.find('=');
        if (equal == std::string::npos || equal == 0) return false;
        assignment.key = line.substr(0, equal);
        if (kind == ConfigKind::Adduser) {
            const std::size_t last = assignment.key.find_last_not_of(" \t");
            if (last == std::string::npos) return false;
            assignment.key.erase(last + 1);
        }
        if (assignment.key.find_first_of(" \t\r\n") != std::string::npos)
            return false;
        std::string value = line.substr(equal + 1);
        if (kind == ConfigKind::Adduser) {
            const std::size_t first = value.find_first_not_of(" \t");
            if (first == std::string::npos) value.clear();
            else value.erase(0, first);
            const std::size_t last = value.find_last_not_of(" \t");
            if (last != std::string::npos) value.erase(last + 1);
        }
        if (kind == ConfigKind::Adduser && value.size() >= 2 &&
            ((value.front() == '"' && value.back() == '"') ||
             (value.front() == '\'' && value.back() == '\''))) {
            value = value.substr(1, value.size() - 2);
        }
        if (value.find_first_of("\r\n") != std::string::npos) return false;
    }
    if (assignment.key.empty()) return false;
    assignment.line = line;
    return true;
}

std::string trimSpaces(std::string value) {
    const std::size_t first = value.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    const std::size_t last = value.find_last_not_of(" \t");
    return value.substr(first, last - first + 1);
}

std::string trimLeadingSpaces(std::string value) {
    const std::size_t first = value.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    return value.substr(first);
}

std::string uppercaseAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](char ch) {
        return static_cast<char>(
            std::toupper(static_cast<unsigned char>(ch)));
    });
    return value;
}

bool parseNativeAssignment(const std::string& raw, ConfigKind kind,
                           Assignment& assignment, bool& ignored) {
    assignment = {};
    ignored = false;
    std::string line = raw;
    if (kind == ConfigKind::LoginDefs || kind == ConfigKind::Adduser) {
        const std::size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos) {
            ignored = true;
            return true;
        }
        line.erase(0, first);
    }
    if (line.empty() || line[0] == '#') {
        ignored = true;
        return true;
    }
    if (kind == ConfigKind::LoginDefs) {
        const std::size_t split = line.find_first_of(" \t");
        if (split == std::string::npos) return false;
        const std::size_t valueStart = line.find_first_not_of(" \t", split);
        if (valueStart == std::string::npos) {
            ignored = true;
            return true;
        }
        assignment.key = line.substr(0, split);
        assignment.line = assignment.key + " " + line.substr(valueStart);
        return true;
    }
    if (kind == ConfigKind::UseraddDefaults &&
        std::isspace(static_cast<unsigned char>(line[0]))) {
        ignored = true;
        return true;
    }
    const std::size_t equal = line.find('=');
    if (equal == std::string::npos || equal == 0) return false;
    std::string key = line.substr(0, equal);
    std::string value = line.substr(equal + 1);
    if (kind == ConfigKind::Adduser) {
        key = uppercaseAscii(trimSpaces(key));
        // adduser strips whitespace before the value but preserves trailing
        // bytes. EXTRA_GROUPS="audio"<spaces> is therefore not "audio" on
        // the supported 3.134--3.153 consumers.
        value = trimLeadingSpaces(value);
        if (value.size() >= 2 && value.front() == '"' &&
            value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        } else if (!value.empty() &&
                   (value.front() == '\'' || value.back() == '\'')) {
            // adduser 3.134/3.137 accept shell-style single quotes, while
            // 3.152/3.153 do not. Never claim a cross-version foreign no-op
            // for syntax whose consumer meaning is not uniform. Preserve the
            // quotes in the opaque value so a later canonical EOF assignment
            // safely overrides it instead of treating it as malformed.
        }
    } else if (key.find_first_of(" \t") != std::string::npos) {
        return false;
    }
    if (key.empty()) return false;
    assignment.key = std::move(key);
    assignment.line = assignment.key + "=" + value;
    return true;
}

std::string valueFromLine(const Assignment& assignment, ConfigKind kind) {
    if (kind == ConfigKind::LoginDefs) {
        const std::size_t split = assignment.line.find_first_of(" \t");
        const std::size_t start = assignment.line.find_first_not_of(" \t", split);
        return assignment.line.substr(start);
    }
    std::string value = assignment.line.substr(assignment.line.find('=') + 1);
    if (kind == ConfigKind::Adduser) value = trimLeadingSpaces(value);
    if (kind == ConfigKind::Adduser && value.size() >= 2 &&
        value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
    }
    return value;
}

std::vector<std::string> normalizedGroupList(std::string value, char separator) {
    std::vector<std::string> groups;
    std::size_t start = 0;
    while (start <= value.size()) {
        std::size_t end = separator == ' '
            ? value.find_first_of(" \t", start) : value.find(separator, start);
        std::string item = value.substr(start,
            end == std::string::npos ? std::string::npos : end - start);
        if (!item.empty()) groups.push_back(std::move(item));
        if (end == std::string::npos) break;
        start = value.find_first_not_of(separator == ' ' ? " \t" : ",", end);
        if (start == std::string::npos) break;
    }
    std::sort(groups.begin(), groups.end());
    return groups;
}

std::string serializeContainer(const std::vector<PolicyBlock>& policies) {
    if (policies.empty()) return {};
    std::string block = std::string(kBlockBegin) + "\n";
    for (const auto& policy : policies) block += policy.raw;
    block += std::string(kBlockEnd) + "\n";
    return block;
}

std::string foreignWithoutBlock(const std::string& content,
                                const ManagedConfigModel& model) {
    if (!model.blockPresent) return content;
    return content.substr(0, model.blockOffset) +
        content.substr(model.blockOffset + model.blockLength);
}

std::string appendAtLogicalEof(std::string foreign, const std::string& block) {
    if (block.empty()) return foreign;
    return foreign + block;
}

} // namespace

bool policyRoute(const fic::platform::UserCreationPlatformConfig& platform,
                 const std::string& policyName, PolicyRoute& route,
                 std::string& error) {
    route = {};
    const std::map<std::string, std::pair<ConfigKind, std::string>> scalar = {
        {"user_home_base_directory", {ConfigKind::UseraddDefaults, "HOME"}},
        {"user_skeleton_directory", {ConfigKind::UseraddDefaults, "SKEL"}},
        {"user_default_shell", {ConfigKind::UseraddDefaults, "SHELL"}},
        {"user_default_primary_group", {ConfigKind::UseraddDefaults, "GROUP"}},
        {"user_create_home", {ConfigKind::LoginDefs, "CREATE_HOME"}},
        {"user_create_private_group", {ConfigKind::LoginDefs, "USERGROUPS_ENAB"}}
    };
    const auto found = scalar.find(policyName);
    if (found != scalar.end()) {
        route.kind = found->second.first;
        route.keys = {found->second.second};
        route.path = (route.kind == ConfigKind::UseraddDefaults
            ? platform.useraddDefaultsPath : platform.loginDefsPath).string();
        return !route.path.empty();
    }
    if (policyName != "user_default_supplementary_groups") {
        error = "unknown USER_CREATION policy: " + policyName;
        return false;
    }
    if (platform.supplementaryGroupsProvider ==
        fic::platform::UserSupplementaryGroupsProviderKind::ShadowUseraddDefaults) {
        route = {ConfigKind::UseraddDefaults,
                 platform.useraddDefaultsPath.string(), {"GROUPS"}};
        return !route.path.empty();
    }
    if (platform.supplementaryGroupsProvider ==
        fic::platform::UserSupplementaryGroupsProviderKind::DebianAdduser) {
        route = {ConfigKind::Adduser, platform.adduserConfigPath.string(),
                 {"ADD_EXTRA_GROUPS", "EXTRA_GROUPS"}};
        return !route.path.empty();
    }
    error = "supplementary groups route is unsupported";
    return false;
}

bool parseManagedConfig(const std::string& content, ConfigKind kind,
                        ManagedConfigModel& model, std::string& error) {
    model = {};
    error.clear();
    const auto lines = linesWithOffsets(content);
    bool inContainer = false;
    bool inPolicy = false;
    PolicyBlock current;
    std::size_t policyStart = 0;
    std::set<std::string> names;
    std::set<std::string> keys;
    std::size_t containerStart = 0;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const std::string& line = lines[i].first;
        const std::size_t offset = lines[i].second;
        if (line.rfind(kMarkerIntroducer, 0) != 0) {
            if (inPolicy) {
                Assignment assignment;
                if (!parseManagedAssignment(line, kind, assignment) ||
                    !keys.insert(assignment.key).second) {
                    error = "invalid or duplicate assignment in FIC policy block";
                    return false;
                }
                current.assignments.push_back(std::move(assignment));
            } else if (inContainer && !line.empty()) {
                error = "unexpected content in FIC USER_CREATION block";
                return false;
            }
            continue;
        }
        if (line == kBlockBegin && !inContainer && !model.blockPresent) {
            inContainer = true;
            containerStart = offset;
            model.blockOffset = offset;
            continue;
        }
        std::string name;
        if (inContainer && !inPolicy && parseMarkerName(line, kPolicyBegin, name)) {
            if (!names.insert(name).second) {
                error = "duplicate FIC USER_CREATION policy block: " + name;
                return false;
            }
            inPolicy = true;
            current = {};
            current.policyName = name;
            policyStart = offset;
            keys.clear();
            continue;
        }
        if (inPolicy && parseMarkerName(line, kPolicyEnd, name) &&
            name == current.policyName) {
            if (current.assignments.empty()) {
                error = "empty FIC USER_CREATION policy block";
                return false;
            }
            const std::size_t rawEnd = i + 1 < lines.size()
                ? lines[i + 1].second : content.size();
            current.raw = content.substr(policyStart, rawEnd - policyStart);
            if (current.raw.empty() || current.raw.back() != '\n')
                current.raw += '\n';
            model.policies.push_back(std::move(current));
            inPolicy = false;
            continue;
        }
        if (line == kBlockEnd && inContainer && !inPolicy) {
            const std::size_t end = i + 1 < lines.size()
                ? lines[i + 1].second : content.size();
            model.blockLength = end - containerStart;
            model.blockPresent = true;
            inContainer = false;
            continue;
        }
        error = "malformed or unexpected FIC USER_CREATION marker: " + line;
        return false;
    }
    if (inContainer || inPolicy) {
        error = "dangling FIC USER_CREATION marker";
        return false;
    }
    return true;
}

std::string canonicalPolicyBlock(const std::string& policyName,
                                 const std::vector<Assignment>& assignments) {
    std::string result = std::string(kPolicyBegin) + policyName + "@\n";
    for (const auto& assignment : assignments) result += assignment.line + "\n";
    result += std::string(kPolicyEnd) + policyName + "@\n";
    return result;
}

const PolicyBlock* findPolicyBlock(const ManagedConfigModel& model,
                                   const std::string& policyName) {
    const auto found = std::find_if(model.policies.begin(), model.policies.end(),
        [&](const PolicyBlock& block) { return block.policyName == policyName; });
    return found == model.policies.end() ? nullptr : &*found;
}

bool upsertPolicyBlock(const std::string& content, ConfigKind kind,
                       const std::string& policyName,
                       const std::vector<Assignment>& assignments,
                       std::string& result, bool& changed,
                       std::string& error) {
    ManagedConfigModel model;
    if (!parseManagedConfig(content, kind, model, error)) return false;
    const std::string raw = canonicalPolicyBlock(policyName, assignments);
    bool found = false;
    for (auto& block : model.policies) {
        if (block.policyName == policyName) {
            found = true;
            block.assignments = assignments;
            block.raw = raw;
        }
    }
    if (!found) model.policies.push_back({policyName, assignments, raw});
    const std::string foreign = foreignWithoutBlock(content, model);
    if (!foreign.empty() && foreign.back() != '\n') {
        error = "foreign configuration has no terminating newline; cannot append FIC marker without changing foreign bytes";
        return false;
    }
    result = appendAtLogicalEof(foreign,
                                serializeContainer(model.policies));
    changed = result != content;
    return true;
}

bool removePolicyBlock(const std::string& content, ConfigKind kind,
                       const std::string& policyName,
                       const std::vector<Assignment>& expected,
                       std::string& result, bool& removed,
                       std::string& error) {
    ManagedConfigModel model;
    if (!parseManagedConfig(content, kind, model, error)) return false;
    const PolicyBlock* current = findPolicyBlock(model, policyName);
    if (current == nullptr) {
        result = content;
        removed = false;
        return true;
    }
    if (current->assignments != expected) {
        error = "FIC USER_CREATION policy block drifted: " + policyName;
        return false;
    }
    model.policies.erase(std::remove_if(model.policies.begin(), model.policies.end(),
        [&](const PolicyBlock& block) { return block.policyName == policyName; }),
        model.policies.end());
    const std::string foreign = foreignWithoutBlock(content, model);
    if (!foreign.empty() && !model.policies.empty() && foreign.back() != '\n') {
        error = "foreign configuration has no terminating newline; cannot retain peer FIC block without changing foreign bytes";
        return false;
    }
    result = appendAtLogicalEof(foreign,
                                serializeContainer(model.policies));
    removed = true;
    return true;
}

bool effectiveValue(const std::string& content, ConfigKind kind,
                    fic::platform::UseraddDefaultsLookupSemantics semantics,
                    const std::string& key,
                    std::optional<std::string>& value,
                    std::string& error) {
    value.reset();
    (void)semantics;
    for (const auto& [line, offset] : linesWithOffsets(content)) {
        (void)offset;
        Assignment assignment;
        bool ignored = false;
        if (line.rfind(kMarkerIntroducer, 0) == 0) continue;
        if (!parseNativeAssignment(line, kind, assignment, ignored)) {
            const std::string candidate = kind == ConfigKind::Adduser
                ? uppercaseAscii(trimSpaces(line)) : trimSpaces(line);
            const bool targetLike = candidate.rfind(key, 0) == 0;
            if (targetLike) {
                error = "malformed target assignment for " + key;
                return false;
            }
            continue;
        }
        if (ignored) continue;
        const bool matches = assignment.key == key;
        if (matches) value = valueFromLine(assignment, kind);
    }
    return true;
}

bool effectiveAssignmentsMatch(
    const std::string& content, ConfigKind kind,
    fic::platform::UseraddDefaultsLookupSemantics semantics,
    const std::vector<Assignment>& expected, std::string& error) {
    for (const auto& assignment : expected) {
        std::optional<std::string> actual;
        if (!effectiveValue(content, kind, semantics, assignment.key,
                            actual, error)) return false;
        const std::string expectedValue = valueFromLine(assignment, kind);
        if (!actual.has_value() && assignment.key == "GROUPS" &&
            normalizedGroupList(expectedValue, ',').empty()) {
            continue; // absent native GROUPS is the empty membership set
        }
        if (!actual.has_value() ||
            (assignment.key == "GROUPS"
                 ? normalizedGroupList(*actual, ',') !=
                       normalizedGroupList(expectedValue, ',')
                 : assignment.key == "EXTRA_GROUPS"
                       ? normalizedGroupList(*actual, ' ') !=
                             normalizedGroupList(expectedValue, ' ')
                       : *actual != expectedValue)) {
            error = "consumer-effective value mismatch for " + assignment.key;
            return false;
        }
    }
    return true;
}

} // namespace fic::identity::user_creation
