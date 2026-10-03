#include "modules/identity_access/shared/login_defs/IdentityLoginDefsManagedConfig.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <limits>
#include <map>
#include <sys/types.h>

namespace fic::identity::login_defs {
namespace {

struct PolicySpec {
    std::string submodule;
    std::string key;
    Relation relation;
};

const std::map<std::string, PolicySpec>& policySpecs() {
    static const std::map<std::string, PolicySpec> specs = {
        {"user_create_home", {"USER_CREATION", "CREATE_HOME", Relation::None}},
        {"user_create_private_group",
         {"USER_CREATION", "USERGROUPS_ENAB", Relation::None}},
        {"password_min_age_days",
         {"PASSWORD_AGING", "PASS_MIN_DAYS", Relation::PasswordMinimum}},
        {"password_max_age_days",
         {"PASSWORD_AGING", "PASS_MAX_DAYS", Relation::PasswordMaximum}},
        {"password_expiration_warning_days",
         {"PASSWORD_AGING", "PASS_WARN_AGE", Relation::None}},
        {"regular_user_uid_min",
         {"PASSWORD_AGING", "UID_MIN", Relation::UidMinimum}},
        {"regular_user_uid_max",
         {"PASSWORD_AGING", "UID_MAX", Relation::UidMaximum}},
    };
    return specs;
}

const PolicySpec* policySpec(const PolicyRef& policy) {
    if (policy.moduleName != "IDENTITY_ACCESS") return nullptr;
    const auto found = policySpecs().find(policy.policyName);
    if (found == policySpecs().end() ||
        found->second.submodule != policy.submoduleName) {
        return nullptr;
    }
    return &found->second;
}

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

bool parseMarkerRef(const std::string& line, const char* prefix,
                    std::string& ref) {
    const std::string p(prefix);
    if (line.rfind(p, 0) != 0 || line.size() <= p.size() + 1 ||
        line.back() != '@') {
        return false;
    }
    ref = line.substr(p.size(), line.size() - p.size() - 1);
    return !ref.empty() && ref.find_first_of(" \t\r\n=@") == std::string::npos;
}

// Canonical single-assignment body: "KEY value" with exactly one separating
// space, a non-empty single-token value and no trailing content.
bool parseCanonicalAssignment(const std::string& line, std::string& key,
                              std::string& value) {
    const std::size_t split = line.find(' ');
    if (split == std::string::npos || split == 0) return false;
    key = line.substr(0, split);
    value = line.substr(split + 1);
    if (value.empty() || value.front() == '#' ||
        value.find_first_of(" \t\r\n") != std::string::npos) {
        return false;
    }
    return true;
}

std::string serializeContainer(
    const std::vector<ManagedPolicyBlock>& policies) {
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

bool parseLongStrict(const std::string& value, long minimum, long maximum,
                     long& out) {
    if (value.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    if (errno != 0 || end != value.c_str() + value.size() ||
        parsed < minimum || parsed > maximum) {
        return false;
    }
    out = parsed;
    return true;
}

} // namespace

bool policyRoute(const std::string& loginDefsPath, const PolicyRef& policy,
                 PolicyRoute& route, std::string& error) {
    route = {};
    const PolicySpec* spec = policySpec(policy);
    if (spec == nullptr) {
        error = "unknown shared login.defs policy: " + policy.submoduleName +
            "/" + policy.policyName;
        return false;
    }
    route.policyRef = policy.moduleName + "/" + policy.submoduleName + "/" +
        policy.policyName;
    route.key = spec->key;
    route.path = loginDefsPath;
    return !route.path.empty();
}

Relation policyRelation(const PolicyRef& policy, std::string& error) {
    const PolicySpec* spec = policySpec(policy);
    if (spec == nullptr) {
        error = "unknown shared login.defs policy: " + policy.submoduleName +
            "/" + policy.policyName;
        return Relation::None;
    }
    return spec->relation;
}

bool validatePolicyValue(const PolicyRef& policy, const std::string& value,
                         std::string& error) {
    const PolicySpec* spec = policySpec(policy);
    if (spec == nullptr) {
        error = "unknown shared login.defs policy: " + policy.submoduleName +
            "/" + policy.policyName;
        return false;
    }
    const auto decimal = [&](long minimum, long maximum) {
        long parsed = 0;
        if (!parseLongStrict(value, minimum, maximum, parsed)) return false;
        // Canonical form: no leading zeros, no '+'.
        return value == std::to_string(parsed);
    };
    const bool valid = [&] {
        if (spec->relation == Relation::None && spec->key != "PASS_WARN_AGE") {
            return value == "yes" || value == "no";
        }
        if (spec->key == "PASS_MIN_DAYS") return decimal(0, INT_MAX);
        if (spec->key == "PASS_MAX_DAYS") return decimal(-1, INT_MAX);
        if (spec->key == "PASS_WARN_AGE") return decimal(-1, INT_MAX);
        // UID range is the full uid_t range, not capped at INT_MAX.
        if (value.empty()) return false;
        errno = 0;
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
        if (errno != 0 || end != value.c_str() + value.size() ||
            parsed > std::numeric_limits<uid_t>::max()) {
            return false;
        }
        return value == std::to_string(parsed);
    }();
    if (!valid) {
        error = "invalid canonical value for " + spec->key + ": '" + value +
            "'";
        return false;
    }
    return true;
}

bool parseManagedConfig(const std::string& content, ManagedConfigModel& model,
                        std::string& error) {
    model = {};
    error.clear();
    const auto lines = linesWithOffsets(content);
    bool inContainer = false;
    bool inPolicy = false;
    ManagedPolicyBlock current;
    std::size_t containerStart = 0;
    std::size_t policyStart = 0;
    bool assignmentSeen = false;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const std::string& line = lines[i].first;
        const std::size_t offset = lines[i].second;
        if (line.rfind(kMarkerIntroducer, 0) != 0) {
            if (inPolicy) {
                if (line.empty()) continue;
                std::string key;
                std::string value;
                if (assignmentSeen ||
                    !parseCanonicalAssignment(line, key, value)) {
                    error = "invalid or duplicate assignment in FIC "
                            "login.defs policy sub-block";
                    return false;
                }
                current.key = key;
                current.value = value;
                assignmentSeen = true;
            } else if (inContainer && !line.empty()) {
                error = "unexpected content in FIC login.defs block";
                return false;
            }
            continue;
        }
        std::string ref;
        if (line == kBlockBegin && !inContainer && !model.blockPresent) {
            inContainer = true;
            containerStart = offset;
            model.blockOffset = offset;
            continue;
        }
        if (inContainer && !inPolicy &&
            parseMarkerRef(line, kPolicyBegin, ref)) {
            for (const auto& policy : model.policies) {
                if (policy.policyRef == ref) {
                    error = "duplicate FIC login.defs policy sub-block: " +
                        ref;
                    return false;
                }
            }
            inPolicy = true;
            current = {};
            current.policyRef = ref;
            policyStart = offset;
            assignmentSeen = false;
            continue;
        }
        if (inPolicy && parseMarkerRef(line, kPolicyEnd, ref) &&
            ref == current.policyRef) {
            if (!assignmentSeen) {
                error = "empty FIC login.defs policy sub-block: " + ref;
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
        error = "malformed or unexpected FIC login.defs marker: " + line;
        return false;
    }
    if (inContainer || inPolicy) {
        error = "dangling FIC login.defs marker";
        return false;
    }
    return true;
}

std::string canonicalPolicyBlock(const std::string& policyRef,
                                 const std::string& key,
                                 const std::string& value) {
    std::string result = std::string(kPolicyBegin) + policyRef + "@\n";
    result += key + " " + value + "\n";
    result += std::string(kPolicyEnd) + policyRef + "@\n";
    return result;
}

const ManagedPolicyBlock* findPolicyBlock(const ManagedConfigModel& model,
                                          const std::string& policyRef) {
    const auto found = std::find_if(model.policies.begin(),
        model.policies.end(), [&](const ManagedPolicyBlock& block) {
            return block.policyRef == policyRef;
        });
    return found == model.policies.end() ? nullptr : &*found;
}

bool upsertPolicyBlock(const std::string& content, const std::string& policyRef,
                       const std::string& key, const std::string& value,
                       std::string& result, bool& changed, std::string& error) {
    ManagedConfigModel model;
    if (!parseManagedConfig(content, model, error)) return false;
    const std::string raw = canonicalPolicyBlock(policyRef, key, value);
    bool found = false;
    for (auto& block : model.policies) {
        if (block.policyRef == policyRef) {
            found = true;
            block.key = key;
            block.value = value;
            block.raw = raw;
        }
    }
    if (!found) {
        ManagedPolicyBlock block;
        block.policyRef = policyRef;
        block.key = key;
        block.value = value;
        block.raw = raw;
        model.policies.push_back(std::move(block));
    }
    const std::string foreign = foreignWithoutBlock(content, model);
    if (!foreign.empty() && foreign.back() != '\n') {
        error = "foreign configuration has no terminating newline; cannot "
                "append FIC marker without changing foreign bytes";
        return false;
    }
    result = foreign + serializeContainer(model.policies);
    changed = result != content;
    return true;
}

bool removePolicyBlock(const std::string& content, const std::string& policyRef,
                       std::string& result, bool& removed, std::string& error) {
    ManagedConfigModel model;
    if (!parseManagedConfig(content, model, error)) return false;
    const ManagedPolicyBlock* current = findPolicyBlock(model, policyRef);
    if (current == nullptr) {
        result = content;
        removed = false;
        return true;
    }
    std::vector<ManagedPolicyBlock> peers;
    for (auto& block : model.policies) {
        if (block.policyRef != policyRef) peers.push_back(std::move(block));
    }
    const std::string foreign = foreignWithoutBlock(content, model);
    if (!peers.empty() && !foreign.empty() && foreign.back() != '\n') {
        error = "foreign configuration has no terminating newline; cannot "
                "retain peer FIC block without changing foreign bytes";
        return false;
    }
    result = foreign;
    if (!peers.empty()) result += serializeContainer(peers);
    removed = true;
    return true;
}

bool effectiveValue(const std::string& content, const std::string& key,
                    std::optional<std::string>& value, std::string& error) {
    value.reset();
    for (const auto& entry : linesWithOffsets(content)) {
        const std::string& line = entry.first;
        (void)entry.second;
        const std::size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue; // blank
        if (line[first] == '#') continue;         // comment line
        std::size_t keyEnd = first;
        while (keyEnd < line.size() &&
               std::isspace(static_cast<unsigned char>(line[keyEnd])) == 0) {
            ++keyEnd;
        }
        if (keyEnd == first) continue;
        const std::string candidateKey = line.substr(first, keyEnd - first);
        const std::size_t valueStart =
            line.find_first_not_of(" \t\r\n", keyEnd);
        if (valueStart == std::string::npos) {
            // No-value assignment: native shadow ignores it, so it must not
            // replace an earlier effective value.
            continue;
        }
        std::size_t valueEnd = valueStart;
        while (valueEnd < line.size() &&
               std::isspace(static_cast<unsigned char>(line[valueEnd])) == 0) {
            ++valueEnd;
        }
        const bool valid =
            line.find_first_not_of(" \t\r\n", valueEnd) == std::string::npos &&
            valueEnd > valueStart && line[valueStart] != '#';
        if (candidateKey != key) continue;
        if (!valid) {
            error = "malformed target-like login.defs assignment for " + key +
                ": " + line;
            return false;
        }
        value = line.substr(valueStart, valueEnd - valueStart);
    }
    return true;
}

bool relationsValidInCandidate(const std::string& candidateContent,
                               const PolicyRef& policy,
                               const MissingKeySemantics& semantics,
                               std::string& error) {
    const Relation relation = policyRelation(policy, error);
    if (!error.empty()) return false;
    if (relation == Relation::None) return true;
    const auto effective = [&](const std::string& key, long minimum,
                               long maximum, long& out) {
        std::optional<std::string> value;
        std::string readError;
        if (!effectiveValue(candidateContent, key, value, readError)) {
            error = "invalid candidate login.defs state for " + key + ": " +
                readError;
            return false;
        }
        if (!value.has_value()) {
            out = key == "PASS_MIN_DAYS" ? semantics.minDays
                                         : semantics.maxDays;
            return true;
        }
        return parseLongStrict(*value, minimum, maximum, out);
    };
    long minDays = 0;
    long maxDays = 0;
    if (relation == Relation::PasswordMinimum ||
        relation == Relation::PasswordMaximum) {
        if (!effective("PASS_MIN_DAYS", 0, INT_MAX, minDays) ||
            !effective("PASS_MAX_DAYS", -1, INT_MAX, maxDays)) {
            return false;
        }
        if (maxDays != -1 && minDays > maxDays) {
            error = "candidate login.defs relation is invalid: "
                    "PASS_MIN_DAYS > PASS_MAX_DAYS";
            return false;
        }
        return true;
    }
    // UID relation: both peers must be effectively present and valid.
    if (!effective("UID_MIN", 0, INT_MAX, minDays) ||
        !effective("UID_MAX", 0, INT_MAX, maxDays)) {
        error = "candidate login.defs UID relation is not provable: " + error;
        return false;
    }
    if (minDays > maxDays) {
        error = "candidate login.defs relation is invalid: UID_MIN > UID_MAX";
        return false;
    }
    return true;
}

} // namespace fic::identity::login_defs