#include "modules/net/ssh/SshManagedBlock.h"

#include "modules/net/ssh/SshConfigSyntax.h"

#include <algorithm>
#include <atomic>
#include <ctime>
#include <map>
#include <utility>

#include <unistd.h>

namespace {

bool startsWith(const std::string& text, const char* prefix) {
    return text.rfind(prefix, 0) == 0;
}

// Parses the trailing "key=value key=value@" field section of a marker line.
// The line must end exactly with '@' after the fields.
bool parseMarkerFields(const std::string& body,
                       std::map<std::string, std::string>& fields) {
    fields.clear();
    if (body.empty() || body.back() != '@') {
        return false;
    }
    const std::string content = body.substr(0, body.size() - 1);
    std::size_t position = 0;
    while (position < content.size()) {
        while (position < content.size() && content[position] == ' ') {
            ++position;
        }
        const std::size_t keyStart = position;
        while (position < content.size() && content[position] != '=' &&
               content[position] != ' ') {
            ++position;
        }
        if (position >= content.size() || content[position] != '=') {
            return false;
        }
        const std::string key = content.substr(keyStart, position - keyStart);
        ++position; // '='
        const std::size_t valueStart = position;
        while (position < content.size() && content[position] != ' ') {
            ++position;
        }
        if (position == valueStart || key.empty()) {
            return false;
        }
        if (!fields.emplace(key, content.substr(valueStart, position - valueStart))
                 .second) {
            return false; // duplicate field
        }
    }
    return !fields.empty();
}

bool isMatchLine(const std::string& line, bool& ok) {
    const SshLineParseResult parsed = parseSshConfigLine(line);
    ok = parsed.ok;
    return parsed.ok && parsed.hasDirective &&
           normalizeSshKeyword(parsed.directive.keyword) == "match";
}

struct PolicySemanticsEntry {
    const char* policyName;
    SshDirectiveSemantics semantics;
    const char* directive;
};

const PolicySemanticsEntry kSshPolicySemantics[] = {
    {"ssh_root_login", SshDirectiveSemantics::ScalarFirstWins, "PermitRootLogin"},
    {"ssh_pubkey_auth", SshDirectiveSemantics::ScalarFirstWins,
     "PubkeyAuthentication"},
    {"ssh_max_auth_tries", SshDirectiveSemantics::ScalarFirstWins,
     "MaxAuthTries"},
    {"ssh_port", SshDirectiveSemantics::MultiValue, "Port"},
};

const PolicySemanticsEntry* findPolicyEntry(const std::string& policyName) {
    for (const PolicySemanticsEntry& entry : kSshPolicySemantics) {
        if (policyName == entry.policyName) {
            return &entry;
        }
    }
    return nullptr;
}

} // namespace
// PLACEHOLDER_REST

namespace {

// Mutable state of the marker parser (see parseSshManagedModel()).
struct ParserState {
    bool inManagedBlock = false;
    bool inPolicyBlock = false;
    bool inDisabledBlock = false;
    bool disabledLineSeen = false;
    SshManagedPolicyBlock currentPolicy;
    SshDisabledBlock currentDisabled;
};

// Handles one FIC marker line. Returns Ok to continue, otherwise the final
// parse status with the error filled in.
SshManagedParseStatus parseMarkerLine(const std::string& line,
                                      std::size_t index,
                                      ParserState& state,
                                      SshManagedModel& model,
                                      std::string& error) {
    const auto fail = [&error, &index](const std::string& message) {
        error = message + " (строка " + std::to_string(index + 1) + ")";
        return SshManagedParseStatus::Malformed;
    };

    if (state.inDisabledBlock) {
        if (startsWith(line, kSshDisabledLinePrefix)) {
            if (state.disabledLineSeen) {
                return fail("Несколько FIC_DISABLED_LINE в одном блоке");
            }
            state.disabledLineSeen = true;
            state.currentDisabled.originalLine =
                line.substr(std::string(kSshDisabledLinePrefix).size());
            return SshManagedParseStatus::Ok;
        }
        if (startsWith(line, kSshDisabledEndPrefix)) {
            std::map<std::string, std::string> fields;
            if (!parseMarkerFields(
                    line.substr(std::string(kSshDisabledEndPrefix).size()),
                    fields) ||
                fields.size() != 2 ||
                fields["policy"] != state.currentDisabled.policy ||
                fields["mutation"] != state.currentDisabled.mutationId) {
                return fail("Несогласованный FIC_DISABLED_END маркер");
            }
            state.currentDisabled.endLine = index;
            model.disabled.push_back(state.currentDisabled);
            state.inDisabledBlock = false;
            return SshManagedParseStatus::Ok;
        }
        return fail("Неожиданный FIC-маркер внутри DISABLED-блока");
    }
    if (state.inPolicyBlock) {
        if (startsWith(line, kSshPolicyEndPrefix)) {
            std::map<std::string, std::string> fields;
            if (!parseMarkerFields(
                    line.substr(std::string(kSshPolicyEndPrefix).size()),
                    fields) ||
                fields.size() != 1 ||
                fields["name"] != state.currentPolicy.name) {
                return fail("Несогласованный FIC_POLICY_END маркер");
            }
            if (state.currentPolicy.directiveLine.empty()) {
                return fail("Пустой FIC policy-блок '" +
                            state.currentPolicy.name + "'");
            }
            state.currentPolicy.endLine = index;
            model.policies.push_back(state.currentPolicy);
            state.inPolicyBlock = false;
            return SshManagedParseStatus::Ok;
        }
        return fail("Неожиданный FIC-маркер внутри policy-блока");
    }
    if (state.inManagedBlock) {
        if (startsWith(line, kSshPolicyBeginPrefix)) {
            std::map<std::string, std::string> fields;
            if (!parseMarkerFields(
                    line.substr(std::string(kSshPolicyBeginPrefix).size()),
                    fields) ||
                fields.size() != 1 || fields.count("name") == 0 ||
                fields["name"].empty()) {
                return fail("Некорректный FIC_POLICY_BEGIN маркер");
            }
            for (const SshManagedPolicyBlock& existing : model.policies) {
                if (existing.name == fields["name"]) {
                    return fail("Дублирующийся FIC policy-блок '" +
                                existing.name + "'");
                }
            }
            state.currentPolicy = SshManagedPolicyBlock{};
            state.currentPolicy.name = fields["name"];
            state.currentPolicy.beginLine = index;
            state.inPolicyBlock = true;
            return SshManagedParseStatus::Ok;
        }
        if (startsWith(line, kSshBlockEnd)) {
            if (line != kSshBlockEnd) {
                return fail("Некорректный FIC_SSH_BLOCK_END маркер");
            }
            model.blockEnd = index;
            state.inManagedBlock = false;
            model.blockPresent = true;
            return SshManagedParseStatus::Ok;
        }
        return fail("Неожиданный FIC-маркер внутри managed-блока");
    }

    // Outside any block.
    if (startsWith(line, kSshBlockBeginPrefix)) {
        if (model.blockPresent) {
            return fail("Дублирующийся FIC managed-блок");
        }
        std::map<std::string, std::string> fields;
        if (!parseMarkerFields(
                line.substr(std::string(kSshBlockBeginPrefix).size()), fields) ||
            fields.size() != 1 || fields.count("version") == 0) {
            return fail("Некорректный FIC_SSH_BLOCK_BEGIN маркер");
        }
        int version = 0;
        try {
            version = std::stoi(fields["version"]);
        } catch (...) {
            return fail("Некорректная версия FIC managed-блока");
        }
        if (version != kSshManagedBlockVersion) {
            error = "Неподдерживаемая версия FIC managed-блока: " +
                    std::to_string(version);
            return SshManagedParseStatus::UnsupportedVersion;
        }
        model.version = version;
        model.blockBegin = index;
        state.inManagedBlock = true;
        return SshManagedParseStatus::Ok;
    }
    if (startsWith(line, kSshDisabledBeginPrefix)) {
        if (model.blockPresent && index <= model.blockEnd) {
            return fail("DISABLED-блок внутри FIC managed-блока");
        }
        std::map<std::string, std::string> fields;
        if (!parseMarkerFields(
                line.substr(std::string(kSshDisabledBeginPrefix).size()),
                fields) ||
            fields.size() != 2 || fields.count("policy") == 0 ||
            fields.count("mutation") == 0 || fields["policy"].empty() ||
            fields["mutation"].empty()) {
            return fail("Некорректный FIC_DISABLED_BEGIN маркер");
        }
        state.currentDisabled = SshDisabledBlock{};
        state.currentDisabled.policy = fields["policy"];
        state.currentDisabled.mutationId = fields["mutation"];
        state.currentDisabled.beginLine = index;
        state.disabledLineSeen = false;
        state.inDisabledBlock = true;
        return SshManagedParseStatus::Ok;
    }
    return fail("Некорректный или неожиданный FIC-маркер: " + line);
}

} // namespace
SshDirectiveSemantics sshPolicyDirectiveSemantics(const std::string& policyName) {
    const PolicySemanticsEntry* entry = findPolicyEntry(policyName);
    return entry != nullptr ? entry->semantics
                            : SshDirectiveSemantics::Unsupported;
}

std::string sshPolicyDirectiveKeyword(const std::string& policyName) {
    const PolicySemanticsEntry* entry = findPolicyEntry(policyName);
    return entry != nullptr ? std::string(entry->directive) : std::string();
}

std::string sshManagedDirectiveLine(const std::string& directive,
                                    const std::string& value) {
    return directive + " " + value;
}
SshManagedParseStatus parseSshManagedModel(const std::vector<std::string>& lines,
                                           SshManagedModel& model,
                                           std::string& error) {
    model = SshManagedModel{};
    error.clear();

    ParserState state;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        const std::string& line = lines[index];
        if (!startsWith(line, kSshMarkerIntroducer)) {
            bool ok = false;
            if (!state.inManagedBlock && !state.inDisabledBlock &&
                !state.inPolicyBlock && isMatchLine(line, ok)) {
                if (!ok) {
                    error = "Не удалось разобрать строку " +
                            std::to_string(index + 1) + " sshd_config";
                    return SshManagedParseStatus::Malformed;
                }
                // Global section ended: no FIC markers are allowed inside
                // Match sections.
                for (std::size_t rest = index; rest < lines.size(); ++rest) {
                    if (startsWith(lines[rest], kSshMarkerIntroducer)) {
                        error = "FIC-маркер внутри Match-секции sshd_config "
                                "(строка " +
                                std::to_string(rest + 1) + ")";
                        return SshManagedParseStatus::Malformed;
                    }
                }
                return SshManagedParseStatus::Ok;
            }
            if (state.inPolicyBlock) {
                // Sub-block content: exactly one active directive line and
                // nothing else. Comments and blank lines inside the owned
                // range are foreign content and fail closed.
                if (line.empty()) {
                    error = "Пустая строка внутри FIC policy-блока '" +
                            state.currentPolicy.name + "' не допускается";
                    return SshManagedParseStatus::Malformed;
                }
                const SshLineParseResult parsed = parseSshConfigLine(line);
                if (!parsed.ok) {
                    error = "Не удалось разобрать строку " +
                            std::to_string(index + 1) + " sshd_config";
                    return SshManagedParseStatus::Malformed;
                }
                if (!parsed.hasDirective) {
                    error = "Строка комментария внутри FIC policy-блока '" +
                            state.currentPolicy.name + "' не допускается";
                    return SshManagedParseStatus::Malformed;
                }
                if (!state.currentPolicy.directiveLine.empty()) {
                    error = "Несколько директив внутри FIC policy-блока '" +
                            state.currentPolicy.name + "'";
                    return SshManagedParseStatus::Malformed;
                }
                state.currentPolicy.directiveLine = line;
                continue;
            }
            if (state.inDisabledBlock) {
                // Disabled wrapper content: only the single FIC_DISABLED_LINE
                // marker (handled by parseMarkerLine). Any other line —
                // directive, comment or blank — is foreign content inside an
                // owned range and fails closed.
                error = "Посторонняя строка внутри FIC_DISABLED-блока политики '" +
                        state.currentDisabled.policy + "' (строка " +
                        std::to_string(index + 1) + ")";
                return SshManagedParseStatus::Malformed;
            }
            if (state.inManagedBlock) {
                // Managed block content: only FIC_POLICY sub-blocks (handled
                // by parseMarkerLine). Any other line — directive, comment or
                // blank — is foreign content inside an owned range and fails
                // closed.
                error = "Посторонняя строка внутри FIC managed-блока (строка " +
                        std::to_string(index + 1) + ")";
                return SshManagedParseStatus::Malformed;
            }
            continue;
        }
        const SshManagedParseStatus status =
            parseMarkerLine(line, index, state, model, error);
        if (status != SshManagedParseStatus::Ok) {
            return status;
        }
    }

    if (state.inManagedBlock || state.inPolicyBlock || state.inDisabledBlock) {
        error = "Незакрытый FIC-маркер в конце sshd_config";
        return SshManagedParseStatus::Malformed;
    }
    return SshManagedParseStatus::Ok;
}
SshDisabledProvenanceCheck checkSshDisabledProvenance(
    const SshManagedModel& model,
    const std::string& policyName,
    const std::vector<std::string>& expectedMutationIds) {
    SshDisabledProvenanceCheck result;

    std::vector<std::string> expected = expectedMutationIds;
    std::sort(expected.begin(), expected.end());
    if (std::adjacent_find(expected.begin(), expected.end()) !=
        expected.end()) {
        result.payloadMalformed = true;
    }

    std::vector<std::string> actual;
    for (const SshDisabledBlock& block : model.disabled) {
        if (block.policy == policyName) {
            actual.push_back(block.mutationId);
        }
    }
    std::sort(actual.begin(), actual.end());
    if (std::adjacent_find(actual.begin(), actual.end()) != actual.end()) {
        result.fileDuplicate = true;
    }

    for (std::size_t i = 0; i < actual.size(); ++i) {
        if (i > 0 && actual[i] == actual[i - 1]) {
            continue; // already reported as fileDuplicate
        }
        if (std::find(expected.begin(), expected.end(), actual[i]) ==
            expected.end()) {
            result.unknownIds.push_back(actual[i]);
        }
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (i > 0 && expected[i] == expected[i - 1]) {
            continue; // already reported as payloadMalformed
        }
        if (std::find(actual.begin(), actual.end(), expected[i]) ==
            actual.end()) {
            result.missingIds.push_back(expected[i]);
        }
    }
    return result;
}

std::string describeSshDisabledProvenance(
    const SshDisabledProvenanceCheck& check,
    const std::string& policyName) {
    if (check.ok()) {
        return {};
    }
    std::string description;
    if (check.payloadMalformed) {
        description += "journal payload содержит дублирующийся mutation id; ";
    }
    if (check.fileDuplicate) {
        description += "в файле несколько FIC_DISABLED блоков с одним mutation id; ";
    }
    if (!check.unknownIds.empty()) {
        description += "неизвестные payload'у wrapper id:";
        for (const std::string& id : check.unknownIds) {
            description += " '" + id + "'";
        }
        description += "; ";
    }
    if (!check.missingIds.empty()) {
        description += "отсутствующие в файле wrapper id:";
        for (const std::string& id : check.missingIds) {
            description += " '" + id + "'";
        }
        description += "; ";
    }
    return "провенанс FIC_DISABLED блоков политики '" + policyName +
           "' не совпадает с journal payload: " + description;
}

bool sshManagedModelHasPolicy(const SshManagedModel& model,
                              const std::string& policyName) {
    for (const SshManagedPolicyBlock& block : model.policies) {
        if (block.name == policyName) {
            return true;
        }
    }
    return false;
}

bool sshManagedModelHasDisabledForPolicy(const SshManagedModel& model,
                                         const std::string& policyName) {
    for (const SshDisabledBlock& block : model.disabled) {
        if (block.policy == policyName) {
            return true;
        }
    }
    return false;
}

bool upsertSshManagedPolicyBlock(std::vector<std::string>& lines,
                                 const std::string& policyName,
                                 const std::string& directiveLine,
                                 bool& changed,
                                 std::string& error) {
    changed = false;
    SshManagedModel model;
    const SshManagedParseStatus status =
        parseSshManagedModel(lines, model, error);
    if (status != SshManagedParseStatus::Ok) {
        error = "Не удалось разобрать FIC-маркеры sshd_config: " + error;
        return false;
    }

    for (const SshManagedPolicyBlock& block : model.policies) {
        if (block.name == policyName) {
            if (block.directiveLine == directiveLine) {
                return true; // idempotent
            }
            lines[block.beginLine + 1] = directiveLine;
            changed = true;
            return true;
        }
    }

    std::vector<std::string> blockLines = {
        std::string("#@FIC_POLICY_BEGIN name=") + policyName + "@",
        directiveLine,
        std::string("#@FIC_POLICY_END name=") + policyName + "@",
    };
    if (!model.blockPresent) {
        // Place the managed block at the very top of the file: scalar
        // first-obtained-value directives must override user lines and
        // included files.
        std::vector<std::string> prefix = {
            std::string(kSshBlockBeginPrefix) + "version=" +
                std::to_string(kSshManagedBlockVersion) + "@",
        };
        prefix.insert(prefix.end(), blockLines.begin(), blockLines.end());
        prefix.push_back(kSshBlockEnd);
        // No separator line outside the managed block: FIC must never add
        // artifacts it cannot remove byte-exact on rollback.
        lines.insert(lines.begin(), prefix.begin(), prefix.end());
        changed = true;
        return true;
    }
    lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(model.blockEnd),
                 blockLines.begin(), blockLines.end());
    changed = true;
    return true;
}
bool removeSshManagedPolicyBlock(std::vector<std::string>& lines,
                                 const std::string& policyName,
                                 const std::string& expectedDirectiveLine,
                                 bool& removed,
                                 std::string& error) {
    removed = false;
    SshManagedModel model;
    const SshManagedParseStatus status =
        parseSshManagedModel(lines, model, error);
    if (status != SshManagedParseStatus::Ok) {
        error = "Не удалось разобрать FIC-маркеры sshd_config: " + error;
        return false;
    }
    for (const SshManagedPolicyBlock& block : model.policies) {
        if (block.name != policyName) {
            continue;
        }
        if (block.directiveLine != expectedDirectiveLine) {
            error = "Содержимое FIC policy-блока '" + policyName +
                    "' не соответствует записанному FIC значению; владение "
                    "не может быть доказано";
            return false;
        }
        std::size_t begin = block.beginLine;
        std::size_t count = block.endLine - block.beginLine + 1;
        if (model.policies.size() == 1) {
            // The whole managed block becomes empty: remove the markers too.
            begin = model.blockBegin;
            count = model.blockEnd - model.blockBegin + 1;
        }
        lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(begin),
                    lines.begin() + static_cast<std::ptrdiff_t>(begin + count));
        removed = true;
        return true;
    }
    return true; // nothing owned for this policy
}

void disableSshLine(std::vector<std::string>& lines,
                    std::size_t index,
                    const std::string& policyName,
                    const std::string& mutationId) {
    std::vector<std::string> wrapper = {
        std::string(kSshDisabledBeginPrefix) + "policy=" + policyName +
            " mutation=" + mutationId + "@",
        std::string(kSshDisabledLinePrefix) + lines[index],
        std::string(kSshDisabledEndPrefix) + "policy=" + policyName +
            " mutation=" + mutationId + "@",
    };
    lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(index));
    lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(index),
                 wrapper.begin(), wrapper.end());
}

bool restoreSshDisabledLines(std::vector<std::string>& lines,
                             const std::string& policyName,
                             const std::vector<std::string>& allowedMutationIds,
                             bool& changed,
                             std::string& error) {
    changed = false;
    SshManagedModel model;
    const SshManagedParseStatus status =
        parseSshManagedModel(lines, model, error);
    if (status != SshManagedParseStatus::Ok) {
        error = "Не удалось разобрать FIC-маркеры sshd_config: " + error;
        return false;
    }
    for (std::size_t position = model.disabled.size(); position-- > 0;) {
        const SshDisabledBlock& block = model.disabled[position];
        if (block.policy != policyName) {
            continue;
        }
        if (std::find(allowedMutationIds.begin(), allowedMutationIds.end(),
                      block.mutationId) == allowedMutationIds.end()) {
            error = "FIC_DISABLED блок политики '" + policyName +
                    "' имеет неизвестный mutation id '" + block.mutationId +
                    "'; владение не может быть доказано";
            return false;
        }
        lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(block.beginLine),
                    lines.begin() +
                        static_cast<std::ptrdiff_t>(block.endLine + 1));
        lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(block.beginLine),
                     block.originalLine);
        changed = true;
    }
    return true;
}

std::string generateSshDisabledMutationId(int ordinal) {
    static std::atomic<unsigned long long> counter{0};
    // Nanosecond wall-clock time + pid + per-process counter: unique across
    // rapid daemon restarts within the same second, without external
    // dependencies.
    timespec now{};
    timespec_get(&now, TIME_UTC);
    return "FIC-" + std::to_string(static_cast<unsigned long long>(now.tv_sec)) +
           "-" + std::to_string(static_cast<unsigned long long>(now.tv_nsec)) +
           "-" + std::to_string(static_cast<unsigned long long>(::getpid())) +
           "-" + std::to_string(counter.fetch_add(1)) +
           "-" + std::to_string(ordinal);
}