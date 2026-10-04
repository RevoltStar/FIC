#include "modules/dac/sudo/SudoersDisabledWrapper.h"

#include <algorithm>
#include <atomic>
#include <ctime>
#include <map>
#include <utility>

#include <unistd.h>

namespace fic::sudoers {
namespace {

bool startsWith(const std::string& text, const char* prefix) {
    return text.rfind(prefix, 0) == 0;
}

bool startsWithIntroducer(const std::string& text) {
    return startsWith(text, kSudoMarkerIntroducer);
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

bool parseWrapperMarker(const std::string& line,
                        const char* prefix,
                        std::string& policy,
                        std::string& mutationId,
                        std::string& error) {
    const std::string body = line.substr(std::char_traits<char>::length(prefix));
    std::map<std::string, std::string> fields;
    if (!parseMarkerFields(body, fields)) {
        error = "неразбираемые поля FIC-маркера: " + line;
        return false;
    }
    const auto policyIt = fields.find("policy");
    const auto mutationIt = fields.find("mutation");
    if (policyIt == fields.end() || mutationIt == fields.end() ||
        fields.size() != 2) {
        error = "в FIC-маркере должны быть ровно поля policy= и mutation=: " + line;
        return false;
    }
    policy = policyIt->second;
    mutationId = mutationIt->second;
    return true;
}

} // namespace

SudoWrapperParseStatus parseSudoDisabledWrappers(
    const std::vector<std::string>& lines,
    std::vector<SudoDisabledWrapper>& wrappers,
    std::string& error) {
    wrappers.clear();
    error.clear();

    bool inWrapper = false;
    SudoDisabledWrapper current;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        const std::string& line = lines[index];
        if (startsWith(line, kSudoDisabledBeginPrefix)) {
            if (inWrapper) {
                error = "вложенный FIC_SUDO_DISABLED_BEGIN в строке " +
                    std::to_string(index + 1);
                return SudoWrapperParseStatus::Malformed;
            }
            SudoDisabledWrapper wrapper;
            wrapper.beginLine = index;
            if (!parseWrapperMarker(line, kSudoDisabledBeginPrefix,
                                    wrapper.policy, wrapper.mutationId, error)) {
                return SudoWrapperParseStatus::Malformed;
            }
            inWrapper = true;
            current = std::move(wrapper);
            continue;
        }

        if (startsWith(line, kSudoDisabledEndPrefix)) {
            if (!inWrapper) {
                error = "FIC_SUDO_DISABLED_END без BEGIN в строке " +
                    std::to_string(index + 1);
                return SudoWrapperParseStatus::Malformed;
            }
            std::string endPolicy;
            std::string endMutation;
            if (!parseWrapperMarker(line, kSudoDisabledEndPrefix, endPolicy,
                                    endMutation, error)) {
                return SudoWrapperParseStatus::Malformed;
            }
            if (endPolicy != current.policy || endMutation != current.mutationId) {
                error = "FIC_SUDO_DISABLED_END не соответствует своему BEGIN";
                return SudoWrapperParseStatus::Malformed;
            }
            if (current.originalLines.empty()) {
                error = "FIC_SUDO_DISABLED блок " + current.mutationId +
                    " не содержит исходных строк";
                return SudoWrapperParseStatus::Malformed;
            }
            current.endLine = index;
            wrappers.push_back(std::move(current));
            inWrapper = false;
            current = SudoDisabledWrapper{};
            continue;
        }

        if (inWrapper) {
            if (!startsWith(line, kSudoDisabledLinePrefix)) {
                error = "не FIC-строка внутри FIC_SUDO_DISABLED блока: " + line;
                return SudoWrapperParseStatus::Malformed;
            }
            current.originalLines.push_back(
                line.substr(std::char_traits<char>::length(kSudoDisabledLinePrefix)));
            continue;
        }

        if (startsWithIntroducer(line)) {
            error = "неизвестный FIC-маркер sudoers в строке " +
                std::to_string(index + 1) + ": " + line;
            return SudoWrapperParseStatus::Malformed;
        }
    }

    if (inWrapper) {
        error = "незакрытый FIC_SUDO_DISABLED блок " + current.mutationId;
        return SudoWrapperParseStatus::Malformed;
    }
    return SudoWrapperParseStatus::Ok;
}

void disableSudoEntry(std::vector<std::string>& lines,
                      std::size_t firstLine,
                      std::size_t lineCount,
                      const std::string& policyName,
                      const std::string& mutationId) {
    const std::string begin = std::string(kSudoDisabledBeginPrefix) +
        "policy=" + policyName + " mutation=" + mutationId + "@";
    const std::string end = std::string(kSudoDisabledEndPrefix) +
        "policy=" + policyName + " mutation=" + mutationId + "@";

    std::vector<std::string> wrapper;
    wrapper.reserve(lineCount + 2);
    wrapper.push_back(begin);
    for (std::size_t offset = 0; offset < lineCount; ++offset) {
        wrapper.push_back(std::string(kSudoDisabledLinePrefix) +
                          lines[firstLine + offset]);
    }
    wrapper.push_back(end);

    lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(firstLine),
                lines.begin() + static_cast<std::ptrdiff_t>(firstLine + lineCount));
    lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(firstLine),
                 wrapper.begin(), wrapper.end());
}

bool restoreSudoDisabledEntries(std::vector<std::string>& lines,
                                const std::string& policyName,
                                const std::vector<std::string>& allowedMutationIds,
                                bool& changed,
                                std::string& error) {
    changed = false;
    std::vector<SudoDisabledWrapper> wrappers;
    if (parseSudoDisabledWrappers(lines, wrappers, error) !=
        SudoWrapperParseStatus::Ok) {
        error = "Не удалось разобрать FIC-маркеры sudoers: " + error;
        return false;
    }
    for (std::size_t position = wrappers.size(); position-- > 0;) {
        const SudoDisabledWrapper& wrapper = wrappers[position];
        if (wrapper.policy != policyName) {
            continue;
        }
        if (std::find(allowedMutationIds.begin(), allowedMutationIds.end(),
                      wrapper.mutationId) == allowedMutationIds.end()) {
            error = "FIC_SUDO_DISABLED блок политики '" + policyName +
                    "' имеет неизвестный mutation id '" + wrapper.mutationId +
                    "'; владение не может быть доказано";
            return false;
        }
        lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(wrapper.beginLine),
                    lines.begin() +
                        static_cast<std::ptrdiff_t>(wrapper.endLine + 1));
        lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(wrapper.beginLine),
                     wrapper.originalLines.begin(), wrapper.originalLines.end());
        changed = true;
    }
    return true;
}

SudoWrapperProvenanceCheck checkSudoWrapperProvenance(
    const std::vector<SudoDisabledWrapper>& wrappers,
    const std::string& policyName,
    const std::vector<std::string>& expectedMutationIds) {
    SudoWrapperProvenanceCheck check;
    std::map<std::string, size_t> payloadCounts;
    for (const std::string& id : expectedMutationIds) {
        ++payloadCounts[id];
    }
    for (const auto& entry : payloadCounts) {
        if (entry.second > 1) {
            check.payloadMalformed = true;
        }
    }

    std::map<std::string, size_t> fileCounts;
    for (const SudoDisabledWrapper& wrapper : wrappers) {
        if (wrapper.policy != policyName) {
            continue;
        }
        ++fileCounts[wrapper.mutationId];
    }
    for (const auto& entry : fileCounts) {
        if (entry.second > 1) {
            check.fileDuplicate = true;
        }
        if (payloadCounts.find(entry.first) == payloadCounts.end()) {
            check.unknownIds.push_back(entry.first);
        }
    }
    for (const std::string& id : expectedMutationIds) {
        if (fileCounts.find(id) == fileCounts.end()) {
            check.releasedIds.push_back(id);
        }
    }
    return check;
}

std::string describeSudoWrapperProvenance(
    const SudoWrapperProvenanceCheck& check,
    const std::string& policyName) {
    if (check.safeToRelease()) {
        return {};
    }
    std::string message = "проверка владения FIC_SUDO_DISABLED политики '" +
        policyName + "' не пройдена";
    if (check.payloadMalformed) {
        message += "; payload journal содержит повторяющиеся mutation id";
    }
    if (check.fileDuplicate) {
        message += "; файл содержит повторяющиеся mutation id";
    }
    if (!check.unknownIds.empty()) {
        message += "; неизвестные mutation id:";
        for (const std::string& id : check.unknownIds) {
            message += " " + id;
        }
    }
    return message;
}

std::string generateSudoWrapperMutationId(int ordinal) {
    static std::atomic<unsigned long long> counter{0};
    timespec now{};
    timespec_get(&now, TIME_UTC);
    return "FIC-SUDO-" + std::to_string(static_cast<unsigned long long>(now.tv_sec)) +
           "-" + std::to_string(static_cast<unsigned long long>(now.tv_nsec)) +
           "-" + std::to_string(static_cast<unsigned long long>(::getpid())) +
           "-" + std::to_string(counter.fetch_add(1)) +
           "-" + std::to_string(ordinal);
}

} // namespace fic::sudoers
