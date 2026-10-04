#include "modules/dac/sudo/SudoersDisabledWrapper.h"

#include <fic/core/integrity/ContentDigest.h>

#include <algorithm>
#include <filesystem>
#include <atomic>
#include <cctype>
#include <ctime>
#include <map>
#include <set>
#include <utility>

#include <unistd.h>

namespace fic::sudoers {

bool isCanonicalSudoWrapperId(const std::string& wrapperId) {
    constexpr const char* kPrefix = "FIC-SUDO-";
    if (wrapperId.rfind(kPrefix, 0) != 0) {
        return false;
    }
    // Five decimal groups separated by '-'.
    int groups = 0;
    std::size_t index = std::char_traits<char>::length(kPrefix);
    while (index < wrapperId.size()) {
        std::size_t digits = 0;
        while (index < wrapperId.size() &&
               std::isdigit(static_cast<unsigned char>(wrapperId[index])) != 0) {
            ++index;
            ++digits;
        }
        if (digits == 0) {
            return false;
        }
        ++groups;
        if (index == wrapperId.size()) {
            break;
        }
        if (wrapperId[index] != '-') {
            return false;
        }
        ++index;
    }
    return groups == 5;
}

std::string canonicalizeSudoProofPath(const std::filesystem::path& path) {
    // weakly_canonical resolves symlinks of existing prefixes and normalizes
    // the rest; the proof spelling must be stable and comparable across runs.
    std::error_code ignored;
    std::filesystem::path resolved = std::filesystem::weakly_canonical(path, ignored);
    if (resolved.empty()) {
        resolved = path.lexically_normal();
    }
    return resolved.lexically_normal().string();
}

bool isCanonicalSudoProofPath(const std::string& value) {
    if (value.empty() || value.find('\0') != std::string::npos) {
        return false;
    }
    const std::filesystem::path path(value);
    if (!path.is_absolute()) {
        return false;
    }
    // Must already be in canonical spelling: a round trip must be a no-op.
    return path.lexically_normal().string() == value;
}

std::vector<SudoPhysicalLine> splitPhysicalLines(const std::string& content) {
    std::vector<SudoPhysicalLine> lines;
    std::size_t start = 0;
    while (start <= content.size()) {
        const std::size_t newline = content.find('\n', start);
        if (newline == std::string::npos) {
            SudoPhysicalLine line;
            line.text = content.substr(start);
            line.terminator.clear();
            if (!line.text.empty()) {
                lines.push_back(std::move(line));
            }
            return lines;
        }
        SudoPhysicalLine line;
        // A '\r' immediately before the '\n' belongs to the terminator, so a
        // CRLF file is neither split incorrectly nor silently rewritten.
        const std::size_t textEnd =
            newline > start && content[newline - 1] == '\r' ? newline - 1 : newline;
        line.text = content.substr(start, textEnd - start);
        line.terminator = content.substr(textEnd, newline - textEnd + 1);
        lines.push_back(std::move(line));
        start = newline + 1;
    }
    return lines;
}

std::string joinPhysicalLines(const std::vector<SudoPhysicalLine>& lines) {
    std::string content;
    for (const SudoPhysicalLine& line : lines) {
        content += line.text;
        content += line.terminator;
    }
    return content;
}

std::string suppressedEntryBytes(const std::vector<SudoPhysicalLine>& lines) {
    return joinPhysicalLines(lines);
}

// Explicit terminator provenance for a suppressed line.
//
// The wrapper FRAMING must always be well-formed comment lines terminated by
// LF. Otherwise a suppressed FINAL line that had no trailing newline would run
// physically into the END marker and corrupt a single comment line. The
// original terminator therefore cannot be recovered from the physical wrapper
// line and is encoded explicitly:
//
//     #@FIC_SUDO_DISABLED_LINE@eol=<lf|crlf|none>@<original content>
//
// The digest is still computed from the ORIGINAL bytes reconstructed from this
// metadata, never from the framing bytes, and a hand-edited eol value yields a
// digest mismatch (Conflict) rather than a silent normalization.
constexpr const char* kSudoLineEolPrefix = "eol=";

std::string encodeSudoLineEol(const std::string& terminator) {
    if (terminator == "\n") {
        return "lf";
    }
    if (terminator == "\r\n") {
        return "crlf";
    }
    if (terminator.empty()) {
        return "none";
    }
    return {}; // unsupported terminator: caller must fail closed
}

bool decodeSudoLineEol(const std::string& value, std::string& terminator) {
    if (value == "lf") {
        terminator = "\n";
        return true;
    }
    if (value == "crlf") {
        terminator = "\r\n";
        return true;
    }
    if (value == "none") {
        terminator.clear();
        return true;
    }
    return false;
}

std::string SudoDisabledWrapper::payloadDigest() const {
    return fic::core::ContentDigest::sha256Hex(
        suppressedEntryBytes(originalLines));
}
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
    const std::vector<SudoPhysicalLine>& lines,
    std::vector<SudoDisabledWrapper>& wrappers,
    std::string& error) {
    wrappers.clear();
    error.clear();

    bool inWrapper = false;
    SudoDisabledWrapper current;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        const SudoPhysicalLine& line = lines[index];
        const std::string& lineText = line.text;
        if (startsWith(lineText, kSudoDisabledBeginPrefix)) {
            if (inWrapper) {
                error = "вложенный FIC_SUDO_DISABLED_BEGIN в строке " +
                    std::to_string(index + 1);
                return SudoWrapperParseStatus::Malformed;
            }
            SudoDisabledWrapper wrapper;
            wrapper.beginLine = index;
            if (!parseWrapperMarker(lineText, kSudoDisabledBeginPrefix,
                                    wrapper.policy, wrapper.mutationId, error)) {
                return SudoWrapperParseStatus::Malformed;
            }
            inWrapper = true;
            current = std::move(wrapper);
            continue;
        }

        if (startsWith(lineText, kSudoDisabledEndPrefix)) {
            if (!inWrapper) {
                error = "FIC_SUDO_DISABLED_END без BEGIN в строке " +
                    std::to_string(index + 1);
                return SudoWrapperParseStatus::Malformed;
            }
            std::string endPolicy;
            std::string endMutation;
            if (!parseWrapperMarker(lineText, kSudoDisabledEndPrefix, endPolicy,
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
            if (!startsWith(lineText, kSudoDisabledLinePrefix)) {
                error = "не FIC-строка внутри FIC_SUDO_DISABLED блока: " +
                    lineText;
                return SudoWrapperParseStatus::Malformed;
            }
            const std::string body = lineText.substr(
                std::char_traits<char>::length(kSudoDisabledLinePrefix));
            if (!startsWith(body, kSudoLineEolPrefix)) {
                error = "FIC_SUDO_DISABLED_LINE без явного eol=метаданных: " +
                    lineText;
                return SudoWrapperParseStatus::Malformed;
            }
            const std::size_t valueStart =
                std::char_traits<char>::length(kSudoLineEolPrefix);
            const std::size_t at = body.find('@', valueStart);
            if (at == std::string::npos) {
                error = "FIC_SUDO_DISABLED_LINE без разделителя '@': " + lineText;
                return SudoWrapperParseStatus::Malformed;
            }
            SudoPhysicalLine original;
            // Everything after the metadata separator is the original content,
            // taken verbatim: it may itself contain spaces, '@' and '='.
            original.text = body.substr(at + 1);
            if (!decodeSudoLineEol(body.substr(valueStart, at - valueStart),
                                   original.terminator)) {
                error = "неизвестный eol=код в FIC_SUDO_DISABLED_LINE: " +
                    lineText;
                return SudoWrapperParseStatus::Malformed;
            }
            current.originalLines.push_back(std::move(original));
            continue;
        }

        if (startsWithIntroducer(lineText)) {
            error = "неизвестный FIC-маркер sudoers в строке " +
                std::to_string(index + 1) + ": " + lineText;
            return SudoWrapperParseStatus::Malformed;
        }
    }

    if (inWrapper) {
        error = "незакрытый FIC_SUDO_DISABLED блок " + current.mutationId;
        return SudoWrapperParseStatus::Malformed;
    }
    return SudoWrapperParseStatus::Ok;
}

void disableSudoEntry(std::vector<SudoPhysicalLine>& lines,
                      std::size_t firstLine,
                      std::size_t lineCount,
                      const std::string& policyName,
                      const std::string& mutationId) {
    const std::string begin = std::string(kSudoDisabledBeginPrefix) +
        "policy=" + policyName + " mutation=" + mutationId + "@";
    const std::string end = std::string(kSudoDisabledEndPrefix) +
        "policy=" + policyName + " mutation=" + mutationId + "@";

    const auto marker = [](const std::string& text) {
        SudoPhysicalLine line;
        line.text = text;
        // Wrapper FRAMING is always LF-terminated so that every wrapper line is
        // an independent, syntactically valid comment line even when the
        // suppressed entry ended at EOF without a newline.
        line.terminator = "\n";
        return line;
    };

    std::vector<SudoPhysicalLine> wrapper;
    wrapper.reserve(lineCount + 2);
    wrapper.push_back(marker(begin));
    for (std::size_t offset = 0; offset < lineCount; ++offset) {
        const SudoPhysicalLine& original = lines[firstLine + offset];
        const std::string eol = encodeSudoLineEol(original.terminator);
        SudoPhysicalLine line = marker(std::string(kSudoDisabledLinePrefix) +
                                      kSudoLineEolPrefix + eol + "@" +
                                      original.text);
        wrapper.push_back(std::move(line));
    }
    wrapper.push_back(marker(end));

    lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(firstLine),
                lines.begin() + static_cast<std::ptrdiff_t>(firstLine + lineCount));
    lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(firstLine),
                 wrapper.begin(), wrapper.end());
}

bool restoreSudoDisabledEntries(
    std::vector<SudoPhysicalLine>& lines,
    const std::filesystem::path& filePath,
    const std::string& policyName,
    const std::vector<SudoScopedDefaultsWrapperProof>& allowedProofs,
    bool& changed,
    std::string& error) {
    changed = false;
    std::vector<SudoDisabledWrapper> wrappers;
    if (parseSudoDisabledWrappers(lines, wrappers, error) !=
        SudoWrapperParseStatus::Ok) {
        error = "Не удалось разобрать FIC-маркеры sudoers: " + error;
        return false;
    }
    // Ownership is proven BEFORE anything is rewritten: an unproven or
    // drifted wrapper must leave the file completely untouched.
    const SudoWrapperProvenanceCheck check =
        checkSudoWrapperProvenance(wrappers, filePath, policyName, allowedProofs);
    if (!check.safeToRelease()) {
        error = describeSudoWrapperProvenance(check, policyName);
        return false;
    }
    for (std::size_t position = wrappers.size(); position-- > 0;) {
        const SudoDisabledWrapper& wrapper = wrappers[position];
        if (wrapper.policy != policyName) {
            continue;
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

bool restoreSelectedSudoDisabledEntries(
    std::vector<SudoPhysicalLine>& lines,
    const std::filesystem::path& filePath,
    const std::string& policyName,
    const std::vector<SudoScopedDefaultsWrapperProof>& allExpectedProofs,
    const std::vector<std::string>& selectedIdsToRestore,
    bool& changed,
    std::string& error) {
    changed = false;
    std::vector<SudoDisabledWrapper> wrappers;
    if (parseSudoDisabledWrappers(lines, wrappers, error) !=
        SudoWrapperParseStatus::Ok) {
        error = "Не удалось разобрать FIC-маркеры sudoers: " + error;
        return false;
    }
    // The ENTIRE current state is proven against the full target proof set
    // first: an unknown, orphan or drifted wrapper anywhere in this file makes
    // the selective rewind fail closed.
    const SudoWrapperProvenanceCheck check = checkSudoWrapperProvenance(
        wrappers, filePath, policyName, allExpectedProofs);
    if (!check.safeToRelease()) {
        error = describeSudoWrapperProvenance(check, policyName);
        return false;
    }
    std::set<std::string> selected(selectedIdsToRestore.begin(),
                                   selectedIdsToRestore.end());
    for (std::size_t position = wrappers.size(); position-- > 0;) {
        const SudoDisabledWrapper& wrapper = wrappers[position];
        if (wrapper.policy != policyName ||
            selected.find(wrapper.mutationId) == selected.end()) {
            continue;
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
    const std::filesystem::path& filePath,
    const std::string& policyName,
    const std::vector<SudoScopedDefaultsWrapperProof>& expectedProofs) {
    SudoWrapperProvenanceCheck check;
    // Keyed by wrapper id; the value is (canonical path, payload digest).
    std::map<std::string, std::pair<std::string, std::string>> payloadById;
    for (const SudoScopedDefaultsWrapperProof& proof : expectedProofs) {
        if (!payloadById.emplace(proof.wrapperId,
                                  std::make_pair(proof.canonicalPath,
                                                 proof.payloadDigest)).second) {
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
        const std::string& id = entry.first;
        if (entry.second > 1) {
            check.fileDuplicate = true;
        }
        const auto proven = payloadById.find(id);
        if (proven == payloadById.end()) {
            check.unknownIds.push_back(id);
            continue;
        }
        // The proof authorizes one EXACT file: an id proven for another
        // sudoers file proves nothing here.
        if (proven->second.first != canonicalizeSudoProofPath(filePath)) {
            check.unknownIds.push_back(id);
            continue;
        }
        // A proven id whose CURRENT payload differs from the recorded digest
        // is drift, not ownership: FIC must never activate content it did not
        // suppress.
        for (const SudoDisabledWrapper& wrapper : wrappers) {
            if (wrapper.policy == policyName && wrapper.mutationId == id &&
                wrapper.payloadDigest() != proven->second.second) {
                check.driftedIds.push_back(id);
                break;
            }
        }
    }
    for (const SudoScopedDefaultsWrapperProof& proof : expectedProofs) {
        if (fileCounts.find(proof.wrapperId) == fileCounts.end()) {
            check.releasedIds.push_back(proof.wrapperId);
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
    if (!check.driftedIds.empty()) {
        message += "; содержимое подавленных записей изменено после "
                   "применения (drift), id:";
        for (const std::string& id : check.driftedIds) {
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
