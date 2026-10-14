#include "SudoersAuthenticationWrapper.h"
#include "SudoersAuthenticationGrammar.h"
#include <fic/core/integrity/ContentDigest.h>
#include <set>

namespace fic::sudoers {
namespace {
const std::string begin = "#@FIC_AUTH_BEGIN id=";
const std::string end = "#@FIC_AUTH_END id=";
const std::string originalPrefix = "#@FIC_AUTH_ORIGINAL eol=";
const std::string active = "#@FIC_AUTH_ACTIVE";
std::string digest(const std::string& value) { return fic::core::ContentDigest::sha256Hex(value); }
}
AuthenticationProof AuthenticationWrapper::proof(const std::filesystem::path& path) const {
    return {id, canonicalizeSudoProofPath(path), digest(original), digest(replacement)};
}
std::vector<SudoPhysicalLine> makeAuthenticationWrapper(const std::string& id,
    const std::string& original, const std::string& replacement) {
    std::vector<SudoPhysicalLine> result{{begin + id, "\n"}};
    for (const auto& line : splitPhysicalLines(original)) {
        std::string eol = line.terminator == "\n" ? "LF" : line.terminator == "\r\n" ? "CRLF" : "NONE";
        result.push_back({originalPrefix + eol + "@" + line.text, "\n"});
    }
    result.push_back({active, "\n"});
    auto replacementLines = splitPhysicalLines(replacement);
    // This separator belongs to the frame. The canonical active bytes are
    // independently derived from original eol metadata during parsing.
    if (!replacementLines.empty() && replacementLines.back().terminator.empty())
        replacementLines.back().terminator = "\n";
    result.insert(result.end(), replacementLines.begin(), replacementLines.end());
    result.push_back({end + id, "\n"});
    return result;
}
bool parseAuthenticationWrappers(const std::vector<SudoPhysicalLine>& lines,
    std::vector<AuthenticationWrapper>& wrappers, std::string& error) {
    wrappers.clear(); error.clear(); std::set<std::string> ids;
    for (std::size_t p = 0; p < lines.size(); ++p) {
        const auto first = lines[p].text.find_first_not_of(" \t\r");
        if (first == std::string::npos || lines[p].text.compare(first, 10, "#@FIC_AUTH") != 0) continue;
        if (first != 0) { error = "Non-canonical indented FIC_AUTH marker"; return false; }
        if (lines[p].text.rfind(begin, 0) != 0) { error = "Unknown FIC_AUTH marker"; return false; }
        AuthenticationWrapper wrapper;
        wrapper.first = p; wrapper.id = lines[p].text.substr(begin.size());
        if (!isCanonicalSudoWrapperId(wrapper.id) || !ids.insert(wrapper.id).second) {
            error = "Invalid or duplicate FIC_AUTH id"; return false;
        }
        auto current = p + 1;
        std::vector<SudoPhysicalLine> originals;
        while (current < lines.size() && lines[current].text.rfind(originalPrefix, 0) == 0) {
            const auto& body = lines[current].text;
            auto at = body.find('@', originalPrefix.size());
            if (at == std::string::npos) { error = "Missing original eol delimiter"; return false; }
            auto eol = body.substr(originalPrefix.size(), at - originalPrefix.size());
            if (eol != "LF" && eol != "CRLF" && eol != "NONE") { error = "Invalid original eol"; return false; }
            originals.push_back({body.substr(at + 1), eol == "LF" ? "\n" : eol == "CRLF" ? "\r\n" : ""});
            ++current;
        }
        if (originals.empty() || current >= lines.size() || lines[current].text != active) {
            error = "Incomplete FIC_AUTH original/active frame"; return false;
        }
        for (std::size_t i = 0; i + 1 < originals.size(); ++i)
            if (originals[i].terminator.empty()) { error = "Non-final original line has no terminator"; return false; }
        wrapper.original = joinPhysicalLines(originals);
        if (!authenticationReplacement(wrapper.original, wrapper.replacement, wrapper.scoped, error)) return false;
        const auto canonical = makeAuthenticationWrapper(wrapper.id, wrapper.original, wrapper.replacement);
        if (canonical.size() > lines.size() - p) { error = "Truncated FIC_AUTH frame"; return false; }
        for (std::size_t i = 0; i < canonical.size(); ++i) {
            if (canonical[i].text != lines[p + i].text || canonical[i].terminator != lines[p + i].terminator) {
                error = "FIC_AUTH frame differs from proven typed transformation"; return false;
            }
        }
        wrapper.last = p + canonical.size() - 1;
        wrappers.push_back(std::move(wrapper)); p += canonical.size() - 1;
    }
    return true;
}
}
