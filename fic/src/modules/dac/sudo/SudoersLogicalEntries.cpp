#include "SudoersLogicalEntries.h"

#include <algorithm>
#include <cctype>
#include <utility>

namespace fic::sudoers {
namespace {

std::pair<std::size_t, std::size_t> trimBounds(const std::string& value) {
    std::size_t first = 0, last = value.size();
    while (first < last && std::isspace(static_cast<unsigned char>(value[first]))) ++first;
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
    return {first, last};
}

std::string trimLogicalCopy(const std::string& value) {
    const auto [first, last] = trimBounds(value);
    return value.substr(first, last - first);
}

// An ODD number of trailing backslashes means the line is continued: an even
// count is an escaped backslash, which terminates the logical line.
bool hasContinuation(const std::string& line) {
    const std::string trimmed = trimLogicalCopy(line);
    if (trimmed.empty() || trimmed.back() != '\\') {
        return false;
    }
    std::size_t slashCount = 0;
    for (std::size_t i = trimmed.size(); i > 0 && trimmed[i - 1] == '\\'; --i) {
        ++slashCount;
    }
    return slashCount % 2 == 1;
}

} // namespace

std::vector<SudoLogicalEntry> assembleSudoLogicalEntries(
    const std::vector<SudoPhysicalLine>& lines, bool withSourcePositions) {
    std::vector<SudoLogicalEntry> entries;
    std::size_t index = 0;
    while (index < lines.size()) {
        SudoLogicalEntry entry;
        entry.firstPhysicalLine = index;
        entry.lineCount = 1;
        entry.text = lines[index].text;
        if (withSourcePositions) {
            for (std::size_t column = 0; column < entry.text.size(); ++column)
                entry.sourcePositions.push_back({index, column});
        }
        // A trailing continuation on the LAST physical line is not continued
        // past the end of the file: the entry simply ends there.
        while (hasContinuation(entry.text) && index + 1 < lines.size()) {
            const auto [first, last] = trimBounds(entry.text);
            std::string trimmed = entry.text.substr(first, last - first);
            trimmed.pop_back();
            if (withSourcePositions) {
                entry.sourcePositions = std::vector<SudoLogicalEntry::SourcePosition>(
                    entry.sourcePositions.begin() + first,
                    entry.sourcePositions.begin() + last - 1);
                entry.sourcePositions.push_back({});
            }
            const auto [nextFirst, nextLast] = trimBounds(lines[++index].text);
            entry.text = trimmed + " " + lines[index].text.substr(nextFirst, nextLast - nextFirst);
            if (withSourcePositions) {
                for (std::size_t column = nextFirst; column < nextLast; ++column)
                    entry.sourcePositions.push_back({index, column});
            }
            ++entry.lineCount;
        }
        entries.push_back(std::move(entry));
        ++index;
    }
    return entries;
}

bool replaceSudoLogicalTokens(const SudoLogicalEntry& entry,
                              const std::vector<SudoTokenReplacement>& edits,
                              std::vector<SudoPhysicalLine>& lines,
                              std::string& error) {
    error.clear();
    auto reject = [&](const char* reason) { error = reason; return false; };
    if (entry.sourcePositions.size() != entry.text.size())
        return reject("Missing physical source coordinates");
    auto ordered = edits;
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
        return a.logicalOffset < b.logicalOffset;
    });
    std::size_t previousEnd = 0;
    for (const auto& edit : ordered) {
        if (edit.expected.empty() || edit.logicalOffset > entry.text.size() ||
            edit.expected.size() > entry.text.size() - edit.logicalOffset ||
            edit.logicalOffset < previousEnd ||
            entry.text.compare(edit.logicalOffset, edit.expected.size(), edit.expected) != 0)
            return reject("Invalid or overlapping logical token replacement");
        if (edit.replacement.find_first_of("\r\n") != std::string::npos)
            return reject("Token replacement contains a line terminator");
        const auto first = entry.sourcePositions[edit.logicalOffset];
        if (!first.isPhysical() || first.physicalLine >= lines.size())
            return reject("Token has no physical source");
        for (std::size_t index = 0; index < edit.expected.size(); ++index) {
            const auto source = entry.sourcePositions[edit.logicalOffset + index];
            if (!source.isPhysical() || source.physicalLine != first.physicalLine ||
                source.column != first.column + index)
                return reject("Token crosses a continuation boundary");
        }
        const auto& physical = lines[first.physicalLine].text;
        if (first.column > physical.size() || edit.expected.size() > physical.size() - first.column ||
            physical.compare(first.column, edit.expected.size(), edit.expected) != 0)
            return reject("Physical token snapshot changed");
        previousEnd = edit.logicalOffset + edit.expected.size();
    }
    auto updated = lines;
    for (auto it = ordered.rbegin(); it != ordered.rend(); ++it) {
        const auto source = entry.sourcePositions[it->logicalOffset];
        updated[source.physicalLine].text.replace(source.column, it->expected.size(), it->replacement);
    }
    lines.swap(updated);
    return true;
}

} // namespace fic::sudoers
