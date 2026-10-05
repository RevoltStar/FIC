#include "SudoersLogicalEntries.h"

#include <algorithm>
#include <cctype>

namespace fic::sudoers {
namespace {

std::string trimLogicalCopy(std::string value) {
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(),
                             [](unsigned char c) { return !std::isspace(c); }));
    value.erase(std::find_if(value.rbegin(), value.rend(),
                             [](unsigned char c) { return !std::isspace(c); })
                    .base(),
                value.end());
    return value;
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
    const std::vector<SudoPhysicalLine>& lines) {
    std::vector<SudoLogicalEntry> entries;
    std::size_t index = 0;
    while (index < lines.size()) {
        SudoLogicalEntry entry;
        entry.firstPhysicalLine = index;
        entry.lineCount = 1;
        entry.text = lines[index].text;
        // A trailing continuation on the LAST physical line is not continued
        // past the end of the file: the entry simply ends there.
        while (hasContinuation(entry.text) && index + 1 < lines.size()) {
            std::string trimmed = trimLogicalCopy(entry.text);
            trimmed.pop_back();
            entry.text = trimmed + " " + trimLogicalCopy(lines[++index].text);
            ++entry.lineCount;
        }
        entries.push_back(std::move(entry));
        ++index;
    }
    return entries;
}

} // namespace fic::sudoers
