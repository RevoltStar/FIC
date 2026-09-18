#include "modules/oss/grub/GrubManagedBlock.h"

#include <algorithm>

namespace {

// Strips CR/LF line endings and trailing spaces/tabs (never leading ones:
// marker grammar requires the marker at the start of the line).
std::string lineContent(const std::string& physicalLine) {
    std::string line = physicalLine;
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.pop_back();
    }
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
        line.pop_back();
    }
    return line;
}

// Strips only the physical CR/LF line boundary: canonical-strict grammar
// of the block body must see any trailing whitespace and fail closed.
std::string physicalLineContent(const std::string& physicalLine) {
    std::string line = physicalLine;
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.pop_back();
    }
    return line;
}

std::vector<std::string> physicalLines(const std::string& content) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < content.size()) {
        const size_t newline = content.find('\n', start);
        if (newline == std::string::npos) {
            lines.push_back(content.substr(start));
            return lines;
        }
        lines.push_back(content.substr(start, newline - start + 1));
        start = newline + 1;
    }
    return lines;
}

bool mentionsMarkerKeyword(const std::string& line) {
    return line.find("FIC_GRUB_BLOCK_BEGIN") != std::string::npos ||
        line.find("FIC_GRUB_BLOCK_END") != std::string::npos;
}

// Parses one canonical block body line: KEY="value" with a whitelisted key.
// Grammar is canonical-strict: the line must be EXACTLY the serialization
// format FIC renders — no whitespace around '=', no leading/trailing
// whitespace, no inline comments, no unquoted RHS. Anything deviating from
// the canonical form is fail-closed (the block was edited externally).
bool parseBlockAssignment(const std::string& line,
                          std::pair<std::string, std::string>& entry,
                          std::string& error) {
    const size_t equals = line.find('=');
    if (equals == std::string::npos) {
        error = "строка внутри FIC GRUB managed block не является "
                "canonical assignment: " + line;
        return false;
    }
    // Canonical key: no leading/trailing whitespace allowed.
    const std::string key = line.substr(0, equals);
    if (!isGrubManagedKey(key)) {
        error = "недопустимый ключ внутри FIC GRUB managed block: " + key;
        return false;
    }
    // Canonical RHS: starts immediately after '=' and must be exactly
    // key + "=" + encodeGrubManagedValue(decoded) — no surrounding
    // whitespace, no inline comments after the closing quote.
    const std::string literal = line.substr(equals + 1);
    std::string value;
    if (!decodeGrubManagedValue(literal, value, error)) {
        return false;
    }
    if (line != key + "=" + encodeGrubManagedValue(value)) {
        error = "неканоническое присваивание внутри FIC GRUB managed block: " +
            line;
        return false;
    }
    entry = {key, std::move(value)};
    return true;
}

} // namespace

std::string encodeGrubManagedValue(const std::string& value) {
    std::string quoted = "\"";
    for (const char ch : value) {
        if (ch == '\\' || ch == '"' || ch == '$' || ch == '`') {
            quoted.push_back('\\');
        }
        quoted.push_back(ch);
    }
    quoted.push_back('"');
    return quoted;
}

bool decodeGrubManagedValue(const std::string& text,
                            std::string& value,
                            std::string& error) {
    value.clear();
    if (text.size() < 2 || text.front() != '"' || text.back() != '"') {
        error = "значение FIC GRUB managed block должно быть double-quoted "
                "литералом";
        return false;
    }
    for (std::size_t index = 1; index + 1 < text.size(); ++index) {
        const char ch = text[index];
        if (ch == '\r' || ch == '\n' || ch == '\0') {
            error = "значение FIC GRUB managed block содержит запрещённый "
                    "символ CR/LF/NUL";
            return false;
        }
        if (ch == '$' || ch == '`') {
            error = "динамические shell-выражения запрещены внутри FIC GRUB "
                    "managed block";
            return false;
        }
        if (ch != '\\') {
            value.push_back(ch);
            continue;
        }
        if (index + 2 >= text.size()) {
            error = "незавершённая escape-последовательность внутри FIC GRUB "
                    "managed block";
            return false;
        }
        const char escaped = text[++index];
        if (escaped != '"' && escaped != '\\' &&
            escaped != '$' && escaped != '`') {
            error = "неподдерживаемая escape-последовательность внутри FIC "
                    "GRUB managed block";
            return false;
        }
        value.push_back(escaped);
    }
    return true;
}

GrubBlockParseResult parseGrubManagedBlock(const std::string& content) {
    GrubBlockParseResult result;
    const std::vector<std::string> lines = physicalLines(content);

    std::size_t beginIndex = std::string::npos;
    std::size_t endIndex = std::string::npos;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        const std::string line = lineContent(lines[index]);
        if (line == kGrubBlockBeginMarker) {
            if (beginIndex != std::string::npos) {
                result.error = "дублированный FIC GRUB managed block";
                return result;
            }
            if (endIndex != std::string::npos) {
                result.error = "FIC GRUB managed BEGIN после END";
                return result;
            }
            beginIndex = index;
            continue;
        }
        if (line == kGrubBlockEndMarker) {
            if (beginIndex == std::string::npos) {
                result.error = "FIC GRUB managed END без BEGIN";
                return result;
            }
            endIndex = index;
            continue;
        }
        // Any OTHER line mentioning the marker keywords is a foreign
        // FIC-like malformed marker: fail closed, never interpret it.
        // (Marker-keyword lines inside the block are rejected below as
        // comment-like block lines; here only foreign lines are classified.)
        if (mentionsMarkerKeyword(line) &&
            !(beginIndex != std::string::npos &&
              endIndex == std::string::npos)) {
            result.error = "foreign FIC-подобный malformed marker в shared "
                           "GRUB defaults: " + line;
            return result;
        }
    }

    if (beginIndex != std::string::npos && endIndex == std::string::npos) {
        result.error = "FIC GRUB managed block не закрыт маркером END";
        return result;
    }

    GrubBlockEntries entries;
    if (beginIndex != std::string::npos) {
        result.view.present = true;
        for (std::size_t index = beginIndex + 1; index < endIndex; ++index) {
            // Canonical-strict: the block body line is passed with only the
            // physical CR/LF boundary stripped; parseBlockAssignment
            // rejects any leading/trailing whitespace itself.
            const std::string line = physicalLineContent(lines[index]);
            if (line.empty()) {
                result.error = "пустая строка внутри FIC GRUB managed block";
                return result;
            }
            if (line.front() == '#' || mentionsMarkerKeyword(line)) {
                result.error = "комментарии и маркеры внутри FIC GRUB "
                               "managed block не допускаются: " + line;
                return result;
            }
            std::pair<std::string, std::string> entry;
            if (!parseBlockAssignment(line, entry, result.error)) {
                return result;
            }
            if (std::any_of(
                    entries.begin(), entries.end(),
                    [&entry](const GrubBlockEntries::value_type& existing) {
                        return existing.first == entry.first;
                    })) {
                result.error = "дублированный ключ внутри FIC GRUB managed "
                               "block: " + entry.first;
                return result;
            }
            entries.push_back(std::move(entry));
        }
        // Canonical order for stable comparisons and rendering.
        std::stable_sort(
            entries.begin(), entries.end(),
            [](const GrubBlockEntries::value_type& left,
               const GrubBlockEntries::value_type& right) {
                return grubManagedKeyOrder(left.first) <
                    grubManagedKeyOrder(right.first);
            });
    }

    result.ok = true;
    result.view.entries = std::move(entries);
    return result;
}

namespace {

// Foreign bytes = everything except the proven block, in the original order.
// The newline immediately before a BEGIN marker that sits at EOF is the
// FIC-owned serialization separator (assembleAtEof always appends exactly one
// for a non-empty foreign area), so it is stripped on decode. This makes
// foreign bytes survive apply -> rewrite -> removal byte-exact, including
// foreign content that does not end with a newline. When the block is NOT at
// EOF (foreign bytes were appended after it), the separator position is no
// longer identifiable, so nothing is stripped and foreign bytes are kept
// verbatim.
std::string foreignBytes(const std::vector<std::string>& lines,
                         std::size_t beginIndex,
                         std::size_t endIndex) {
    if (beginIndex == std::string::npos) {
        std::string whole;
        for (const std::string& line : lines) {
            whole += line;
        }
        return whole;
    }
    std::string before;
    for (std::size_t index = 0; index < beginIndex; ++index) {
        before += lines[index];
    }
    const bool blockAtEof = endIndex + 1 == lines.size();
    if (blockAtEof && !before.empty() && before.back() == '\n') {
        before.pop_back();
    }
    std::string after;
    for (std::size_t index = endIndex + 1; index < lines.size(); ++index) {
        after += lines[index];
    }
    return before + after;
}

// Joins foreign bytes with the block at EOF. The newline separating the
// foreign area from the block is FIC-owned serialization: it is ALWAYS
// appended for a non-empty foreign area (even when the foreign content
// already ends with a newline), so the exact pre-apply foreign bytes are
// recoverable on decode by stripping exactly that one separator newline.
std::string assembleAtEof(const std::string& foreign,
                          const std::string& block) {
    std::string content = foreign;
    if (!content.empty()) {
        content.push_back('\n');
    }
    content += block;
    return content;
}

std::string renderBlock(const GrubBlockEntries& entries) {
    std::string block;
    block += kGrubBlockBeginMarker;
    block.push_back('\n');
    for (const GrubBlockEntries::value_type& entry : entries) {
        block += entry.first;
        block.push_back('=');
        block += encodeGrubManagedValue(entry.second);
        block.push_back('\n');
    }
    block += kGrubBlockEndMarker;
    block.push_back('\n');
    return block;
}

void findBlockIndices(const std::string& content,
                      std::size_t& beginIndex,
                      std::size_t& endIndex) {
    beginIndex = std::string::npos;
    endIndex = std::string::npos;
    const std::vector<std::string> lines = physicalLines(content);
    for (std::size_t index = 0; index < lines.size(); ++index) {
        const std::string line = lineContent(lines[index]);
        if (line == kGrubBlockBeginMarker) beginIndex = index;
        else if (line == kGrubBlockEndMarker) endIndex = index;
    }
}

// Canonical block rewrite: all foreign bytes (before and after the previous
// block, in the original order) are preserved byte-exact, the canonical
// block is placed at EOF. This transparently relocates a block that is no
// longer at EOF.
GrubBlockMutationResult rewriteEntries(const std::string& content,
                                       const GrubBlockEntries& entries) {
    GrubBlockMutationResult result;
    std::size_t beginIndex = std::string::npos;
    std::size_t endIndex = std::string::npos;
    findBlockIndices(content, beginIndex, endIndex);
    const std::vector<std::string> lines = physicalLines(content);
    const std::string foreign =
        foreignBytes(lines, beginIndex, endIndex);
    result.content = assembleAtEof(foreign, renderBlock(entries));
    result.ok = true;
    return result;
}

} // namespace

GrubBlockMutationResult setGrubManagedBlockValue(
    const std::string& content,
    const std::string& key,
    const std::string& value) {
    GrubBlockMutationResult result;
    if (!isGrubManagedKey(key)) {
        result.error = "недопустимый ключ FIC GRUB managed block: " + key;
        return result;
    }
    if (value.find_first_of("\r\n") != std::string::npos ||
        value.find('\0') != std::string::npos) {
        result.error = "значение FIC GRUB managed block содержит запрещённые "
                       "символы CR/LF/NUL";
        return result;
    }
    const GrubBlockParseResult parse = parseGrubManagedBlock(content);
    if (!parse.ok) {
        result.error = parse.error;
        return result;
    }

    GrubBlockEntries entries = parse.view.entries;
    bool replaced = false;
    for (GrubBlockEntries::value_type& entry : entries) {
        if (entry.first == key) {
            entry.second = value;
            replaced = true;
        }
    }
    if (!replaced) {
        entries.emplace_back(key, value);
        std::stable_sort(
            entries.begin(), entries.end(),
            [](const GrubBlockEntries::value_type& left,
               const GrubBlockEntries::value_type& right) {
                return grubManagedKeyOrder(left.first) <
                    grubManagedKeyOrder(right.first);
            });
    }
    return rewriteEntries(content, entries);
}

GrubBlockMutationResult removeGrubManagedBlockValue(
    const std::string& content,
    const std::string& key) {
    GrubBlockMutationResult result;
    if (!isGrubManagedKey(key)) {
        result.error = "недопустимый ключ FIC GRUB managed block: " + key;
        return result;
    }
    const GrubBlockParseResult parse = parseGrubManagedBlock(content);
    if (!parse.ok) {
        result.error = parse.error;
        return result;
    }
    if (!parse.view.present) {
        // No block: ownership already released, content unchanged.
        result.ok = true;
        result.content = content;
        return result;
    }
    bool removed = false;
    GrubBlockEntries entries;
    GrubBlockEntries existing = parse.view.entries;
    for (GrubBlockEntries::value_type& entry : existing) {
        if (entry.first == key) {
            removed = true;
            continue;
        }
        entries.push_back(std::move(entry));
    }
    if (!removed) {
        result.ok = true;
        result.content = content;
        return result;
    }
    if (entries.empty()) {
        // Remove the whole block: never leave an empty BEGIN/END artifact.
        std::size_t beginIndex = std::string::npos;
        std::size_t endIndex = std::string::npos;
        findBlockIndices(content, beginIndex, endIndex);
        const std::vector<std::string> lines = physicalLines(content);
        result.ok = true;
        result.content = foreignBytes(lines, beginIndex, endIndex);
        return result;
    }
    return rewriteEntries(content, entries);
}
