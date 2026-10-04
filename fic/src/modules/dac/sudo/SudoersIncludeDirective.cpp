#include "modules/dac/sudo/SudoersIncludeDirective.h"

#include <cctype>

namespace fic::sudoers {
namespace {

bool isSpace(char c) {
    return std::isspace(static_cast<unsigned char>(c)) != 0;
}

struct Keyword {
    std::string_view text;
    IncludeKind kind;
};

// Longest keyword first so "@includedir" wins over "@include".
constexpr Keyword kKeywords[] = {
    {"@includedir", IncludeKind::Directory},
    {"#includedir", IncludeKind::Directory},
    {"@include", IncludeKind::File},
    {"#include", IncludeKind::File},
};

// Matches a directive keyword at the start of the trimmed logical line. The
// keyword must be followed by whitespace or end of line, so "@includedir" is
// never read as "@include" + "dir".
bool detectDirective(std::string_view trimmed,
                     IncludeKind& kind,
                     std::size_t& argumentStart) {
    for (const Keyword& keyword : kKeywords) {
        if (trimmed.size() < keyword.text.size() ||
            trimmed.compare(0, keyword.text.size(), keyword.text) != 0) {
            continue;
        }
        const std::size_t after = keyword.text.size();
        if (trimmed.size() > after && !isSpace(trimmed[after])) {
            continue;
        }
        kind = keyword.kind;
        argumentStart = after;
        return true;
    }
    return false;
}

} // namespace

IncludeDirective parseIncludeDirective(std::string_view logicalLine) {
    IncludeDirective directive;

    std::size_t begin = 0;
    while (begin < logicalLine.size() && isSpace(logicalLine[begin])) {
        ++begin;
    }
    const std::string_view trimmed = logicalLine.substr(begin);

    IncludeKind kind = IncludeKind::None;
    std::size_t argumentStart = 0;
    if (!detectDirective(trimmed, kind, argumentStart)) {
        return directive;
    }

    std::size_t cursor = argumentStart;
    const auto skipSpace = [&]() {
        while (cursor < trimmed.size() && isSpace(trimmed[cursor])) {
            ++cursor;
        }
    };
    skipSpace();

    if (cursor >= trimmed.size()) {
        directive.kind = IncludeKind::Unsupported;
        directive.error = "директива include без пути";
        return directive;
    }

    std::string decoded;
    if (trimmed[cursor] == '"') {
        // Double-quoted pathname: whitespace needs no escaping, and the only
        // recognized escape inside the quotes is a backslash.
        ++cursor;
        bool closed = false;
        while (cursor < trimmed.size()) {
            const char c = trimmed[cursor];
            if (c == '\\') {
                if (cursor + 1 >= trimmed.size()) {
                    directive.kind = IncludeKind::Unsupported;
                    directive.error = "незавершённый escape в пути include";
                    return directive;
                }
                decoded.push_back(trimmed[cursor + 1]);
                cursor += 2;
                continue;
            }
            if (c == '"') {
                ++cursor;
                closed = true;
                break;
            }
            decoded.push_back(c);
            ++cursor;
        }
        if (!closed) {
            directive.kind = IncludeKind::Unsupported;
            directive.error = "незакрытая двойная кавычка в пути include";
            return directive;
        }
        if (decoded.empty()) {
            directive.kind = IncludeKind::Unsupported;
            directive.error = "пустой путь include в кавычках";
            return directive;
        }
    } else {
        // Unquoted pathname: whitespace ends the word unless backslash-escaped,
        // and an unquoted '#' starts a trailing comment.
        bool terminated = false;
        while (cursor < trimmed.size()) {
            const char c = trimmed[cursor];
            if (c == '\\') {
                if (cursor + 1 >= trimmed.size()) {
                    directive.kind = IncludeKind::Unsupported;
                    directive.error = "незавершённый escape в пути include";
                    return directive;
                }
                decoded.push_back(trimmed[cursor + 1]);
                cursor += 2;
                continue;
            }
            if (c == '#') {
                terminated = true;
                break;
            }
            if (isSpace(c)) {
                terminated = true;
                break;
            }
            decoded.push_back(c);
            ++cursor;
        }
        if (decoded.empty()) {
            directive.kind = IncludeKind::Unsupported;
            directive.error = "пустой путь include";
            return directive;
        }
        if (!terminated) {
            // The whole argument was consumed; nothing may follow but
            // whitespace/comment, which the checks below handle uniformly.
            skipSpace();
        }
    }

    skipSpace();
    if (cursor < trimmed.size() && trimmed[cursor] != '#') {
        directive.kind = IncludeKind::Unsupported;
        directive.error = "неожиданные символы после пути include";
        return directive;
    }

    directive.kind = kind;
    directive.path = std::move(decoded);
    return directive;
}

} // namespace fic::sudoers
