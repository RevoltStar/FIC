#include "modules/dac/sudo/SudoersIncludeDirective.h"

#include <cctype>

namespace fic::sudoers {
namespace {

bool isSpace(char c) {
    return std::isspace(static_cast<unsigned char>(c)) != 0;
}

bool isHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F');
}

int hexValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return c - 'A' + 10;
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

    // Upstream escape semantics, verified against sudo source
    // (plugins/sudoers/toke_util.c, identical in SUDO_1_9_13 and current):
    // both the unquoted <GOTINC> token and the quoted <INSTR> content are handed
    // to fill()/append(), which call copy_string() and COLLAPSE escapes:
    //   \xHH -> the hex byte,   \c -> c,   otherwise verbatim.
    // This is true for every sudo version FIC supports (debian-12/sudo 1.9.13
    // through current), so escaped whitespace in an unquoted include argument is
    // valid and unambiguous, and \" inside quotes is an escaped quote.
    const auto decode = [&trimmed](const std::string& raw,
                                   std::string& out) -> bool {
        out.clear();
        for (std::size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] != '\\' || i + 1 >= raw.size()) {
                out.push_back(raw[i]);
                continue;
            }
            if (raw[i + 1] == 'x' && i + 3 < raw.size() &&
                isHexDigit(raw[i + 2]) && isHexDigit(raw[i + 3])) {
                out.push_back(static_cast<char>(
                    (hexValue(raw[i + 2]) << 4) | hexValue(raw[i + 3])));
                i += 3;
                continue;
            }
            out.push_back(raw[++i]);
        }
        // A decoded pathname can never contain a line break: FIC fails closed
        // rather than opening a different file than sudo would.
        return out.find('\n') == std::string::npos &&
            out.find('\r') == std::string::npos;
    };

    std::string decoded;
    if (trimmed[cursor] == '"') {
        ++cursor;
        bool closed = false;
        std::string raw;
        while (cursor < trimmed.size()) {
            const char c = trimmed[cursor];
            // Upstream <INSTR> consumes '\\' and the following character as one
            // unit, so an escaped quote does not terminate the string;
            // copy_string() then collapses it to the bare character.
            if (c == '\\' && cursor + 1 < trimmed.size()) {
                raw.push_back(c);
                raw.push_back(trimmed[cursor + 1]);
                cursor += 2;
                continue;
            }
            if (c == '"') {
                ++cursor;
                closed = true;
                break;
            }
            raw.push_back(c);
            ++cursor;
        }
        if (!closed) {
            directive.kind = IncludeKind::Unsupported;
            directive.error = "незакрытая двойная кавычка в пути include";
            return directive;
        }
        if (!decode(raw, decoded)) {
            directive.kind = IncludeKind::Unsupported;
            directive.error = "недопустимый путь include в кавычках";
            return directive;
        }
        if (decoded.empty()) {
            directive.kind = IncludeKind::Unsupported;
            directive.error = "пустой путь include в кавычках";
            return directive;
        }
    } else {
        // Unquoted pathname. The upstream <GOTINC> token is
        //   [^"[:space:]]([^[:space:]]|\\[[:blank:]])*
        // so an ESCAPED blank is part of the token: a backslash always consumes
        // the following character, including a blank.
        std::string raw;
        while (cursor < trimmed.size()) {
            const char c = trimmed[cursor];
            if (c == '\\') {
                raw.push_back(c);
                ++cursor;
                if (cursor < trimmed.size()) {
                    raw.push_back(trimmed[cursor]);
                    ++cursor;
                }
                continue;
            }
            if (isSpace(c) || c == '#') {
                break;
            }
            raw.push_back(c);
            ++cursor;
        }
        if (!decode(raw, decoded)) {
            directive.kind = IncludeKind::Unsupported;
            directive.error = "недопустимый путь include";
            return directive;
        }
        if (decoded.empty()) {
            directive.kind = IncludeKind::Unsupported;
            directive.error = "пустой путь include";
            return directive;
        }
    }

    // Nothing but whitespace/comment may follow the pathname argument.
    while (cursor < trimmed.size() && isSpace(trimmed[cursor])) {
        ++cursor;
    }
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
