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
        // Quoted pathname. Upstream (<INSTR> in toke.l + expand_include() in
        // sudoers.c) applies NO C-style unescaping here: the content between
        // the quotes is taken VERBATIM and expand_include() only strips the
        // surrounding quotes. A backslash inside the quotes therefore does not
        // escape anything -- the single effect of \" is that it does not
        // terminate the string (and both characters are kept).
        // Decoding "\X -> X" here would make FIC open a DIFFERENT file than
        // sudo opens, so the content is copied unchanged.
        ++cursor;
        bool closed = false;
        while (cursor < trimmed.size()) {
            const char c = trimmed[cursor];
            if (c == '\\' && cursor + 1 < trimmed.size() &&
                trimmed[cursor + 1] == '"') {
                decoded.push_back('\\');
                decoded.push_back('"');
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
        // Nothing but whitespace/comment may follow the closing quote.
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

    // Unquoted pathname.
    //
    // A backslash in an UNQUOTED include argument is deliberately rejected.
    // Upstream keeps the token verbatim (fill() copies it unchanged), so whether
    // `\ ` denotes an escaped blank or a literal backslash depends on the
    // deployed sudo build, while sudoers(5) documents the escaped-blank form.
    // FIC cannot prove which pathname the deployed sudo will open, and
    // guessing wrong means reading a file sudo never reads. Explicit
    // fail-closed is the safe answer; the quoted form is unambiguous.
    for (std::size_t index = cursor; index < trimmed.size(); ++index) {
        if (trimmed[index] == '\\') {
            directive.kind = IncludeKind::Unsupported;
            directive.error =
                "экранирование обратным слэшем в некавыченном пути include "
                "не поддерживается: используйте кавычки (\"path with spaces\")";
            return directive;
        }
    }

    // Unquoted: whitespace ends the word, an unquoted '#' starts a comment.
    while (cursor < trimmed.size()) {
        const char c = trimmed[cursor];
        if (c == '#' || isSpace(c)) {
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
    // Only whitespace/comment may follow the pathname argument.
    while (cursor < trimmed.size() && isSpace(trimmed[cursor])) {
        ++cursor;
    }
    if (cursor < trimmed.size() && trimmed[cursor] != '#') {
        directive.kind = IncludeKind::Unsupported;
        directive.error = "неожиданные символы после пути include";
        return directive;
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
