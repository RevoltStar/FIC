#include "SudoersAuthenticationGrammar.h"
#include "SudoersScopedDefaults.h"
#include <algorithm>
#include <cctype>
#include <set>

namespace fic::sudoers {
namespace {
bool space(char c) { return std::isspace(static_cast<unsigned char>(c)); }
std::size_t skip(const std::string& s, std::size_t p) {
    while (p < s.size() && space(s[p])) ++p;
    return p;
}
std::string trim(const std::string& s) {
    auto a = skip(s, 0), b = s.size();
    while (b > a && space(s[b - 1])) --b;
    return s.substr(a, b - a);
}
// Only double quotes are admitted by this subset. Single quotes are refused
// rather than incorrectly treated as shell quoting in sudoers syntax.
bool delimiters(const std::string& s, std::size_t start, char delimiter,
                std::vector<std::size_t>& positions, std::size_t& end,
                std::string& error) {
    bool quoted = false, escaped = false;
    int depth = 0;
    end = s.size();
    for (auto p = start; p < s.size(); ++p) {
        char c = s[p];
        if (escaped) { escaped = false; continue; }
        if (c == '\\') { escaped = true; continue; }
        if (c == '\'') { error = "Unsupported single-quote sudoers syntax"; return false; }
        if (c == '"') { quoted = !quoted; continue; }
        if (quoted) continue;
        if (c == '#' && !(p + 1 < s.size() && std::isdigit(static_cast<unsigned char>(s[p + 1])))) {
            end = p; break;
        }
        if (c == '(') {
            auto previous = p;
            while (previous > start && space(s[previous - 1])) --previous;
            if (depth != 0 || (previous > start && s[previous - 1] != '=' && s[previous - 1] != ',')) {
                error = "Unsupported unquoted parenthesis outside leading Runas_Spec"; return false;
            }
            ++depth;
        }
        if (c == ')' && --depth < 0) { error = "Unbalanced Runas_Spec"; return false; }
        if (depth == 0 && c == delimiter) positions.push_back(p);
    }
    if (quoted || escaped || depth != 0) { error = "Unterminated sudoers token"; return false; }
    return true;
}
const std::set<std::string> tags = {"NOPASSWD", "PASSWD", "NOEXEC", "EXEC",
    "INTERCEPT", "NOINTERCEPT", "SETENV", "NOSETENV", "LOG_INPUT", "NOLOG_INPUT",
    "LOG_OUTPUT", "NOLOG_OUTPUT", "FOLLOW", "NOFOLLOW", "MAIL", "NOMAIL"};
const std::set<std::string> options = {"CWD", "CHROOT", "TIMEOUT", "NOTBEFORE",
    "NOTAFTER", "ROLE", "TYPE", "APPARMOR_PROFILE", "PRIVS", "LIMITPRIVS"};
}

bool parseAuthenticationRule(const SudoLogicalEntry& entry,
                             AuthenticationRule& result, std::string& error) {
    result = {}; error.clear();
    const auto& s = entry.text;
    auto p = skip(s, 0);
    if (p == s.size()) return true;
    for (const auto* directive : {"@include", "@includedir", "#include", "#includedir"}) {
        const auto length = std::char_traits<char>::length(directive);
        if (s.compare(p, length, directive) == 0 && p + length < s.size() && space(s[p + length])) {
            result.kind = AuthenticationStatement::Include; return true;
        }
    }
    if (s[p] == '#' && !(p + 1 < s.size() && std::isdigit(static_cast<unsigned char>(s[p + 1])))) return true;
    for (const auto* prefix : {"User_Alias", "Host_Alias", "Runas_Alias", "Cmnd_Alias"}) {
        const auto length = std::char_traits<char>::length(prefix);
        if (s.compare(p, length, prefix) == 0 && p + length < s.size() && space(s[p + length])) {
            result.kind = AuthenticationStatement::Alias;
            // Native grammar validates alias definitions. Authentication tags
            // are not legal inside aliases; do not reinterpret their arguments.
            return true;
        }
    }
    if (s.compare(p, 8, "Defaults") == 0 &&
        (p + 8 == s.size() || space(s[p + 8]) || std::string(":@>!").find(s[p + 8]) != std::string::npos)) {
        result.kind = AuthenticationStatement::Defaults;
        result.scopedDefaults = !scopedDefaultsScope(s).empty();
        p += 8;
        if (result.scopedDefaults) {
            ++p;
            bool escaped = false, quoted = false;
            for (; p < s.size(); ++p) {
                if (escaped) { escaped = false; continue; }
                if (s[p] == '\\') { escaped = true; continue; }
                if (s[p] == '"') quoted = !quoted;
                if (!quoted && space(s[p])) break;
            }
        }
        p = skip(s, p);
        std::vector<std::size_t> commas; std::size_t end;
        if (!delimiters(s, p, ',', commas, end, error)) return false;
        commas.push_back(end);
        for (auto stop : commas) {
            auto first = skip(s, p), last = stop;
            while (last > first && space(s[last - 1])) --last;
            auto option = s.substr(first, last - first);
            if (option == "!authenticate") result.edits.push_back({first, option, "authenticate"});
            else if (option.find("authenticate") != std::string::npos && option != "authenticate") {
                // A value containing the word is data, but a malformed flag
                // spelling cannot be promoted to a proven unary flag.
                auto equals = option.find('=');
                if (equals == std::string::npos) { error = "Ambiguous authenticate Defaults option"; return false; }
            }
            p = stop + 1;
        }
        return true;
    }
    result.kind = AuthenticationStatement::UserSpec;
    std::vector<std::size_t> equals; std::size_t end;
    if (!delimiters(s, p, '=', equals, end, error) || equals.empty()) {
        if (error.empty()) error = "Unsupported User_Spec without Host_Spec";
        return false;
    }
    auto head = trim(s.substr(p, equals.front() - p));
    // User and host lists cannot be collapsed or guessed. A comma adjacent to
    // the separation makes a whitespace-containing list ambiguous here.
    auto separator = head.find_first_of(" \t");
    if (separator == std::string::npos) { error = "Missing User_List or Host_List"; return false; }
    result.users = head.substr(0, separator);
    result.hosts = trim(head.substr(separator));
    if (result.users.back() == ',' || result.hosts.empty() ||
        result.hosts.find_first_of(" \t") != std::string::npos) {
        error = "Unsupported ambiguous User_List/Host_List whitespace"; return false;
    }
    p = equals.front() + 1;
    std::vector<std::size_t> commas;
    if (!delimiters(s, p, ',', commas, end, error)) return false;
    commas.push_back(end);
    bool requiresPassword = true;
    std::string inheritedRunas;
    for (auto stop : commas) {
        auto cursor = skip(s, p);
        AuthenticationCommand command;
        if (cursor < stop && s[cursor] == '(') {
            auto close = s.find(')', cursor);
            if (close == std::string::npos || close >= stop || s.find('(', cursor + 1) < close) {
                error = "Unsupported nested Runas_Spec"; return false;
            }
            inheritedRunas = s.substr(cursor, close - cursor + 1);
            cursor = skip(s, close + 1);
        }
        command.runas = inheritedRunas;
        while (cursor < stop) {
            auto tokenEnd = cursor;
            while (tokenEnd < stop && (std::isalnum(static_cast<unsigned char>(s[tokenEnd])) || s[tokenEnd] == '_')) ++tokenEnd;
            auto name = s.substr(cursor, tokenEnd - cursor);
            auto next = skip(s, tokenEnd);
            if (next < stop && s[next] == ':' && !name.empty()) {
                if (!tags.count(name)) { error = "Unsupported command tag or digest: " + name; return false; }
                command.tags.push_back(name);
                if (name == "NOPASSWD") {
                    requiresPassword = false;
                    result.edits.push_back({cursor, name, "PASSWD"});
                } else if (name == "PASSWD") requiresPassword = true;
                cursor = skip(s, next + 1); continue;
            }
            if (next < stop && s[next] == '=' && !name.empty()) {
                if (!options.count(name)) { error = "Unsupported command option: " + name; return false; }
                cursor = skip(s, next + 1);
                if (cursor == stop) { error = "Missing command option value"; return false; }
                if (s[cursor] == '"') {
                    ++cursor; bool escaped = false, closed = false;
                    for (; cursor < stop; ++cursor) {
                        if (escaped) { escaped = false; continue; }
                        if (s[cursor] == '\\') { escaped = true; continue; }
                        if (s[cursor] == '"') { ++cursor; closed = true; break; }
                    }
                    if (!closed) { error = "Unterminated command option value"; return false; }
                } else while (cursor < stop && !space(s[cursor])) ++cursor;
                cursor = skip(s, cursor); continue;
            }
            break;
        }
        command.passwordRequired = requiresPassword;
        command.commandAndArguments = trim(s.substr(cursor, stop - cursor));
        auto cmd = command.commandAndArguments;
        if (!cmd.empty() && cmd[0] == '!') cmd.erase(0, 1);
        if (cmd.empty()) { error = "Empty Cmnd_Spec"; return false; }
        // An unescaped colon outside quotes could delimit another Host_Spec.
        std::vector<std::size_t> colons; std::size_t commandEnd;
        if (!delimiters(cmd, 0, ':', colons, commandEnd, error) || !colons.empty()) {
            if (error.empty()) error = "Unsupported additional Host_Spec or command colon";
            return false;
        }
        if (cmd[0] != '/' && cmd != "ALL" && cmd.rfind("sudoedit", 0) != 0 &&
            !(std::all_of(cmd.begin(), cmd.end(), [](unsigned char c) { return std::isupper(c) || std::isdigit(c) || c == '_'; }))) {
            error = "Unsupported command path or alias"; return false;
        }
        result.commands.push_back(std::move(command));
        p = stop + 1;
    }
    return true;
}

bool authenticationReplacement(const std::string& original, std::string& replacement,
                               bool& scoped, std::string& error) {
    auto lines = splitPhysicalLines(original);
    auto entries = assembleSudoLogicalEntries(lines, true);
    if (entries.size() != 1) { error = "Authentication wrapper must contain one logical entry"; return false; }
    AuthenticationRule rule;
    if (!parseAuthenticationRule(entries.front(), rule, error)) return false;
    scoped = rule.scopedDefaults;
    if (rule.edits.empty()) { error = "Authentication wrapper has no authentication mutation"; return false; }
    if (!replaceSudoLogicalTokens(entries.front(), rule.edits, lines, error)) return false;
    replacement = joinPhysicalLines(lines);
    return true;
}
}
