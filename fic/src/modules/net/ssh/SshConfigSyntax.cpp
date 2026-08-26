#include "modules/net/ssh/SshConfigSyntax.h"

#include <algorithm>
#include <cctype>
#include <utility>

namespace {

bool tokenizeArguments(const std::string& text,
                       std::vector<std::string>& arguments,
                       std::string& error) {
    arguments.clear();
    std::string argument;
    bool argumentStarted = false;
    bool escaped = false;
    char quote = '\0';

    for (char character : text) {
        if (escaped) {
            argument += character;
            argumentStarted = true;
            escaped = false;
            continue;
        }
        if (character == '\\' && quote != '\'') {
            escaped = true;
            argumentStarted = true;
            continue;
        }
        if (quote != '\0') {
            if (character == quote) {
                quote = '\0';
            } else {
                argument += character;
            }
            argumentStarted = true;
            continue;
        }
        if (character == '\'' || character == '"') {
            quote = character;
            argumentStarted = true;
            continue;
        }
        if (character == '#') {
            break;
        }
        if (std::isspace(static_cast<unsigned char>(character))) {
            if (argumentStarted) {
                arguments.push_back(std::move(argument));
                argument.clear();
                argumentStarted = false;
            }
            continue;
        }
        argument += character;
        argumentStarted = true;
    }

    if (escaped || quote != '\0') {
        error = "unterminated escape or quote";
        return false;
    }
    if (argumentStarted) {
        arguments.push_back(std::move(argument));
    }
    error.clear();
    return true;
}

} // namespace

SshLineParseResult parseSshConfigLine(const std::string& line) {
    SshLineParseResult result;
    std::size_t position = 0;
    while (position < line.size() &&
           std::isspace(static_cast<unsigned char>(line[position]))) {
        ++position;
    }
    if (position == line.size() || line[position] == '#') {
        result.ok = true;
        return result;
    }

    if (line[position] == '"') {
        const std::size_t keywordStart = ++position;
        const std::size_t closingQuote = line.find('"', position);
        if (closingQuote == std::string::npos) {
            result.error = "unterminated quoted SSH directive";
            return result;
        }
        if (closingQuote == keywordStart) {
            result.error = "empty SSH directive";
            return result;
        }
        result.directive.keyword =
            line.substr(keywordStart, closingQuote - keywordStart);
        position = closingQuote + 1;
    } else {
        const std::size_t keywordStart = position;
        while (position < line.size() &&
               !std::isspace(static_cast<unsigned char>(line[position])) &&
               line[position] != '=') {
            ++position;
        }
        if (position == keywordStart) {
            result.error = "empty SSH directive";
            return result;
        }
        result.directive.keyword =
            line.substr(keywordStart, position - keywordStart);
    }

    while (position < line.size() &&
           std::isspace(static_cast<unsigned char>(line[position]))) {
        ++position;
    }
    if (position < line.size() && line[position] == '=') {
        ++position;
        while (position < line.size() &&
               std::isspace(static_cast<unsigned char>(line[position]))) {
            ++position;
        }
    }

    if (!tokenizeArguments(line.substr(position),
                           result.directive.arguments,
                           result.error)) {
        return result;
    }

    result.ok = true;
    result.hasDirective = true;
    return result;
}

std::string normalizeSshKeyword(std::string keyword) {
    std::transform(keyword.begin(), keyword.end(), keyword.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return keyword;
}

std::string joinSshArguments(const std::vector<std::string>& arguments,
                             std::size_t start) {
    std::string result;
    for (std::size_t index = start; index < arguments.size(); ++index) {
        if (!result.empty()) {
            result += ' ';
        }
        result += arguments[index];
    }
    return result;
}
