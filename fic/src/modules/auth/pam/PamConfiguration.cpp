#include "modules/auth/pam/PamConfiguration.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <utility>

namespace fic::auth {
namespace {

constexpr std::size_t kMaximumIncludeDepth = 32;
constexpr std::size_t kMaximumCollectedRules = 4096;

bool validServiceName(const std::string& service) {
    if (service.empty() || service.size() > 255) {
        return false;
    }
    return std::all_of(service.begin(), service.end(), [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '_' || c == '-' || c == '.';
    });
}

std::string trimCopy(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }).base();
    return std::string(first, last);
}

bool hasUnescapedContinuation(const std::string& line) {
    std::size_t backslashes = 0;
    for (auto it = line.rbegin(); it != line.rend() && *it == '\\'; ++it) {
        ++backslashes;
    }
    return backslashes % 2 == 1;
}

std::string stripComment(const std::string& line) {
    bool quoted = false;
    bool escaped = false;
    int bracketDepth = 0;
    for (std::size_t index = 0; index < line.size(); ++index) {
        const char c = line[index];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"') {
            quoted = !quoted;
            continue;
        }
        if (!quoted) {
            if (c == '[') {
                ++bracketDepth;
            } else if (c == ']' && bracketDepth > 0) {
                --bracketDepth;
            } else if (c == '#' && bracketDepth == 0) {
                return line.substr(0, index);
            }
        }
    }
    return line;
}

bool tokenize(const std::string& line,
              std::vector<std::string>& tokens,
              std::string& error) {
    tokens.clear();
    std::string token;
    bool quoted = false;
    bool escaped = false;
    int bracketDepth = 0;

    for (const char c : line) {
        if (escaped) {
            token.push_back(c);
            escaped = false;
            continue;
        }
        if (c == '\\') {
            token.push_back(c);
            escaped = true;
            continue;
        }
        if (c == '"') {
            quoted = !quoted;
            token.push_back(c);
            continue;
        }
        if (!quoted) {
            if (c == '[') {
                ++bracketDepth;
            } else if (c == ']') {
                if (bracketDepth == 0) {
                    error = "unexpected closing bracket";
                    return false;
                }
                --bracketDepth;
            }
        }
        if (std::isspace(static_cast<unsigned char>(c)) != 0 &&
            !quoted && bracketDepth == 0) {
            if (!token.empty()) {
                tokens.push_back(std::move(token));
                token.clear();
            }
            continue;
        }
        token.push_back(c);
    }

    if (escaped || quoted || bracketDepth != 0) {
        error = "unterminated escape, quote or bracket expression";
        return false;
    }
    if (!token.empty()) {
        tokens.push_back(std::move(token));
    }
    return true;
}

std::optional<PamManagementGroup> parseManagementGroup(std::string token) {
    if (!token.empty() && token.front() == '-') {
        token.erase(token.begin());
    }
    if (token == "auth") {
        return PamManagementGroup::Auth;
    }
    if (token == "account") {
        return PamManagementGroup::Account;
    }
    if (token == "password") {
        return PamManagementGroup::Password;
    }
    if (token == "session") {
        return PamManagementGroup::Session;
    }
    return std::nullopt;
}

bool sameGroup(const PamRule& rule, PamManagementGroup group) {
    return rule.group == group;
}

} // namespace

PamConfiguration::PamConfiguration(
    fic::platform::PamPlatformConfig platformConfig)
    : platformConfig_(std::move(platformConfig)) {
}

bool PamConfiguration::resolveServicePath(
    const std::string& service,
    bool& exists,
    std::filesystem::path& path,
    std::string& error) const {
    exists = false;
    path.clear();
    if (!validServiceName(service)) {
        error = "invalid PAM service name: " + service;
        return false;
    }
    for (const auto& directory : platformConfig_.configDirectories) {
        const std::filesystem::path candidate = directory / service;
        std::error_code filesystemError;
        const bool candidateExists =
            std::filesystem::exists(candidate, filesystemError);
        if (filesystemError) {
            error = "could not inspect PAM service " + candidate.string() +
                ": " + filesystemError.message();
            return false;
        }
        if (!candidateExists) {
            continue;
        }
        if (!std::filesystem::is_regular_file(candidate, filesystemError)) {
            error = filesystemError
                ? "could not inspect PAM service " + candidate.string() +
                    ": " + filesystemError.message()
                : "PAM service is not a regular file: " + candidate.string();
            return false;
        }
        exists = true;
        path = candidate;
        error.clear();
        return true;
    }
    error.clear();
    return true;
}

bool PamConfiguration::serviceExists(const std::string& service) const {
    bool exists = false;
    std::filesystem::path path;
    std::string error;
    return resolveServicePath(service, exists, path, error) && exists;
}

bool PamConfiguration::existingServices(
    const std::vector<std::string>& services,
    std::vector<std::string>& existing,
    std::string& error) const {
    existing.clear();
    for (const auto& service : services) {
        bool exists = false;
        std::filesystem::path path;
        if (!resolveServicePath(service, exists, path, error)) {
            return false;
        }
        if (exists) {
            existing.push_back(service);
        }
    }
    return true;
}

bool PamConfiguration::parseService(const std::string& service,
                                    const ParsedService*& parsed,
                                    std::string& error) {
    const auto cached = cache_.find(service);
    if (cached != cache_.end()) {
        parsed = &cached->second;
        return true;
    }

    std::filesystem::path path;
    bool exists = false;
    if (!resolveServicePath(service, exists, path, error)) {
        return false;
    }
    if (!exists) {
        error = "PAM service was not found: " + service;
        return false;
    }

    std::ifstream input(path);
    if (!input.is_open()) {
        error = "could not open PAM service: " + path.string();
        return false;
    }

    ParsedService candidate;
    candidate.path = path;
    std::string physicalLine;
    std::string logicalLine;
    std::size_t physicalLineNumber = 0;
    std::size_t logicalLineNumber = 0;

    auto parseLogicalLine = [&](const std::string& raw, std::size_t lineNumber) -> bool {
        const std::string line = trimCopy(stripComment(raw));
        if (line.empty()) {
            return true;
        }
        std::vector<std::string> tokens;
        std::string tokenError;
        if (!tokenize(line, tokens, tokenError)) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                ": " + tokenError;
            return false;
        }
        if (tokens.empty()) {
            return true;
        }

        if (tokens.front() == "@include") {
            if (tokens.size() != 2 || !validServiceName(tokens[1])) {
                error = path.string() + ":" + std::to_string(lineNumber) +
                    ": invalid @include directive";
                return false;
            }
            PamRule rule;
            rule.source = path;
            rule.line = lineNumber;
            rule.includeKind = PamIncludeKind::IncludeAll;
            rule.includeTarget = tokens[1];
            candidate.rules.push_back(std::move(rule));
            return true;
        }

        const auto group = parseManagementGroup(tokens.front());
        if (!group.has_value() || tokens.size() < 3) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                ": unsupported or malformed PAM rule";
            return false;
        }

        PamRule rule;
        rule.source = path;
        rule.line = lineNumber;
        rule.group = *group;
        rule.control = tokens[1];
        if (rule.control == "include" || rule.control == "substack") {
            if (!validServiceName(tokens[2])) {
                error = path.string() + ":" + std::to_string(lineNumber) +
                    ": invalid PAM include target";
                return false;
            }
            rule.includeKind = rule.control == "include"
                ? PamIncludeKind::Include
                : PamIncludeKind::Substack;
            rule.includeTarget = tokens[2];
        } else {
            rule.module = tokens[2];
            rule.arguments.assign(tokens.begin() + 3, tokens.end());
        }
        candidate.rules.push_back(std::move(rule));
        return true;
    };

    while (std::getline(input, physicalLine)) {
        ++physicalLineNumber;
        if (logicalLine.empty()) {
            logicalLineNumber = physicalLineNumber;
        }
        logicalLine += physicalLine;
        if (hasUnescapedContinuation(logicalLine)) {
            logicalLine.pop_back();
            logicalLine.push_back(' ');
            continue;
        }
        if (!parseLogicalLine(logicalLine, logicalLineNumber)) {
            return false;
        }
        logicalLine.clear();
    }
    if (!input.eof()) {
        error = "could not read PAM service: " + path.string();
        return false;
    }
    if (!logicalLine.empty() &&
        !parseLogicalLine(logicalLine, logicalLineNumber)) {
        return false;
    }

    const auto [inserted, unused] =
        cache_.emplace(service, std::move(candidate));
    parsed = &inserted->second;
    return true;
}

bool PamConfiguration::collectRules(
    const std::string& service,
    PamManagementGroup group,
    std::vector<PamRule>& rules,
    std::string& error,
    std::set<std::filesystem::path>* sourceFiles) {
    rules.clear();
    std::set<std::string> recursionStack;
    return collectRulesRecursive(
        service, group, rules, recursionStack, 0, sourceFiles, error);
}

bool PamConfiguration::collectRulesRecursive(
    const std::string& service,
    PamManagementGroup group,
    std::vector<PamRule>& rules,
    std::set<std::string>& recursionStack,
    std::size_t depth,
    std::set<std::filesystem::path>* sourceFiles,
    std::string& error) {
    if (depth > kMaximumIncludeDepth) {
        error = "PAM include depth limit exceeded at service: " + service;
        return false;
    }
    const std::string recursionKey =
        service + ":" + pamManagementGroupName(group);
    if (!recursionStack.insert(recursionKey).second) {
        error = "PAM include cycle detected at service: " + service;
        return false;
    }

    const ParsedService* parsed = nullptr;
    if (!parseService(service, parsed, error)) {
        recursionStack.erase(recursionKey);
        return false;
    }
    if (sourceFiles != nullptr) {
        sourceFiles->insert(parsed->path);
    }

    for (const auto& rule : parsed->rules) {
        if (rule.includeKind == PamIncludeKind::IncludeAll) {
            if (!collectRulesRecursive(
                    rule.includeTarget,
                    group,
                    rules,
                    recursionStack,
                    depth + 1,
                    sourceFiles,
                    error)) {
                recursionStack.erase(recursionKey);
                return false;
            }
        } else if (rule.includeKind == PamIncludeKind::Include ||
                   rule.includeKind == PamIncludeKind::Substack) {
            if (sameGroup(rule, group) &&
                !collectRulesRecursive(
                    rule.includeTarget,
                    group,
                    rules,
                    recursionStack,
                    depth + 1,
                    sourceFiles,
                    error)) {
                recursionStack.erase(recursionKey);
                return false;
            }
        } else if (sameGroup(rule, group)) {
            rules.push_back(rule);
            if (rules.size() > kMaximumCollectedRules) {
                error = "PAM rule count limit exceeded at service: " + service;
                recursionStack.erase(recursionKey);
                return false;
            }
        }
    }

    recursionStack.erase(recursionKey);
    return true;
}

std::string pamManagementGroupName(PamManagementGroup group) {
    switch (group) {
    case PamManagementGroup::Auth:
        return "auth";
    case PamManagementGroup::Account:
        return "account";
    case PamManagementGroup::Password:
        return "password";
    case PamManagementGroup::Session:
        return "session";
    }
    return "unknown";
}

} // namespace fic::auth
