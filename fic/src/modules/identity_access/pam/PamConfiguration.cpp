#include "modules/identity_access/pam/PamConfiguration.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iterator>
#include <sstream>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

constexpr std::size_t kMaximumIncludeDepth = 32;
constexpr std::size_t kMaximumCollectedRules = 4096;

bool readTrustedPamSource(const std::filesystem::path& path,
                          std::string& content,
                          std::string& error) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        error = errno == ELOOP
            ? "PAM service is a symbolic link: " + path.string()
            : "could not open PAM service " + path.string() + ": " +
                std::strerror(errno);
        return false;
    }
    struct stat info {};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        error = "PAM service is not a regular file: " + path.string();
        ::close(fd);
        return false;
    }
    content.clear();
    char buffer[8192];
    for (;;) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            content.append(buffer, static_cast<std::size_t>(count));
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            error = "could not read PAM service " + path.string() + ": " +
                std::strerror(errno);
            ::close(fd);
            return false;
        }
    }
    if (::close(fd) != 0) {
        error = "could not close PAM service " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    error.clear();
    return true;
}

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

void flattenStack(const std::vector<PamStackEntry>& entries,
                  std::vector<PamRule>& rules) {
    for (const auto& entry : entries) {
        if (entry.isSubstack()) {
            flattenStack(entry.substack, rules);
        } else {
            rules.push_back(entry.rule);
        }
    }
}

} // namespace

PamConfiguration::PamConfiguration(
    fic::platform::PamPlatformConfig platformConfig)
    : platformConfig_(std::move(platformConfig)) {
}

bool PamConfiguration::parseRulesContent(
    const std::filesystem::path& source,
    const std::string& content,
    std::vector<PamRule>& rules,
    std::string& error) {
    rules.clear();
    std::istringstream input(content);
    std::string physicalLine;
    std::string logicalLine;
    std::size_t physicalLineNumber = 0;
    std::size_t logicalLineNumber = 0;

    auto parseLogicalLine = [&](const std::string& raw,
                                std::size_t lineNumber) -> bool {
        const std::string line = trimCopy(stripComment(raw));
        if (line.empty()) {
            return true;
        }
        std::vector<std::string> tokens;
        std::string tokenError;
        if (!tokenize(line, tokens, tokenError)) {
            error = source.string() + ":" + std::to_string(lineNumber) +
                ": " + tokenError;
            return false;
        }
        if (tokens.empty()) {
            return true;
        }

        if (tokens.front() == "@include") {
            if (tokens.size() != 2 || !validServiceName(tokens[1])) {
                error = source.string() + ":" + std::to_string(lineNumber) +
                    ": invalid @include directive";
                return false;
            }
            PamRule rule;
            rule.source = source;
            rule.line = lineNumber;
            rule.includeKind = PamIncludeKind::IncludeAll;
            rule.includeTarget = tokens[1];
            rules.push_back(std::move(rule));
            return true;
        }

        const auto group = parseManagementGroup(tokens.front());
        if (!group.has_value() || tokens.size() < 3) {
            error = source.string() + ":" + std::to_string(lineNumber) +
                ": unsupported or malformed PAM rule";
            return false;
        }

        PamRule rule;
        rule.source = source;
        rule.line = lineNumber;
        rule.group = *group;
        rule.control = tokens[1];
        if (rule.control == "include" || rule.control == "substack") {
            if (!validServiceName(tokens[2])) {
                error = source.string() + ":" + std::to_string(lineNumber) +
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
        rules.push_back(std::move(rule));
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
            rules.clear();
            return false;
        }
        logicalLine.clear();
    }
    if (!input.eof()) {
        error = "could not read PAM service content: " + source.string();
        rules.clear();
        return false;
    }
    if (!logicalLine.empty() &&
        !parseLogicalLine(logicalLine, logicalLineNumber)) {
        rules.clear();
        return false;
    }
    error.clear();
    return true;
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
        struct stat info {};
        if (::lstat(candidate.c_str(), &info) != 0) {
            if (errno == ENOENT) {
                continue;
            }
            error = "could not inspect PAM service " + candidate.string() +
                ": " + std::strerror(errno);
            return false;
        }
        if (S_ISLNK(info.st_mode)) {
            error = "PAM service is a symbolic link: " + candidate.string();
            return false;
        }
        if (!S_ISREG(info.st_mode)) {
            error = "PAM service is not a regular file: " +
                candidate.string();
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

    std::string content;
    if (!readTrustedPamSource(path, content, error)) {
        return false;
    }
    ParsedService candidate;
    candidate.path = path;
    if (!parseRulesContent(path, content, candidate.rules, error)) {
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
    PamEffectiveStack stack;
    if (!buildEffectiveStack(service, group, stack, error)) {
        rules.clear();
        return false;
    }
    rules.clear();
    flattenStack(stack.entries, rules);
    if (sourceFiles != nullptr) {
        sourceFiles->insert(stack.sourceFiles.begin(), stack.sourceFiles.end());
    }
    return true;
}

bool PamConfiguration::buildEffectiveStack(
    const std::string& service,
    PamManagementGroup group,
    PamEffectiveStack& stack,
    std::string& error) {
    error.clear();
    stack = PamEffectiveStack{};
    stack.service = service;
    stack.group = group;
    std::set<std::string> recursionStack;
    std::size_t entryCount = 0;
    return buildEffectiveStackRecursive(
        service,
        group,
        stack.entries,
        recursionStack,
        0,
        entryCount,
        stack.sourceFiles,
        error);
}

bool PamConfiguration::buildEffectiveStackRecursive(
    const std::string& service,
    PamManagementGroup group,
    std::vector<PamStackEntry>& entries,
    std::set<std::string>& recursionStack,
    std::size_t depth,
    std::size_t& entryCount,
    std::set<std::filesystem::path>& sourceFiles,
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
    sourceFiles.insert(parsed->path);

    for (const auto& rule : parsed->rules) {
        if (rule.includeKind == PamIncludeKind::IncludeAll) {
            if (!buildEffectiveStackRecursive(
                    rule.includeTarget,
                    group,
                    entries,
                    recursionStack,
                    depth + 1,
                    entryCount,
                    sourceFiles,
                    error)) {
                recursionStack.erase(recursionKey);
                return false;
            }
        } else if (rule.includeKind == PamIncludeKind::Include) {
            if (sameGroup(rule, group) &&
                !buildEffectiveStackRecursive(
                    rule.includeTarget,
                    group,
                    entries,
                    recursionStack,
                    depth + 1,
                    entryCount,
                    sourceFiles,
                    error)) {
                recursionStack.erase(recursionKey);
                return false;
            }
        } else if (rule.includeKind == PamIncludeKind::Substack) {
            if (!sameGroup(rule, group)) {
                continue;
            }
            PamStackEntry entry;
            entry.rule = rule;
            ++entryCount;
            if (entryCount > kMaximumCollectedRules ||
                !buildEffectiveStackRecursive(
                    rule.includeTarget,
                    group,
                    entry.substack,
                    recursionStack,
                    depth + 1,
                    entryCount,
                    sourceFiles,
                    error)) {
                if (error.empty()) {
                    error = "PAM rule count limit exceeded at service: " +
                        service;
                }
                recursionStack.erase(recursionKey);
                return false;
            }
            entries.push_back(std::move(entry));
        } else if (sameGroup(rule, group)) {
            entries.push_back(PamStackEntry{rule, {}});
            ++entryCount;
            if (entryCount > kMaximumCollectedRules) {
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

} // namespace fic::identity::pam
