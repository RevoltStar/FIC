#include "modules/identity_access/pam/PasswdqcConfigFile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

struct SecureFile {
    std::string content;
    dev_t device = 0;
    ino_t inode = 0;
};

std::string trimNativeLine(std::string line)
{
    const auto first = line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = line.find_last_not_of(" \t");
    return line.substr(first, last - first + 1);
}

bool parseCanonicalUnsigned(const std::string& text,
                            unsigned int& result,
                            std::string& error)
{
    if (text.empty() ||
        !std::all_of(text.begin(), text.end(), [](unsigned char character) {
            return character >= '0' && character <= '9';
        })) {
        error = "expected an unsigned decimal integer";
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long value = std::strtoul(text.c_str(), &end, 10);
    if (errno == ERANGE || end == nullptr || *end != '\0' || value > INT_MAX) {
        error = "unsigned decimal integer is out of range";
        return false;
    }
    result = static_cast<unsigned int>(value);
    return true;
}

bool parseNativeUnsigned(const std::string& text,
                         unsigned int& result,
                         std::string& error)
{
    errno = 0;
    char* end = nullptr;
    const unsigned long value = std::strtoul(text.c_str(), &end, 10);
    if (errno == ERANGE || end == nullptr || *end != '\0' || value > INT_MAX) {
        error = "invalid native unsigned integer";
        return false;
    }
    result = static_cast<unsigned int>(value);
    return true;
}

bool parseNativeMinimums(const std::string& value,
                         PasswdqcMinimums& result,
                         std::string& error)
{
    std::array<std::string, 5> fields;
    std::size_t begin = 0;
    for (std::size_t index = 0; index < fields.size(); ++index) {
        const auto comma = value.find(',', begin);
        if ((index + 1 < fields.size() && comma == std::string::npos) ||
            (index + 1 == fields.size() && comma != std::string::npos)) {
            error = "passwdqc min requires exactly five comma-separated values";
            return false;
        }
        fields[index] = value.substr(
            begin,
            comma == std::string::npos ? std::string::npos : comma - begin);
        begin = comma == std::string::npos ? value.size() : comma + 1;
    }

    PasswdqcMinimums parsed;
    for (std::size_t index = 0; index < fields.size(); ++index) {
        if (fields[index] == "disabled") {
            parsed.values[index] = std::nullopt;
            continue;
        }
        unsigned int number = 0;
        if (!parseNativeUnsigned(fields[index], number, error)) {
            error = "invalid passwdqc min field " +
                std::to_string(index + 1) + ": " + error;
            return false;
        }
        parsed.values[index] = number;
    }
    const auto rank = [](const std::optional<unsigned int>& field) {
        return field.has_value()
            ? static_cast<unsigned long long>(*field)
            : static_cast<unsigned long long>(INT_MAX);
    };
    for (std::size_t index = 1; index < parsed.values.size(); ++index) {
        if (rank(parsed.values[index]) > rank(parsed.values[index - 1])) {
            error = "each passwdqc min value must not exceed the previous one";
            return false;
        }
    }
    result = parsed;
    error.clear();
    return true;
}

bool startsWith(const std::string& value, const char* prefix)
{
    const std::string expected(prefix);
    return value.compare(0, expected.size(), expected) == 0;
}

bool parseDirective(const std::string& text,
                    const std::filesystem::path& source,
                    std::size_t line,
                    PasswdqcDirective& directive,
                    std::string& error)
{
    directive = PasswdqcDirective{};
    directive.source = source;
    directive.line = line;
    const auto assignment = [&](const char* prefix,
                                PasswdqcDirectiveKind kind) -> bool {
        if (!startsWith(text, prefix)) {
            return false;
        }
        directive.kind = kind;
        directive.option = std::string(prefix, std::strlen(prefix) - 1);
        directive.value = text.substr(std::strlen(prefix));
        return true;
    };

    if (assignment("min=", PasswdqcDirectiveKind::Minimums)) {
        PasswdqcMinimums minimums;
        if (!parseNativeMinimums(directive.value, minimums, error)) {
            return false;
        }
    } else if (assignment("max=", PasswdqcDirectiveKind::Maximum)) {
        unsigned int value = 0;
        if (!parseNativeUnsigned(directive.value, value, error) || value < 8) {
            error = "passwdqc max must be at least 8";
            return false;
        }
    } else if (assignment(
                   "passphrase=", PasswdqcDirectiveKind::PassphraseWords) ||
               assignment("match=", PasswdqcDirectiveKind::MatchLength) ||
               assignment("retry=", PasswdqcDirectiveKind::Retry)) {
        unsigned int unused = 0;
        if (!parseNativeUnsigned(directive.value, unused, error)) {
            return false;
        }
    } else if (assignment("similar=", PasswdqcDirectiveKind::Similar)) {
        if (directive.value != "permit" && directive.value != "deny") {
            error = "passwdqc similar must be permit or deny";
            return false;
        }
    } else if (assignment("random=", PasswdqcDirectiveKind::RandomBits)) {
        std::string number = directive.value;
        if (number.size() >= 5 &&
            number.compare(number.size() - 5, 5, ",only") == 0) {
            number.resize(number.size() - 5);
        }
        unsigned int value = 0;
        if (!parseNativeUnsigned(number, value, error) ||
            (value != 0 && value < 24) || value > 136) {
            error = "passwdqc random must be 0 or between 24 and 136";
            return false;
        }
    } else if (assignment("wordlist=", PasswdqcDirectiveKind::Wordlist) ||
               assignment("denylist=", PasswdqcDirectiveKind::Denylist) ||
               assignment("filter=", PasswdqcDirectiveKind::Filter)) {
        // Native passwdqc accepts an empty path to clear these settings.
    } else if (assignment("enforce=", PasswdqcDirectiveKind::Enforce)) {
        if (directive.value != "none" && directive.value != "users" &&
            directive.value != "everyone") {
            error = "passwdqc enforce must be none, users or everyone";
            return false;
        }
    } else if (text == "non-unix") {
        directive.kind = PasswdqcDirectiveKind::NonUnix;
        directive.option = text;
    } else if (text == "ask_oldauthtok" || text == "ask_oldauthtok=update") {
        directive.kind = PasswdqcDirectiveKind::AskOldAuthToken;
        directive.option = "ask_oldauthtok";
        directive.value = text == "ask_oldauthtok" ? "" : "update";
    } else if (text == "check_oldauthtok") {
        directive.kind = PasswdqcDirectiveKind::CheckOldAuthToken;
        directive.option = text;
    } else if (text == "use_first_pass") {
        directive.kind = PasswdqcDirectiveKind::UseFirstPass;
        directive.option = text;
    } else if (text == "use_authtok") {
        directive.kind = PasswdqcDirectiveKind::UseAuthToken;
        directive.option = text;
    } else if (text == "noaudit") {
        directive.kind = PasswdqcDirectiveKind::NoAudit;
        directive.option = text;
    } else if (assignment("config=", PasswdqcDirectiveKind::Config)) {
        const std::filesystem::path nested(directive.value);
        if (directive.value.empty() || !nested.is_absolute() ||
            nested != nested.lexically_normal()) {
            error = "passwdqc config path must be absolute and normalized";
            return false;
        }
    } else {
        error = "unsupported native passwdqc parameter: " + text;
        return false;
    }
    return true;
}

bool readSecureFile(const std::filesystem::path& path,
                    SecureFile& file,
                    std::string& error)
{
    if (!path.is_absolute() || path != path.lexically_normal()) {
        error = "passwdqc config path must be absolute and normalized: " +
            path.string();
        return false;
    }
    struct stat linkInfo {};
    if (::lstat(path.c_str(), &linkInfo) != 0) {
        error = "could not inspect " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    if (S_ISLNK(linkInfo.st_mode)) {
        error = "refusing to use symbolic link: " + path.string();
        return false;
    }
    const int descriptor = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        error = "could not open " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    struct stat info {};
    if (::fstat(descriptor, &info) != 0) {
        error = "could not stat " + path.string() + ": " +
            std::strerror(errno);
        ::close(descriptor);
        return false;
    }
    if (!S_ISREG(info.st_mode)) {
        error = "refusing to use non-regular file: " + path.string();
        ::close(descriptor);
        return false;
    }
    if (info.st_uid != ::geteuid()) {
        error = "passwdqc config is not owned by the daemon owner: " +
            path.string();
        ::close(descriptor);
        return false;
    }
    if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        error = "passwdqc config is writable by group or others: " +
            path.string();
        ::close(descriptor);
        return false;
    }

    file = SecureFile{};
    file.device = info.st_dev;
    file.inode = info.st_ino;
    char buffer[8192];
    while (true) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = "could not read " + path.string() + ": " +
                std::strerror(errno);
            ::close(descriptor);
            return false;
        }
        file.content.append(buffer, static_cast<std::size_t>(count));
        if (file.content.size() > PasswdqcConfigEvaluator::maximumTotalBytes) {
            error = "passwdqc config input exceeds the total size limit";
            ::close(descriptor);
            return false;
        }
    }
    if (::close(descriptor) != 0) {
        error = "could not close " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    return true;
}

bool applyDirective(const PasswdqcDirective& directive,
                    PasswdqcEffectiveState& state,
                    std::string& error)
{
    unsigned int number = 0;
    switch (directive.kind) {
    case PasswdqcDirectiveKind::Minimums:
        return parseNativeMinimums(directive.value, state.minimums, error);
    case PasswdqcDirectiveKind::Maximum:
        if (!parseNativeUnsigned(directive.value, number, error)) {
            return false;
        }
        state.maximum = std::min(number, 10000U);
        return true;
    case PasswdqcDirectiveKind::PassphraseWords:
        if (!parseNativeUnsigned(directive.value, number, error)) {
            return false;
        }
        state.passphraseWords = number;
        return true;
    case PasswdqcDirectiveKind::MatchLength:
        if (!parseNativeUnsigned(directive.value, number, error)) {
            return false;
        }
        state.matchLength = number;
        return true;
    case PasswdqcDirectiveKind::Similar:
        state.similar = directive.value;
        return true;
    case PasswdqcDirectiveKind::RandomBits: {
        std::string value = directive.value;
        const bool only = value.size() >= 5 &&
            value.compare(value.size() - 5, 5, ",only") == 0;
        if (only) {
            value.resize(value.size() - 5);
        }
        if (!parseNativeUnsigned(value, number, error)) {
            return false;
        }
        state.randomBits = number;
        if (only) {
            state.minimums.values[4] = std::nullopt;
        }
        return true;
    }
    case PasswdqcDirectiveKind::Wordlist:
        state.wordlist = directive.value;
        return true;
    case PasswdqcDirectiveKind::Denylist:
        state.denylist = directive.value;
        return true;
    case PasswdqcDirectiveKind::Filter:
        state.filter = directive.value;
        return true;
    case PasswdqcDirectiveKind::Enforce:
        state.enforce = directive.value;
        return true;
    case PasswdqcDirectiveKind::NonUnix:
        if (state.checkOldAuthToken) {
            error = "non-unix conflicts with check_oldauthtok";
            return false;
        }
        state.nonUnix = true;
        return true;
    case PasswdqcDirectiveKind::Retry:
        if (!parseNativeUnsigned(directive.value, number, error)) {
            return false;
        }
        state.retry = number;
        return true;
    case PasswdqcDirectiveKind::AskOldAuthToken:
        if (state.useFirstPass) {
            error = "ask_oldauthtok conflicts with use_first_pass";
            return false;
        }
        state.askOldAuthToken = directive.value.empty();
        state.askOldAuthTokenDuringUpdate = directive.value == "update";
        return true;
    case PasswdqcDirectiveKind::CheckOldAuthToken:
        if (state.nonUnix) {
            error = "check_oldauthtok conflicts with non-unix";
            return false;
        }
        state.checkOldAuthToken = true;
        return true;
    case PasswdqcDirectiveKind::UseFirstPass:
        if (state.askOldAuthToken || state.askOldAuthTokenDuringUpdate) {
            error = "use_first_pass conflicts with ask_oldauthtok";
            return false;
        }
        state.useFirstPass = true;
        state.useAuthToken = true;
        return true;
    case PasswdqcDirectiveKind::UseAuthToken:
        state.useAuthToken = true;
        return true;
    case PasswdqcDirectiveKind::NoAudit:
        state.noAudit = true;
        return true;
    case PasswdqcDirectiveKind::Config:
        error = "internal error: config directive was not recursively evaluated";
        return false;
    }
    error = "unsupported passwdqc directive";
    return false;
}

struct EvaluationContext {
    std::size_t totalBytes = 0;
    std::vector<std::pair<dev_t, ino_t>> activeFiles;
};

bool evaluateFile(const std::filesystem::path& path,
                  std::size_t depth,
                  EvaluationContext& context,
                  PasswdqcEffectiveState& state,
                  std::string& error)
{
    if (depth >= PasswdqcConfigEvaluator::maximumDepth) {
        error = "passwdqc config recursion depth limit exceeded";
        return false;
    }
    SecureFile file;
    if (!readSecureFile(path, file, error)) {
        return false;
    }
    context.totalBytes += file.content.size();
    if (context.totalBytes > PasswdqcConfigEvaluator::maximumTotalBytes) {
        error = "passwdqc config input exceeds the total size limit";
        return false;
    }
    const auto identity = std::make_pair(file.device, file.inode);
    if (std::find(context.activeFiles.begin(), context.activeFiles.end(),
                  identity) != context.activeFiles.end()) {
        error = "passwdqc config include loop detected at " + path.string();
        return false;
    }
    context.activeFiles.push_back(identity);
    const auto fail = [&](const std::string& detail) {
        context.activeFiles.pop_back();
        error = path.string() + ": " + detail;
        return false;
    };

    std::istringstream input(file.content);
    std::string rawLine;
    std::size_t lineNumber = 0;
    while (std::getline(input, rawLine)) {
        ++lineNumber;
        if (rawLine.size() > PasswdqcConfigEvaluator::maximumLineBytes) {
            return fail("line " + std::to_string(lineNumber) + " is too long");
        }
        const std::string line = trimNativeLine(rawLine);
        if (line.empty() || line.front() == '#') {
            continue;
        }
        PasswdqcDirective directive;
        std::string directiveError;
        if (!parseDirective(
                line, path, lineNumber, directive, directiveError)) {
            return fail("line " + std::to_string(lineNumber) + ": " +
                        directiveError);
        }
        if (directive.kind == PasswdqcDirectiveKind::Config) {
            if (!evaluateFile(
                    std::filesystem::path(directive.value), depth + 1,
                    context, state, directiveError)) {
                return fail("line " + std::to_string(lineNumber) + ": " +
                            directiveError);
            }
        } else if (!applyDirective(directive, state, directiveError)) {
            return fail("line " + std::to_string(lineNumber) + ": " +
                        directiveError);
        }
    }
    context.activeFiles.pop_back();
    return true;
}

std::vector<std::string> splitLines(const std::string& content)
{
    std::vector<std::string> lines;
    std::istringstream input(content);
    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(line);
    }
    return lines;
}

std::string joinLines(const std::vector<std::string>& lines)
{
    std::string content;
    for (const auto& line : lines) {
        content += line;
        content.push_back('\n');
    }
    return content;
}

AtomicWriteOptions writeOptions()
{
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = 0644;
    options.fileOwner = ::geteuid();
    options.fileGroup = ::getegid();
    return options;
}

bool readRootForMutation(const std::filesystem::path& path,
                         bool& existed,
                         std::string& content,
                         std::string& error)
{
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        if (errno == ENOENT) {
            existed = false;
            content.clear();
            return true;
        }
        error = "could not inspect " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    SecureFile file;
    if (!readSecureFile(path, file, error)) {
        return false;
    }
    existed = true;
    content = std::move(file.content);
    return true;
}

bool verifyRawContent(const std::filesystem::path& path,
                      bool expectedToExist,
                      const std::string& expected,
                      std::string& error)
{
    bool existed = false;
    std::string content;
    if (!readRootForMutation(path, existed, content, error)) {
        if (!expectedToExist && error.find("No such file") !=
                std::string::npos) {
            error.clear();
            return true;
        }
        return false;
    }
    if (existed != expectedToExist || (existed && content != expected)) {
        error = "rollback content verification failed for " + path.string();
        return false;
    }
    return true;
}

} // namespace

PasswdqcEffectiveState::PasswdqcEffectiveState()
{
    minimums.values = {
        std::nullopt, 24U, 11U, 8U, 8U
    };
}

bool PasswdqcEffectiveState::managedValue(const std::string& option,
                                          std::string& value,
                                          std::string& error) const
{
    if (option == "min") {
        value = PasswdqcMinimumsCodec::serialize(minimums);
    } else if (option == "passphrase") {
        value = std::to_string(passphraseWords);
    } else if (option == "match") {
        value = std::to_string(matchLength);
    } else if (option == "similar") {
        value = similar;
    } else if (option == "enforce") {
        value = enforce;
    } else if (option == "retry") {
        value = std::to_string(retry);
    } else {
        error = "unsupported managed passwdqc option: " + option;
        return false;
    }
    error.clear();
    return true;
}

bool PasswdqcMinimumsCodec::parse(const std::string& value,
                                  PasswdqcMinimums& result,
                                  std::string& error)
{
    std::array<std::string, 5> fields;
    std::size_t begin = 0;
    for (std::size_t index = 0; index < fields.size(); ++index) {
        const auto comma = value.find(',', begin);
        if ((index + 1 < fields.size() && comma == std::string::npos) ||
            (index + 1 == fields.size() && comma != std::string::npos)) {
            error = "passwdqc min requires exactly five comma-separated values";
            return false;
        }
        fields[index] = value.substr(
            begin, comma == std::string::npos ? std::string::npos : comma - begin);
        begin = comma == std::string::npos ? value.size() : comma + 1;
    }

    PasswdqcMinimums parsed;
    for (std::size_t index = 0; index < fields.size(); ++index) {
        if (fields[index] == "disabled") {
            parsed.values[index] = std::nullopt;
            continue;
        }
        unsigned int number = 0;
        if (!parseCanonicalUnsigned(fields[index], number, error)) {
            error = "invalid passwdqc min field " +
                std::to_string(index + 1) + ": " + error;
            return false;
        }
        parsed.values[index] = number;
    }
    const auto rank = [](const std::optional<unsigned int>& field) {
        return field.has_value()
            ? static_cast<unsigned long long>(*field)
            : static_cast<unsigned long long>(INT_MAX);
    };
    for (std::size_t index = 1; index < parsed.values.size(); ++index) {
        if (rank(parsed.values[index]) > rank(parsed.values[index - 1])) {
            error = "each passwdqc min value must not exceed the previous one";
            return false;
        }
    }
    result = parsed;
    error.clear();
    return true;
}

std::string PasswdqcMinimumsCodec::serialize(const PasswdqcMinimums& value)
{
    std::string result;
    for (std::size_t index = 0; index < value.values.size(); ++index) {
        if (index != 0) {
            result.push_back(',');
        }
        result += value.values[index].has_value()
            ? std::to_string(*value.values[index])
            : "disabled";
    }
    return result;
}

bool PasswdqcConfigEvaluator::evaluate(
    const std::filesystem::path& root,
    PasswdqcEffectiveState& state,
    std::string& error)
{
    PasswdqcEffectiveState evaluated;
    EvaluationContext context;
    if (!evaluateFile(root, 0, context, evaluated, error)) {
        return false;
    }
    state = std::move(evaluated);
    error.clear();
    return true;
}

bool PasswdqcConfigFile::validateNativeValue(const std::string& option,
                                              const std::string& value,
                                              std::string& error)
{
    if (option == "min") {
        PasswdqcMinimums minimums;
        return PasswdqcMinimumsCodec::parse(value, minimums, error);
    }
    if (option == "similar") {
        if (value == "permit" || value == "deny") {
            error.clear();
            return true;
        }
        error = "passwdqc similar must be permit or deny";
        return false;
    }
    if (option == "enforce") {
        if (value == "none" || value == "users" || value == "everyone") {
            error.clear();
            return true;
        }
        error = "passwdqc enforce must be none, users or everyone";
        return false;
    }
    if (option == "passphrase" || option == "match" || option == "retry") {
        unsigned int unused = 0;
        return parseCanonicalUnsigned(value, unused, error);
    }
    error = "unsupported managed passwdqc option: " + option;
    return false;
}

bool PasswdqcConfigFile::hasEffectiveValue(
    const std::filesystem::path& path,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    if (!validateNativeValue(option, expectedValue, error)) {
        return false;
    }
    PasswdqcEffectiveState state;
    if (!PasswdqcConfigEvaluator::evaluate(path, state, error)) {
        return false;
    }
    std::string effective;
    if (!state.managedValue(option, effective, error)) {
        return false;
    }
    if (effective != expectedValue) {
        error = "effective passwdqc " + option + " is " + effective +
            ", expected " + expectedValue;
        return false;
    }
    error.clear();
    return true;
}

bool PasswdqcConfigFile::setValue(const std::filesystem::path& path,
                                  const std::string& option,
                                  const std::string& value,
                                  std::string& error,
                                  Writer writer)
{
    if (!validateNativeValue(option, value, error)) {
        return false;
    }
    bool existed = false;
    std::string original;
    if (!readRootForMutation(path, existed, original, error)) {
        return false;
    }
    if (existed) {
        PasswdqcEffectiveState current;
        if (!PasswdqcConfigEvaluator::evaluate(path, current, error)) {
            return false;
        }
    }

    std::vector<std::string> outputLines;
    const auto lines = splitLines(original);
    for (std::size_t index = 0; index < lines.size(); ++index) {
        const std::string native = trimNativeLine(lines[index]);
        if (native.empty() || native.front() == '#') {
            outputLines.push_back(lines[index]);
            continue;
        }
        PasswdqcDirective directive;
        std::string parseError;
        if (!parseDirective(native, path, index + 1, directive, parseError)) {
            error = parseError;
            return false;
        }
        if (directive.option != option) {
            outputLines.push_back(lines[index]);
        }
    }
    outputLines.push_back(option + "=" + value);

    if (!writer) {
        writer = AtomicFileWriter::write;
    }
    const auto rollback = [&](const std::string& failure) {
        std::string rollbackError;
        bool restored = false;
        if (existed) {
            restored = writer(
                path.string(), original, writeOptions(), &rollbackError);
        } else {
            std::error_code removeError;
            std::filesystem::remove(path, removeError);
            restored = !removeError;
            if (removeError) {
                rollbackError = removeError.message();
            }
        }
        if (restored && !verifyRawContent(
                path, existed, original, rollbackError)) {
            restored = false;
        }
        error = failure;
        if (!restored) {
            error += "; CRITICAL: rollback failed: " + rollbackError;
        }
        return false;
    };

    std::string writeError;
    if (!writer(
            path.string(), joinLines(outputLines), writeOptions(),
            &writeError)) {
        return rollback("passwdqc write failed: " + writeError);
    }
    if (!hasEffectiveValue(path, option, value, error)) {
        return rollback("passwdqc effective postcondition failed: " + error);
    }
    return true;
}

} // namespace fic::identity::pam
