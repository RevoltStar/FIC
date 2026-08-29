#include "modules/identity_access/pam/PwqualityConfigFile.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

// libpwquality 1.4.5 reads into char[PWQSETTINGS_MAX_LINELEN + 1]. A full
// 1023-byte fgets payload without a newline is malformed, including at the
// exact EOF boundary; therefore at most 1022 non-newline bytes are accepted.
constexpr std::size_t MaximumFgetsPayloadLength = 1023;

enum class ManagedOverrideKind {
    Assignment,
    Flag
};

struct ManagedOverride {
    ManagedOverrideKind kind = ManagedOverrideKind::Assignment;
    std::string option;
    std::string value;
    bool enabled = false;
};

std::string trimCopy(std::string value)
{
    const auto first = std::find_if_not(
        value.begin(), value.end(), [](unsigned char character) {
            return std::isspace(character) != 0;
        });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(), [](unsigned char character) {
            return std::isspace(character) != 0;
        }).base();
    return std::string(first, last);
}

std::string lowercaseCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char character) {
                       return static_cast<char>(std::tolower(character));
                   });
    return value;
}

bool parseInteger(const std::string& value, int& parsed)
{
    errno = 0;
    char* end = nullptr;
    const long candidate = std::strtol(value.c_str(), &end, 10);
    if (errno != 0 || value.empty() || end == value.c_str() || *end != '\0' ||
        candidate >= INT_MAX || candidate <= INT_MIN) {
        return false;
    }
    parsed = static_cast<int>(candidate);
    return true;
}

bool applyParameter(const std::string& name,
                    const std::string& value,
                    PwqualityEffectiveState& state,
                    std::string& error)
{
    int parsed = 0;
    const auto integer = [&](int& target) {
        if (!parseInteger(value, parsed)) {
            error = "invalid integer value for pwquality option " + name;
            return false;
        }
        target = parsed;
        return true;
    };

    if (name == "difok") {
        return integer(state.difok);
    }
    if (name == "minlen") {
        if (!integer(state.minlen)) {
            return false;
        }
        state.minlen = std::max(state.minlen, 6);
        return true;
    }
    if (name == "dcredit") {
        return integer(state.dcredit);
    }
    if (name == "ucredit") {
        return integer(state.ucredit);
    }
    if (name == "lcredit") {
        return integer(state.lcredit);
    }
    if (name == "ocredit") {
        return integer(state.ocredit);
    }
    if (name == "minclass") {
        if (!integer(state.minclass)) {
            return false;
        }
        state.minclass = std::min(state.minclass, 4);
        return true;
    }
    if (name == "maxrepeat") {
        return integer(state.maxrepeat);
    }
    if (name == "maxclassrepeat") {
        return integer(state.maxclassrepeat);
    }
    if (name == "maxsequence") {
        return integer(state.maxsequence);
    }
    if (name == "gecoscheck") {
        return integer(state.gecoscheck);
    }
    if (name == "dictcheck") {
        return integer(state.dictcheck);
    }
    if (name == "usercheck") {
        return integer(state.usercheck);
    }
    if (name == "usersubstr") {
        return integer(state.usersubstr);
    }
    if (name == "enforcing") {
        return integer(state.enforcing);
    }
    if (name == "retry") {
        return integer(state.retry);
    }
    if (name == "enforce_for_root") {
        state.enforceForRoot = true;
        return true;
    }
    if (name == "local_users_only") {
        state.localUsersOnly = true;
        return true;
    }
    if (name == "badwords") {
        state.badwords = value;
        return true;
    }
    if (name == "dictpath") {
        state.dictpath = value;
        return true;
    }
    error = "unknown pwquality option " + name;
    return false;
}

bool parseConfigLine(const std::string& raw,
                     PwqualityEffectiveState& state,
                     std::string& error,
                     const ManagedOverride* managedOverride = nullptr)
{
    std::string line = raw;
    const std::size_t comment = line.find('#');
    if (comment != std::string::npos) {
        line.erase(comment);
    }
    line = trimCopy(std::move(line));
    if (line.empty()) {
        return true;
    }

    std::size_t delimiter = 0;
    while (delimiter < line.size() &&
           std::isspace(static_cast<unsigned char>(line[delimiter])) == 0 &&
           line[delimiter] != '=') {
        ++delimiter;
    }
    const std::string name = lowercaseCopy(line.substr(0, delimiter));
    if (name.empty()) {
        error = "malformed pwquality directive";
        return false;
    }
    std::size_t valueStart = delimiter;
    bool equalsSeen = false;
    while (valueStart < line.size()) {
        if (line[valueStart] == '=' && !equalsSeen) {
            equalsSeen = true;
            ++valueStart;
            continue;
        }
        if (std::isspace(
                static_cast<unsigned char>(line[valueStart])) == 0) {
            break;
        }
        ++valueStart;
    }
    if (managedOverride != nullptr && name == managedOverride->option) {
        return true;
    }
    return applyParameter(name, line.substr(valueStart), state, error);
}

bool inspectTrustedPath(const std::filesystem::path& path,
                        bool directory,
                        bool& exists,
                        std::string& error)
{
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        if (errno == ENOENT) {
            exists = false;
            return true;
        }
        error = "could not inspect pwquality configuration input " +
            path.string() + ": " + std::strerror(errno);
        return false;
    }
    exists = true;
    if (S_ISLNK(info.st_mode) ||
        (directory ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode))) {
        error = "unsafe pwquality configuration input: " + path.string();
        return false;
    }
    if (info.st_uid != ::geteuid() ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        error = "untrusted pwquality configuration input: " + path.string();
        return false;
    }
    if (!directory && (info.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) == 0) {
        error = "unreadable pwquality configuration input: " + path.string();
        return false;
    }
    return true;
}

bool evaluateFile(const std::filesystem::path& path,
                  PwqualityEffectiveState& state,
                  std::string& error,
                  const ManagedOverride* managedOverride = nullptr)
{
    bool exists = false;
    if (!inspectTrustedPath(path, false, exists, error) || !exists) {
        if (!exists && error.empty()) {
            error = "pwquality configuration file does not exist: " +
                path.string();
        }
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        error = "could not open pwquality configuration file " + path.string();
        return false;
    }
    std::string line;
    std::size_t lineNumber = 0;
    while (std::getline(input, line)) {
        ++lineNumber;
        if (line.size() >= MaximumFgetsPayloadLength) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                ": pwquality configuration line is too long";
            return false;
        }
        std::string lineError;
        if (!parseConfigLine(line, state, lineError, managedOverride)) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                ": " + lineError;
            return false;
        }
    }
    if (!input.eof()) {
        error = "could not read pwquality configuration file " + path.string();
        return false;
    }
    return true;
}

bool evaluateDropInDirectory(const std::filesystem::path& directory,
                             PwqualityEffectiveState& state,
                             std::string& error)
{
    bool exists = false;
    if (!inspectTrustedPath(directory, true, exists, error)) {
        return false;
    }
    if (!exists) {
        return true;
    }
    std::error_code iterationError;
    std::vector<std::filesystem::path> files;
    for (std::filesystem::directory_iterator iterator(directory, iterationError),
         end;
         !iterationError && iterator != end;
         iterator.increment(iterationError)) {
        const auto name = iterator->path().filename().string();
        const std::size_t suffix = name.find(".conf");
        if (suffix != std::string::npos && suffix + 5 == name.size()) {
            files.push_back(iterator->path());
        }
    }
    if (iterationError) {
        error = "could not enumerate pwquality drop-in directory " +
            directory.string() + ": " + iterationError.message();
        return false;
    }
    std::sort(files.begin(), files.end(), [](const auto& left,
                                              const auto& right) {
        return left.filename().string() < right.filename().string();
    });
    for (const auto& path : files) {
        if (!evaluateFile(path, state, error)) {
            return false;
        }
    }
    return true;
}

bool evaluateTopology(
    const fic::platform::PamProviderConfigTopology& topology,
    PwqualityEffectiveState& state,
    std::string& error)
{
    if (topology.precedence !=
        fic::platform::PamConfigPrecedence::DropInsThenPrimary) {
        error = "unsupported pwquality configuration precedence";
        return false;
    }
    for (const auto& directory : topology.dropInDirectories) {
        if (!evaluateDropInDirectory(directory, state, error)) {
            return false;
        }
    }

    std::vector<std::filesystem::path> mainCandidates;
    if (topology.primaryPath.has_value()) {
        mainCandidates.push_back(*topology.primaryPath);
    }
    mainCandidates.insert(mainCandidates.end(),
                          topology.fallbackPaths.begin(),
                          topology.fallbackPaths.end());
    for (const auto& candidate : mainCandidates) {
        bool exists = false;
        if (!inspectTrustedPath(candidate, false, exists, error)) {
            return false;
        }
        if (exists) {
            return evaluateFile(candidate, state, error);
        }
    }
    if (!topology.primaryOptionalIfMissing) {
        error = "pwquality primary configuration file does not exist";
        return false;
    }
    return true;
}

bool evaluateProspectiveTopology(
    const fic::platform::PamProviderConfigTopology& topology,
    const ManagedOverride& managedOverride,
    PwqualityEffectiveState& state,
    std::string& error)
{
    if (topology.precedence !=
        fic::platform::PamConfigPrecedence::DropInsThenPrimary) {
        error = "unsupported pwquality configuration precedence";
        return false;
    }
    for (const auto& directory : topology.dropInDirectories) {
        if (!evaluateDropInDirectory(directory, state, error)) {
            return false;
        }
    }
    if (!topology.primaryPath.has_value()) {
        error = "pwquality managed topology has no primary path";
        return false;
    }

    bool primaryExists = false;
    if (!inspectTrustedPath(
            *topology.primaryPath, false, primaryExists, error)) {
        return false;
    }
    if (primaryExists &&
        !evaluateFile(
            *topology.primaryPath, state, error, &managedOverride)) {
        return false;
    }

    if (managedOverride.kind == ManagedOverrideKind::Assignment) {
        return applyParameter(
            managedOverride.option, managedOverride.value, state, error);
    }
    if (managedOverride.enabled) {
        return applyParameter(
            managedOverride.option, std::string{}, state, error);
    }
    return true;
}

bool ignoredPamArgument(const std::string& argument)
{
    return argument == "debug" ||
        argument.compare(0, 5, "type=") == 0 ||
        argument.compare(0, 10, "difignore=") == 0 ||
        argument.compare(0, 15, "reject_username") == 0 ||
        argument.compare(0, 12, "authtok_type") == 0 ||
        argument.compare(0, 11, "use_authtok") == 0 ||
        argument.compare(0, 14, "use_first_pass") == 0 ||
        argument.compare(0, 14, "try_first_pass") == 0;
}

bool applyPamArguments(const std::vector<std::string>& arguments,
                       const std::filesystem::path& source,
                       std::size_t line,
                       PwqualityEffectiveState& state,
                       std::string& error)
{
    for (const auto& argument : arguments) {
        if (ignoredPamArgument(argument)) {
            continue;
        }
        const std::size_t equals = argument.find('=');
        const std::string name = lowercaseCopy(argument.substr(0, equals));
        const std::string value = equals == std::string::npos
            ? std::string{}
            : argument.substr(equals + 1);
        std::string parameterError;
        if (!applyParameter(name, value, state, parameterError)) {
            error = source.string() + ":" + std::to_string(line) +
                ": invalid pam_pwquality argument " + argument + ": " +
                parameterError;
            return false;
        }
    }
    return true;
}

} // namespace

bool PwqualityEffectiveState::managedValue(const std::string& option,
                                           std::string& value,
                                           std::string& error) const
{
    const int* integer = nullptr;
    if (option == "difok") integer = &difok;
    else if (option == "minlen") integer = &minlen;
    else if (option == "dcredit") integer = &dcredit;
    else if (option == "ucredit") integer = &ucredit;
    else if (option == "lcredit") integer = &lcredit;
    else if (option == "ocredit") integer = &ocredit;
    else if (option == "minclass") integer = &minclass;
    else if (option == "gecoscheck") integer = &gecoscheck;
    else if (option == "usercheck") integer = &usercheck;
    else if (option == "enforcing") integer = &enforcing;
    if (integer == nullptr) {
        error = "unsupported managed pwquality option " + option;
        return false;
    }
    value = std::to_string(*integer);
    return true;
}

bool PwqualityConfigEvaluator::evaluateInvocation(
    const std::vector<std::string>& arguments,
    const std::filesystem::path& source,
    std::size_t line,
    const fic::platform::PamProviderConfigTopology& topology,
    PwqualityEffectiveState& state,
    std::string& error)
{
    error.clear();
    state = PwqualityEffectiveState{};
    if (!evaluateTopology(topology, state, error)) {
        return false;
    }
    return applyPamArguments(arguments, source, line, state, error);
}

bool PwqualityConfigEvaluator::evaluateInvocationWithManagedOption(
    const std::vector<std::string>& arguments,
    const std::filesystem::path& source,
    std::size_t line,
    const fic::platform::PamProviderConfigTopology& topology,
    const std::string& option,
    const std::string& expectedValue,
    PwqualityEffectiveState& state,
    std::string& error)
{
    error.clear();
    state = PwqualityEffectiveState{};
    const ManagedOverride managedOverride{
        ManagedOverrideKind::Assignment,
        lowercaseCopy(option),
        expectedValue,
        false};
    return evaluateProspectiveTopology(
               topology, managedOverride, state, error) &&
        applyPamArguments(arguments, source, line, state, error);
}

bool PwqualityConfigEvaluator::evaluateInvocationWithManagedFlag(
    const std::vector<std::string>& arguments,
    const std::filesystem::path& source,
    std::size_t line,
    const fic::platform::PamProviderConfigTopology& topology,
    const std::string& flag,
    bool expectedEnabled,
    PwqualityEffectiveState& state,
    std::string& error)
{
    error.clear();
    state = PwqualityEffectiveState{};
    const ManagedOverride managedOverride{
        ManagedOverrideKind::Flag,
        lowercaseCopy(flag),
        {},
        expectedEnabled};
    return evaluateProspectiveTopology(
               topology, managedOverride, state, error) &&
        applyPamArguments(arguments, source, line, state, error);
}

} // namespace fic::identity::pam
