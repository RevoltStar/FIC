#include "modules/identity_access/submodules/password_aging/PasswordAgingRuntime.h"

#include <fic/core/CommandHashStore.h>
#include <fic/core/VerifiedProcessExecutor.h>

#include <charconv>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <map>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace fic::identity::password_aging {
namespace {

bool validAccountArgument(const std::string& name) {
    return !name.empty() && name.find('\0') == std::string::npos;
}

bool validTcbPathComponent(const std::string& name) {
    return validAccountArgument(name) && name != "." && name != ".." &&
        name.find('/') == std::string::npos;
}

int verifyRegularDescriptor(
    int descriptor,
    const std::string& displayPath,
    std::string& error) {
    if (descriptor < 0) {
        return -1;
    }
    struct stat info {};
    if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)) {
        error = "local account path is not a regular file: " + displayPath;
        ::close(descriptor);
        return -1;
    }
    return descriptor;
}

int openRegularNoFollow(
    const std::filesystem::path& path,
    bool missingAllowed,
    std::string& error) {
    const int descriptor = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        const int errorNumber = errno;
        if (missingAllowed && errorNumber == ENOENT) {
            error.clear();
            return -1;
        }
        error = "cannot open local account file " + path.string() + ": " +
            std::strerror(errorNumber);
        return -1;
    }
    return verifyRegularDescriptor(descriptor, path.string(), error);
}

int openRegularAtNoFollow(
    int directory,
    const char* name,
    const std::string& displayPath,
    bool missingAllowed,
    std::string& error) {
    const int descriptor = ::openat(
        directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        const int errorNumber = errno;
        if (missingAllowed && errorNumber == ENOENT) {
            error.clear();
            return -1;
        }
        error = "cannot open local account file " + displayPath + ": " +
            std::strerror(errorNumber);
        return -1;
    }
    return verifyRegularDescriptor(descriptor, displayPath, error);
}

FILE* descriptorStream(
    int descriptor,
    const std::string& displayPath,
    std::string& error) {
    FILE* file = ::fdopen(descriptor, "r");
    if (file == nullptr) {
        error = "cannot create local account stream " + displayPath + ": " +
            std::strerror(errno);
        ::close(descriptor);
    }
    return file;
}

std::vector<std::string_view> splitRecord(
    const std::string& line,
    char delimiter) {
    std::vector<std::string_view> fields;
    std::size_t start = 0;
    for (;;) {
        const std::size_t end = line.find(delimiter, start);
        if (end == std::string::npos) {
            fields.emplace_back(line.data() + start, line.size() - start);
            return fields;
        }
        fields.emplace_back(line.data() + start, end - start);
        start = end + 1;
    }
}

template <typename Integer>
bool parseUnsignedField(std::string_view value, Integer& parsed) {
    if (value.empty()) {
        return false;
    }
    std::uintmax_t wide = 0;
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), wide, 10);
    if (result.ec != std::errc{} ||
        result.ptr != value.data() + value.size() ||
        wide > static_cast<std::uintmax_t>(
                   std::numeric_limits<Integer>::max())) {
        return false;
    }
    parsed = static_cast<Integer>(wide);
    return true;
}

bool parseShadowAgingField(std::string_view value, long& parsed) {
    if (value.empty()) {
        parsed = -1;
        return true;
    }
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed, 10);
    return result.ec == std::errc{} &&
        result.ptr == value.data() + value.size() && parsed >= -1;
}

bool parsePasswdRecord(
    const std::string& line,
    LocalPasswdAccount& account,
    std::string& error) {
    const std::vector<std::string_view> fields = splitRecord(line, ':');
    if (fields.size() != 7 || fields[0].empty()) {
        error = "malformed local passwd record";
        return false;
    }
    const std::string name(fields[0]);
    if (!validAccountArgument(name)) {
        error = "invalid local passwd account name";
        return false;
    }
    uid_t uid = 0;
    gid_t gid = 0;
    if (!parseUnsignedField(fields[2], uid) ||
        !parseUnsignedField(fields[3], gid)) {
        error = "invalid numeric field in local passwd account: " + name;
        return false;
    }
    account = {name, uid};
    return true;
}

bool parseShadowRecord(
    const std::string& line,
    std::string& name,
    ShadowAgingState& aging,
    std::string& error) {
    const std::vector<std::string_view> fields = splitRecord(line, ':');
    if (fields.size() != 9 || fields[0].empty()) {
        error = "malformed local shadow record";
        return false;
    }
    name.assign(fields[0]);
    if (!validAccountArgument(name)) {
        error = "invalid local shadow account name";
        return false;
    }
    long inactive = -1;
    long expire = -1;
    if (!parseShadowAgingField(fields[2], aging.lastChange) ||
        !parseShadowAgingField(fields[3], aging.minDays) ||
        !parseShadowAgingField(fields[4], aging.maxDays) ||
        !parseShadowAgingField(fields[5], aging.warningDays) ||
        !parseShadowAgingField(fields[6], inactive) ||
        !parseShadowAgingField(fields[7], expire)) {
        error = "invalid numeric field in local shadow account: " + name;
        return false;
    }
    if (!fields[8].empty()) {
        unsigned long flag = 0;
        if (!parseUnsignedField(fields[8], flag)) {
            error = "invalid flag field in local shadow account: " + name;
            return false;
        }
    }
    return true;
}

template <typename Callback>
bool readPhysicalRecords(
    FILE* file,
    const std::string& displayPath,
    Callback callback,
    std::string& error) {
    char* buffer = nullptr;
    std::size_t capacity = 0;
    std::size_t lineNumber = 0;
    for (;;) {
        errno = 0;
        const ssize_t count = ::getline(&buffer, &capacity, file);
        if (count < 0) {
            const bool failed = ::ferror(file) != 0;
            const int errorNumber = errno;
            std::free(buffer);
            if (failed) {
                error = "cannot read local account file " + displayPath +
                    ": " + std::strerror(errorNumber);
                return false;
            }
            return true;
        }
        ++lineNumber;
        std::size_t length = static_cast<std::size_t>(count);
        if (length != 0 && buffer[length - 1] == '\n') {
            --length;
        }
        const std::string line(buffer, length);
        if (line.find('\0') != std::string::npos) {
            std::free(buffer);
            error = displayPath + ":" + std::to_string(lineNumber) +
                ": embedded NUL in local account record";
            return false;
        }
        if (line.empty()) {
            continue;
        }
        std::string recordError;
        if (!callback(line, recordError)) {
            std::free(buffer);
            error = displayPath + ":" + std::to_string(lineNumber) +
                ": " + recordError;
            return false;
        }
    }
}

bool addShadowRecord(
    const std::string& line,
    LocalAccountSnapshot& accounts,
    std::string& error) {
    std::string name;
    ShadowAgingState aging;
    if (!parseShadowRecord(line, name, aging, error)) {
        return false;
    }
    const auto inserted = accounts.shadowAccounts.emplace(
        name, aging);
    if (!inserted.second) {
        error = "duplicate local shadow account: " + name;
        return false;
    }
    return true;
}

bool readShadowFile(
    const std::filesystem::path& path,
    LocalAccountSnapshot& accounts,
    std::string& error,
    bool missingAllowed) {
    const int descriptor = openRegularNoFollow(path, missingAllowed, error);
    if (descriptor < 0) {
        if (missingAllowed && error.empty()) {
            return true;
        }
        return false;
    }
    FILE* file = descriptorStream(descriptor, path.string(), error);
    if (file == nullptr) {
        return false;
    }
    const bool result = readPhysicalRecords(
        file, path.string(),
        [&](const std::string& line, std::string& recordError) {
            return addShadowRecord(line, accounts, recordError);
        },
        error);
    ::fclose(file);
    return result;
}

bool readTcbShadow(
    int tcbRoot,
    const std::filesystem::path& tcbPath,
    const LocalPasswdAccount& account,
    LocalAccountSnapshot& accounts,
    std::string& error) {
    if (!validTcbPathComponent(account.name)) {
        error = "local account name is unsafe as a TCB path component: " +
            account.name;
        return false;
    }
    const int userDirectory = ::openat(
        tcbRoot,
        account.name.c_str(),
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK);
    if (userDirectory < 0) {
        const int errorNumber = errno;
        if (errorNumber == ENOENT) {
            return true;
        }
        error = "cannot open local TCB account directory " +
            (tcbPath / account.name).string() + ": " +
            std::strerror(errorNumber);
        return false;
    }

    const std::string displayPath =
        (tcbPath / account.name / "shadow").string();
    const int shadowDescriptor = openRegularAtNoFollow(
        userDirectory, "shadow", displayPath, true, error);
    ::close(userDirectory);
    if (shadowDescriptor < 0) {
        return error.empty();
    }
    FILE* file = descriptorStream(shadowDescriptor, displayPath, error);
    if (file == nullptr) {
        return false;
    }
    std::size_t records = 0;
    std::string parsedName;
    const bool result = readPhysicalRecords(
        file, displayPath,
        [&](const std::string& line, std::string& recordError) {
            std::string name;
            ShadowAgingState aging;
            if (!parseShadowRecord(line, name, aging, recordError)) {
                return false;
            }
            ++records;
            parsedName = name;
            if (name != account.name) {
                recordError =
                    "TCB shadow record does not match its local account";
                return false;
            }
            const auto inserted = accounts.shadowAccounts.emplace(name, aging);
            if (!inserted.second) {
                recordError = "duplicate local shadow account: " + name;
                return false;
            }
            return true;
        },
        error);
    ::fclose(file);
    if (!result) {
        return false;
    }
    if (records != 1 || parsedName != account.name) {
        error = "TCB shadow file does not contain exactly its local account: " +
            account.name;
        return false;
    }
    return true;
}

} // namespace

PasswordAgingRuntime::PasswordAgingRuntime(
    fic::platform::PasswordAgingPlatformConfig platform,
    const fic::platform::PlatformExecutableResolver& executables,
    PasswordAgingCommandRunner runner,
    PasswordAgingTrustVerifier trustVerifier,
    LocalAccountReader accountReader)
    : platform_(std::move(platform)),
      executables_(executables),
      runner_(std::move(runner)),
      trustVerifier_(std::move(trustVerifier)),
      accountReader_(std::move(accountReader)) {
    if (!runner_) {
        runner_ = [](const std::string& executable,
                     const std::vector<std::string>& arguments) {
            return VerifiedProcessExecutor::execute(executable, arguments);
        };
    }
    if (!trustVerifier_) {
        trustVerifier_ = CommandHashStore::verifyHash;
    }
    if (!accountReader_) {
        accountReader_ = readLocalAccounts;
    }
}

bool PasswordAgingRuntime::preflight(
    std::filesystem::path& chage,
    LocalAccountSnapshot& accounts,
    std::string& error) const {
    if (!executables_.resolve(
            fic::platform::ExecutableId::Chage, chage, error)) {
        return false;
    }
    if (!trustVerifier_(chage.string(), error)) {
        return false;
    }
    return readAccounts(accounts, error);
}

bool PasswordAgingRuntime::readAccounts(
    LocalAccountSnapshot& accounts,
    std::string& error) const {
    return accountReader_(platform_, accounts, error);
}

ProcessResult PasswordAgingRuntime::apply(
    const std::filesystem::path& chage,
    const std::string& user,
    long minDays,
    long maxDays,
    long warningDays) const {
    if (!validAccountArgument(user)) {
        ProcessResult result;
        result.error = "invalid local account name";
        return result;
    }
    return runner_(chage.string(), {
        "-m", std::to_string(minDays),
        "-M", std::to_string(maxDays),
        "-W", std::to_string(warningDays),
        "--", user});
}

bool PasswordAgingRuntime::readLocalAccounts(
    const fic::platform::PasswordAgingPlatformConfig& platform,
    LocalAccountSnapshot& accounts,
    std::string& error) {
    accounts = {};
    const int passwdDescriptor = openRegularNoFollow(
        platform.passwdPath, false, error);
    if (passwdDescriptor < 0) {
        return false;
    }
    FILE* passwdFile = descriptorStream(
        passwdDescriptor, platform.passwdPath.string(), error);
    if (passwdFile == nullptr) {
        return false;
    }
    std::map<std::string, bool> names;
    const bool passwdResult = readPhysicalRecords(
        passwdFile,
        platform.passwdPath.string(),
        [&](const std::string& line, std::string& recordError) {
            LocalPasswdAccount account;
            if (!parsePasswdRecord(line, account, recordError)) {
                return false;
            }
            if (!names.emplace(account.name, true).second) {
                recordError =
                    "duplicate local passwd account: " + account.name;
                return false;
            }
            accounts.passwdAccounts.push_back(std::move(account));
            return true;
        },
        error);
    ::fclose(passwdFile);
    if (!passwdResult) {
        return false;
    }

    if (platform.shadowKind == fic::platform::LocalShadowKind::ShadowFile) {
        return readShadowFile(platform.shadowPath, accounts, error, false);
    }
    const int tcbRoot = ::open(
        platform.tcbDirectory.c_str(),
        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK);
    if (tcbRoot < 0) {
        error = "cannot open local TCB root directory " +
            platform.tcbDirectory.string() + ": " + std::strerror(errno);
        return false;
    }
    for (const LocalPasswdAccount& account : accounts.passwdAccounts) {
        if (!readTcbShadow(
                tcbRoot, platform.tcbDirectory, account, accounts, error)) {
            ::close(tcbRoot);
            return false;
        }
    }
    ::close(tcbRoot);
    return true;
}

} // namespace fic::identity::password_aging
