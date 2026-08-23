#include "modules/identity_access/submodules/password_aging/PasswordAgingRuntime.h"

#include <fic/core/CommandHashStore.h>
#include <fic/core/VerifiedProcessExecutor.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <pwd.h>
#include <shadow.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace fic::identity::password_aging {
namespace {

bool validLocalName(const std::string& name) {
    return !name.empty() && name.front() != '-' &&
        name.find('/') == std::string::npos &&
        name.find('\0') == std::string::npos;
}

FILE* openRegularNoFollow(
    const std::filesystem::path& path,
    bool missingAllowed,
    std::string& error) {
    const int descriptor = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        if (missingAllowed && errno == ENOENT) {
            error.clear();
            return nullptr;
        }
        error = "cannot open local account file " + path.string() + ": " +
            std::strerror(errno);
        return nullptr;
    }
    struct stat info {};
    if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)) {
        error = "local account path is not a regular file: " + path.string();
        ::close(descriptor);
        return nullptr;
    }
    FILE* file = ::fdopen(descriptor, "r");
    if (file == nullptr) {
        error = "cannot create local account stream " + path.string() + ": " +
            std::strerror(errno);
        ::close(descriptor);
    }
    return file;
}

bool addShadowEntry(
    const spwd& entry,
    LocalAccountSnapshot& accounts,
    std::string& error) {
    if (entry.sp_namp == nullptr || !validLocalName(entry.sp_namp)) {
        error = "invalid local shadow account name";
        return false;
    }
    const std::string name(entry.sp_namp);
    const auto inserted = accounts.shadowAccounts.emplace(
        name,
        ShadowAgingState{
            entry.sp_lstchg, entry.sp_min, entry.sp_max, entry.sp_warn});
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
    errno = 0;
    FILE* file = openRegularNoFollow(path, missingAllowed, error);
    if (file == nullptr) {
        if (missingAllowed && error.empty()) {
            return true;
        }
        return false;
    }
    errno = 0;
    while (spwd* entry = ::fgetspent(file)) {
        if (!addShadowEntry(*entry, accounts, error)) {
            ::fclose(file);
            return false;
        }
        errno = 0;
    }
    const int readError = errno;
    ::fclose(file);
    if (readError != 0 && readError != ENOENT) {
        error = "cannot parse local shadow file " + path.string() + ": " +
            std::strerror(readError);
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
    if (!validLocalName(user)) {
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
    errno = 0;
    FILE* passwdFile = openRegularNoFollow(
        platform.passwdPath, false, error);
    if (passwdFile == nullptr) {
        return false;
    }
    std::map<std::string, bool> names;
    errno = 0;
    while (struct passwd* entry = ::fgetpwent(passwdFile)) {
        if (entry->pw_name == nullptr || !validLocalName(entry->pw_name)) {
            error = "invalid local passwd account name";
            ::fclose(passwdFile);
            return false;
        }
        const std::string name(entry->pw_name);
        if (!names.emplace(name, true).second) {
            error = "duplicate local passwd account: " + name;
            ::fclose(passwdFile);
            return false;
        }
        accounts.passwdAccounts.push_back(
            {name, static_cast<unsigned long>(entry->pw_uid)});
        errno = 0;
    }
    const int passwdError = errno;
    ::fclose(passwdFile);
    if (passwdError != 0 && passwdError != ENOENT) {
        error = "cannot parse local passwd file: " +
            std::string(std::strerror(passwdError));
        return false;
    }

    if (platform.shadowKind == fic::platform::LocalShadowKind::ShadowFile) {
        return readShadowFile(platform.shadowPath, accounts, error, false);
    }
    for (const LocalPasswdAccount& account : accounts.passwdAccounts) {
        const std::size_t before = accounts.shadowAccounts.size();
        if (!readShadowFile(
                platform.tcbDirectory / account.name / "shadow",
                accounts,
                error,
                true)) {
            return false;
        }
        if (accounts.shadowAccounts.size() != before &&
            (accounts.shadowAccounts.size() != before + 1 ||
             accounts.shadowAccounts.count(account.name) != 1)) {
            error = "TCB shadow file does not contain exactly its local account: " +
                account.name;
            return false;
        }
    }
    return true;
}

} // namespace fic::identity::password_aging
