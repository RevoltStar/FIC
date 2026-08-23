#ifndef FIC_IDENTITY_PASSWORD_AGING_RUNTIME_H
#define FIC_IDENTITY_PASSWORD_AGING_RUNTIME_H

#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"

#include <fic/core/ProcessExecutor.h>

#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace fic::identity::password_aging {

struct LocalPasswdAccount {
    std::string name;
    unsigned long uid = 0;
};

struct ShadowAgingState {
    long lastChange = -1;
    long minDays = -1;
    long maxDays = -1;
    long warningDays = -1;
};

struct LocalAccountSnapshot {
    std::vector<LocalPasswdAccount> passwdAccounts;
    std::map<std::string, ShadowAgingState> shadowAccounts;
};

using PasswordAgingCommandRunner = std::function<ProcessResult(
    const std::string&, const std::vector<std::string>&)>;
using PasswordAgingTrustVerifier = std::function<bool(
    const std::string&, std::string&)>;
using LocalAccountReader = std::function<bool(
    const fic::platform::PasswordAgingPlatformConfig&,
    LocalAccountSnapshot&,
    std::string&)>;

class PasswordAgingRuntime {
public:
    PasswordAgingRuntime(
        fic::platform::PasswordAgingPlatformConfig platform,
        const fic::platform::PlatformExecutableResolver& executables,
        PasswordAgingCommandRunner runner = {},
        PasswordAgingTrustVerifier trustVerifier = {},
        LocalAccountReader accountReader = {});

    bool preflight(
        std::filesystem::path& chage,
        LocalAccountSnapshot& accounts,
        std::string& error) const;
    bool readAccounts(LocalAccountSnapshot& accounts, std::string& error) const;
    ProcessResult apply(
        const std::filesystem::path& chage,
        const std::string& user,
        long minDays,
        long maxDays,
        long warningDays) const;

    static bool readLocalAccounts(
        const fic::platform::PasswordAgingPlatformConfig& platform,
        LocalAccountSnapshot& accounts,
        std::string& error);

private:
    fic::platform::PasswordAgingPlatformConfig platform_;
    const fic::platform::PlatformExecutableResolver& executables_;
    PasswordAgingCommandRunner runner_;
    PasswordAgingTrustVerifier trustVerifier_;
    LocalAccountReader accountReader_;
};

} // namespace fic::identity::password_aging

#endif
