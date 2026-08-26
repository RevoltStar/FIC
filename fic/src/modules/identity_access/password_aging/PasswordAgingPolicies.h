#ifndef FIC_IDENTITY_PASSWORD_AGING_POLICIES_H
#define FIC_IDENTITY_PASSWORD_AGING_POLICIES_H

#include "modules/identity_access/IdentityAccessPolicy.h"
#include "modules/identity_access/password_aging/PasswordAgingRuntime.h"
#include "platform/PlatformProfile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <memory>
#include <string>

class LoginDefsOptionPolicy : public IdentityAccessPolicy {
public:
    enum class Relation {
        PasswordMinimum,
        PasswordMaximum,
        UidMinimum,
        UidMaximum,
        None
    };

    bool apply() override;

protected:
    LoginDefsOptionPolicy(
        const std::string& policyName,
        const std::string& key,
        Relation relation,
        fic::platform::PasswordAgingPlatformConfig platform,
        std::unique_ptr<PolicyTypeValue> valueType,
        AtomicWriteOptions writeOptions = {});

private:
    std::string key_;
    Relation relation_;
    fic::platform::PasswordAgingPlatformConfig platform_;
    AtomicWriteOptions writeOptions_;
};

class PasswordMinAgeDaysPolicy final : public LoginDefsOptionPolicy {
public:
    explicit PasswordMinAgeDaysPolicy(
        fic::platform::PasswordAgingPlatformConfig platform,
        AtomicWriteOptions options = {});
};
class PasswordMaxAgeDaysPolicy final : public LoginDefsOptionPolicy {
public:
    explicit PasswordMaxAgeDaysPolicy(
        fic::platform::PasswordAgingPlatformConfig platform,
        AtomicWriteOptions options = {});
};
class PasswordExpirationWarningDaysPolicy final : public LoginDefsOptionPolicy {
public:
    explicit PasswordExpirationWarningDaysPolicy(
        fic::platform::PasswordAgingPlatformConfig platform,
        AtomicWriteOptions options = {});
};
class RegularUserUidMinPolicy final : public LoginDefsOptionPolicy {
public:
    explicit RegularUserUidMinPolicy(
        fic::platform::PasswordAgingPlatformConfig platform,
        AtomicWriteOptions options = {});
};
class RegularUserUidMaxPolicy final : public LoginDefsOptionPolicy {
public:
    explicit RegularUserUidMaxPolicy(
        fic::platform::PasswordAgingPlatformConfig platform,
        AtomicWriteOptions options = {});
};

class PasswordAgingOperationalPolicy : public IdentityAccessPolicy {
protected:
    PasswordAgingOperationalPolicy(
        const std::string& policyName,
        fic::platform::PasswordAgingPlatformConfig platform,
        fic::identity::password_aging::PasswordAgingRuntime runtime);

    bool loadExpected(
        long& minDays,
        long& maxDays,
        long& warningDays,
        uid_t& uidMin,
        uid_t& uidMax,
        bool requireUidRange);
    bool synchronize(
        const std::vector<fic::identity::password_aging::LocalPasswdAccount>& targets,
        const fic::identity::password_aging::LocalAccountSnapshot& before,
        const std::filesystem::path& chage,
        long minDays,
        long maxDays,
        long warningDays);

    fic::platform::PasswordAgingPlatformConfig platform_;
    fic::identity::password_aging::PasswordAgingRuntime runtime_;
};

class PasswordAgingApplyToExistingAccountsPolicy final
    : public PasswordAgingOperationalPolicy {
public:
    PasswordAgingApplyToExistingAccountsPolicy(
        fic::platform::PasswordAgingPlatformConfig platform,
        const fic::platform::PlatformExecutableResolver& executables);
    PasswordAgingApplyToExistingAccountsPolicy(
        fic::platform::PasswordAgingPlatformConfig platform,
        fic::identity::password_aging::PasswordAgingRuntime runtime);
    bool apply() override;
};

class PasswordAgingEnforceForRootPolicy final
    : public PasswordAgingOperationalPolicy {
public:
    PasswordAgingEnforceForRootPolicy(
        fic::platform::PasswordAgingPlatformConfig platform,
        const fic::platform::PlatformExecutableResolver& executables);
    PasswordAgingEnforceForRootPolicy(
        fic::platform::PasswordAgingPlatformConfig platform,
        fic::identity::password_aging::PasswordAgingRuntime runtime);
    bool apply() override;
};

#endif
