#include "modules/identity_access/submodules/password_aging/PasswordAgingPolicies.h"

#include "modules/identity_access/submodules/password_aging/LoginDefsFileHandler.h"

#include <climits>
#include <cerrno>
#include <cstdlib>
#include <sstream>
#include <utility>

using namespace fic::identity::password_aging;

namespace {

constexpr const char* kSubmodule = "PASSWORD_AGING";

bool parseLong(const std::string& value, long minimum, long maximum, long& out) {
    if (value.empty()) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str() || *end != '\0' ||
        parsed < minimum || parsed > maximum) {
        return false;
    }
    out = parsed;
    return true;
}

bool passwordRelationValid(long minimum, long maximum) {
    return maximum == -1 || minimum <= maximum;
}

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) return result.error;
    if (result.timedOut) return "timeout";
    if (!result.standardError.empty()) return result.standardError;
    return "exit_code=" + std::to_string(result.exitCode);
}

PolicyRef passwordAgingRef(const char* policy) {
    return {"IDENTITY_ACCESS", kSubmodule, policy};
}

} // namespace

LoginDefsOptionPolicy::LoginDefsOptionPolicy(
    const std::string& policyName,
    const std::string& key,
    int minimum,
    int maximum,
    int defaultValue,
    Relation relation,
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions writeOptions)
    : IdentityAccessPolicy(kSubmodule),
      key_(key),
      relation_(relation),
      platform_(std::move(platform)),
      writeOptions_(std::move(writeOptions)) {
    writeOptions_.createIfMissing = false;
    writeOptions_.rejectSymlink = true;
    this->policyName = policyName;
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(minimum, maximum, defaultValue);
}

bool LoginDefsOptionPolicy::apply() {
    const auto expected = getValue();
    if (!expected.has_value()) return false;

    const std::lock_guard<std::mutex> lock(configurationMutex());
    FileHandlerOptions options;
    options.writeOptions = writeOptions_;
    LoginDefsFileHandler file(platform_.loginDefsPath.string(), options);
    if (!file.loadConfig()) {
        log("Could not load " + platform_.loginDefsPath.string(), logLevel::ERROR);
        return false;
    }
    const LoginDefsValue current = file.lookup(key_);
    if (current.state == LoginDefsValueState::Duplicate ||
        current.state == LoginDefsValueState::Malformed) {
        log("Ambiguous login.defs parameter: " + key_, logLevel::ERROR);
        return false;
    }

    auto readPeer = [&](const char* key, int fallback, long min, long max,
                        long& value) {
        const LoginDefsValue peer = file.lookup(key);
        if (peer.state == LoginDefsValueState::Duplicate ||
            peer.state == LoginDefsValueState::Malformed) {
            return false;
        }
        return peer.state == LoginDefsValueState::Missing
            ? (value = fallback, true)
            : parseLong(peer.value, min, max, value);
    };

    long requested = 0;
    if (!parseLong(*expected, -1, INT_MAX, requested)) return false;
    const auto relationIsValid = [&]() {
        long peer = 0;
        switch (relation_) {
        case Relation::PasswordMinimum:
            return readPeer("PASS_MAX_DAYS", platform_.defaults.maxDays,
                            -1, INT_MAX, peer) &&
                passwordRelationValid(requested, peer);
        case Relation::PasswordMaximum:
            return readPeer("PASS_MIN_DAYS", platform_.defaults.minDays,
                            0, INT_MAX, peer) &&
                passwordRelationValid(peer, requested);
        case Relation::UidMinimum:
            return readPeer("UID_MAX", platform_.defaults.uidMax,
                            0, INT_MAX, peer) && requested <= peer;
        case Relation::UidMaximum:
            return readPeer("UID_MIN", platform_.defaults.uidMin,
                            0, INT_MAX, peer) && peer <= requested;
        case Relation::None:
            return true;
        }
        return false;
    };
    if (!relationIsValid()) {
        log("Resulting login.defs relation is invalid for " + key_,
            logLevel::ERROR);
        return false;
    }

    if (current.state == LoginDefsValueState::Unique &&
        current.value == *expected) {
        return true;
    }
    if (!file.setValue(key_, *expected) || !file.saveAndReload()) {
        log("Could not update login.defs parameter " + key_, logLevel::ERROR);
        return false;
    }
    const LoginDefsValue verified = file.lookup(key_);
    if (verified.state != LoginDefsValueState::Unique ||
        verified.value != *expected || !relationIsValid()) {
        log("login.defs postcondition failed for " + key_, logLevel::ERROR);
        return false;
    }
    return true;
}

PasswordMinAgeDaysPolicy::PasswordMinAgeDaysPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions options)
    : LoginDefsOptionPolicy(
          "password_min_age_days", "PASS_MIN_DAYS", 0, INT_MAX,
          platform.defaults.minDays, Relation::PasswordMinimum,
          std::move(platform), std::move(options)) {}

PasswordMaxAgeDaysPolicy::PasswordMaxAgeDaysPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions options)
    : LoginDefsOptionPolicy(
          "password_max_age_days", "PASS_MAX_DAYS", -1, INT_MAX,
          platform.defaults.maxDays, Relation::PasswordMaximum,
          std::move(platform), std::move(options)) {}

PasswordExpirationWarningDaysPolicy::PasswordExpirationWarningDaysPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions options)
    : LoginDefsOptionPolicy(
          "password_expiration_warning_days", "PASS_WARN_AGE", -1, INT_MAX,
          platform.defaults.warningDays, Relation::None,
          std::move(platform), std::move(options)) {}

RegularUserUidMinPolicy::RegularUserUidMinPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions options)
    : LoginDefsOptionPolicy(
          "regular_user_uid_min", "UID_MIN", 0, INT_MAX,
          platform.defaults.uidMin, Relation::UidMinimum,
          std::move(platform), std::move(options)) {}

RegularUserUidMaxPolicy::RegularUserUidMaxPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions options)
    : LoginDefsOptionPolicy(
          "regular_user_uid_max", "UID_MAX", 0, INT_MAX,
          platform.defaults.uidMax, Relation::UidMaximum,
          std::move(platform), std::move(options)) {}

PasswordAgingOperationalPolicy::PasswordAgingOperationalPolicy(
    const std::string& policyName,
    fic::platform::PasswordAgingPlatformConfig platform,
    PasswordAgingRuntime runtime)
    : IdentityAccessPolicy(kSubmodule),
      platform_(std::move(platform)),
      runtime_(std::move(runtime)) {
    this->policyName = policyName;
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>("yes");
}

bool PasswordAgingOperationalPolicy::loadExpected(
    long& minDays, long& maxDays, long& warningDays,
    long& uidMin, long& uidMax, bool requireUidRange) {
    FileHandlerOptions options;
    options.writeOptions.rejectSymlink = true;
    LoginDefsFileHandler file(platform_.loginDefsPath.string(), options);
    if (!file.loadConfig()) return false;
    auto read = [&](const char* key, long minimum, long maximum, long& out) {
        const LoginDefsValue value = file.lookup(key);
        if (value.state != LoginDefsValueState::Unique) {
            log("Missing or ambiguous login.defs parameter: " +
                std::string(key), logLevel::ERROR);
            return false;
        }
        if (!parseLong(value.value, minimum, maximum, out)) {
            log("Invalid numeric login.defs parameter: " +
                std::string(key), logLevel::ERROR);
            return false;
        }
        return true;
    };
    if (!read("PASS_MIN_DAYS", 0, INT_MAX, minDays) ||
        !read("PASS_MAX_DAYS", -1, INT_MAX, maxDays) ||
        !read("PASS_WARN_AGE", -1, INT_MAX, warningDays)) {
        return false;
    }
    if (requireUidRange &&
        (!read("UID_MIN", 0, INT_MAX, uidMin) ||
         !read("UID_MAX", 0, INT_MAX, uidMax))) {
        return false;
    }
    if (!passwordRelationValid(minDays, maxDays) ||
        (requireUidRange && uidMin > uidMax)) {
        log("Invalid relation in login.defs password aging settings",
            logLevel::ERROR);
        return false;
    }
    return true;
}

bool PasswordAgingOperationalPolicy::synchronize(
    const std::vector<LocalPasswdAccount>& targets,
    const LocalAccountSnapshot& before,
    const std::filesystem::path& chage,
    long minDays,
    long maxDays,
    long warningDays) {
    std::vector<std::string> changed;
    for (const LocalPasswdAccount& account : targets) {
        const auto oldIt = before.shadowAccounts.find(account.name);
        if (oldIt == before.shadowAccounts.end()) continue;
        const ShadowAgingState old = oldIt->second;
        if (old.minDays == minDays && old.maxDays == maxDays &&
            old.warningDays == warningDays) {
            continue;
        }
        const ProcessResult result = runtime_.apply(
            chage, account.name, minDays, maxDays, warningDays);
        if (!result.success()) {
            std::string changedUsers;
            for (const std::string& user : changed) {
                if (!changedUsers.empty()) changedUsers += ",";
                changedUsers += user;
            }
            log("chage failed for user=" + account.name + " uid=" +
                    std::to_string(account.uid) + ": " +
                    processFailure(result) + "; changed_before_failure=" +
                    (changedUsers.empty() ? std::string("none") : changedUsers),
                logLevel::ERROR);
            return false;
        }
        LocalAccountSnapshot after;
        std::string error;
        if (!runtime_.readAccounts(after, error)) {
            log("Could not verify chage for user=" + account.name + ": " + error,
                logLevel::ERROR);
            return false;
        }
        const auto newIt = after.shadowAccounts.find(account.name);
        if (newIt == after.shadowAccounts.end() ||
            newIt->second.minDays != minDays ||
            newIt->second.maxDays != maxDays ||
            newIt->second.warningDays != warningDays ||
            newIt->second.lastChange != old.lastChange) {
            log("Password aging postcondition failed for user=" + account.name +
                    "; sp_lstchg must remain unchanged",
                logLevel::ERROR);
            return false;
        }
        changed.push_back(account.name);
    }
    return true;
}

PasswordAgingApplyToExistingAccountsPolicy::
PasswordAgingApplyToExistingAccountsPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    const fic::platform::PlatformExecutableResolver& executables)
    : PasswordAgingApplyToExistingAccountsPolicy(
          platform, PasswordAgingRuntime(platform, executables)) {}

PasswordAgingApplyToExistingAccountsPolicy::
PasswordAgingApplyToExistingAccountsPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    PasswordAgingRuntime runtime)
    : PasswordAgingOperationalPolicy(
          "password_aging_apply_to_existing_accounts",
          std::move(platform), std::move(runtime)) {
    addRequiredDependency(passwordAgingRef("password_min_age_days"));
    addRequiredDependency(passwordAgingRef("password_max_age_days"));
    addRequiredDependency(passwordAgingRef("password_expiration_warning_days"));
    addRequiredDependency(passwordAgingRef("regular_user_uid_min"));
    addRequiredDependency(passwordAgingRef("regular_user_uid_max"));
}

bool PasswordAgingApplyToExistingAccountsPolicy::apply() {
    if (!getValue().has_value()) return false;
    const std::lock_guard<std::mutex> lock(configurationMutex());
    long minDays, maxDays, warningDays, uidMin, uidMax;
    if (!loadExpected(
            minDays, maxDays, warningDays, uidMin, uidMax, true)) return false;
    std::filesystem::path chage;
    LocalAccountSnapshot accounts;
    std::string error;
    if (!runtime_.preflight(chage, accounts, error)) {
        log("Password aging preflight failed: " + error, logLevel::ERROR);
        return false;
    }
    std::vector<LocalPasswdAccount> targets;
    for (const LocalPasswdAccount& account : accounts.passwdAccounts) {
        if (account.uid != 0 && account.uid >= static_cast<unsigned long>(uidMin) &&
            account.uid <= static_cast<unsigned long>(uidMax) &&
            accounts.shadowAccounts.count(account.name) != 0) {
            targets.push_back(account);
        }
    }
    return synchronize(targets, accounts, chage, minDays, maxDays, warningDays);
}

PasswordAgingEnforceForRootPolicy::PasswordAgingEnforceForRootPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    const fic::platform::PlatformExecutableResolver& executables)
    : PasswordAgingEnforceForRootPolicy(
          platform, PasswordAgingRuntime(platform, executables)) {}

PasswordAgingEnforceForRootPolicy::PasswordAgingEnforceForRootPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    PasswordAgingRuntime runtime)
    : PasswordAgingOperationalPolicy(
          "password_aging_enforce_for_root",
          std::move(platform), std::move(runtime)) {
    addRequiredDependency(passwordAgingRef("password_min_age_days"));
    addRequiredDependency(passwordAgingRef("password_max_age_days"));
    addRequiredDependency(passwordAgingRef("password_expiration_warning_days"));
}

bool PasswordAgingEnforceForRootPolicy::apply() {
    if (!getValue().has_value()) return false;
    const std::lock_guard<std::mutex> lock(configurationMutex());
    long minDays, maxDays, warningDays, uidMin, uidMax;
    if (!loadExpected(
            minDays, maxDays, warningDays, uidMin, uidMax, false)) return false;
    std::filesystem::path chage;
    LocalAccountSnapshot accounts;
    std::string error;
    if (!runtime_.preflight(chage, accounts, error)) {
        log("Root password aging preflight failed: " + error, logLevel::ERROR);
        return false;
    }
    std::vector<LocalPasswdAccount> root;
    for (const LocalPasswdAccount& account : accounts.passwdAccounts) {
        if (account.name == "root" && account.uid == 0) root.push_back(account);
    }
    if (root.size() != 1 || accounts.shadowAccounts.count("root") != 1) {
        log("Local root passwd/shadow state is missing or ambiguous",
            logLevel::ERROR);
        return false;
    }
    return synchronize(root, accounts, chage, minDays, maxDays, warningDays);
}
