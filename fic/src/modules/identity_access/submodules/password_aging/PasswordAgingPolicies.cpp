#include "modules/identity_access/submodules/password_aging/PasswordAgingPolicies.h"

#include "modules/identity_access/configuration/LoginDefsFileHandler.h"

#include <charconv>
#include <climits>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <sstream>
#include <utility>

using namespace fic::identity::password_aging;
using fic::identity::LoginDefsFileHandler;
using fic::identity::LoginDefsValue;
using fic::identity::LoginDefsValueState;

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

bool parseUid(const std::string& value, uid_t& out) {
    if (value.empty()) {
        return false;
    }
    std::uintmax_t parsed = 0;
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed, 10);
    if (result.ec != std::errc{} ||
        result.ptr != value.data() + value.size() ||
        parsed > static_cast<std::uintmax_t>(
                     std::numeric_limits<uid_t>::max())) {
        return false;
    }
    out = static_cast<uid_t>(parsed);
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
    Relation relation,
    fic::platform::PasswordAgingPlatformConfig platform,
    std::unique_ptr<PolicyTypeValue> valueType,
    AtomicWriteOptions writeOptions)
    : IdentityAccessPolicy(kSubmodule),
      key_(key),
      relation_(relation),
      platform_(std::move(platform)),
      writeOptions_(std::move(writeOptions)) {
    writeOptions_.createIfMissing = false;
    writeOptions_.rejectSymlink = true;
    this->policyName = policyName;
    this->policyTypeValue = std::move(valueType);
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

    auto readPasswordPeer = [&](const char* key, long missingValue,
                                long min, long max, long& value) {
        const LoginDefsValue peer = file.lookup(key);
        if (peer.state == LoginDefsValueState::Duplicate ||
            peer.state == LoginDefsValueState::Malformed) {
            return false;
        }
        return peer.state == LoginDefsValueState::Missing
            ? (value = missingValue, true)
            : parseLong(peer.value, min, max, value);
    };

    const auto relationIsValid = [&]() {
        switch (relation_) {
        case Relation::PasswordMinimum: {
            long requested = 0;
            long peer = 0;
            return parseLong(*expected, 0, INT_MAX, requested) &&
                readPasswordPeer(
                    "PASS_MAX_DAYS",
                    platform_.missingKeySemantics.maxDays,
                    -1,
                    INT_MAX,
                    peer) &&
                passwordRelationValid(requested, peer);
        }
        case Relation::PasswordMaximum: {
            long requested = 0;
            long peer = 0;
            return parseLong(*expected, -1, INT_MAX, requested) &&
                readPasswordPeer(
                    "PASS_MIN_DAYS",
                    platform_.missingKeySemantics.minDays,
                    -1,
                    INT_MAX,
                    peer) &&
                passwordRelationValid(peer, requested);
        }
        case Relation::UidMinimum:
        case Relation::UidMaximum: {
            uid_t requested = 0;
            if (!parseUid(*expected, requested)) {
                return false;
            }
            const char* peerKey = relation_ == Relation::UidMinimum
                ? "UID_MAX"
                : "UID_MIN";
            const LoginDefsValue peerValue = file.lookup(peerKey);
            uid_t peer = 0;
            if (peerValue.state != LoginDefsValueState::Unique ||
                !parseUid(peerValue.value, peer)) {
                return false;
            }
            return relation_ == Relation::UidMinimum
                ? requested <= peer
                : peer <= requested;
        }
        case Relation::None:
            if (key_ == "PASS_WARN_AGE") {
                long requested = 0;
                return parseLong(*expected, -1, INT_MAX, requested);
            }
            return false;
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
          "password_min_age_days", "PASS_MIN_DAYS", Relation::PasswordMinimum,
          platform,
          std::make_unique<IntPolicyTypeValue>(
              0, INT_MAX, static_cast<int>(platform.policyDefaults.minDays)),
          std::move(options)) {}

PasswordMaxAgeDaysPolicy::PasswordMaxAgeDaysPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions options)
    : LoginDefsOptionPolicy(
          "password_max_age_days", "PASS_MAX_DAYS", Relation::PasswordMaximum,
          platform,
          std::make_unique<IntPolicyTypeValue>(
              -1, INT_MAX, static_cast<int>(platform.policyDefaults.maxDays)),
          std::move(options)) {}

PasswordExpirationWarningDaysPolicy::PasswordExpirationWarningDaysPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions options)
    : LoginDefsOptionPolicy(
          "password_expiration_warning_days", "PASS_WARN_AGE", Relation::None,
          platform,
          std::make_unique<IntPolicyTypeValue>(
              -1, INT_MAX,
              static_cast<int>(platform.policyDefaults.warningDays)),
          std::move(options)) {}

RegularUserUidMinPolicy::RegularUserUidMinPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions options)
    : LoginDefsOptionPolicy(
          "regular_user_uid_min", "UID_MIN", Relation::UidMinimum,
          platform,
          std::make_unique<UnsignedIntegerPolicyTypeValue>(
              0,
              std::numeric_limits<uid_t>::max(),
              platform.policyDefaults.uidMin),
          std::move(options)) {}

RegularUserUidMaxPolicy::RegularUserUidMaxPolicy(
    fic::platform::PasswordAgingPlatformConfig platform,
    AtomicWriteOptions options)
    : LoginDefsOptionPolicy(
          "regular_user_uid_max", "UID_MAX", Relation::UidMaximum,
          platform,
          std::make_unique<UnsignedIntegerPolicyTypeValue>(
              0,
              std::numeric_limits<uid_t>::max(),
              platform.policyDefaults.uidMax),
          std::move(options)) {}

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
    uid_t& uidMin, uid_t& uidMax, bool requireUidRange) {
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
    if (requireUidRange) {
        auto readUid = [&](const char* key, uid_t& out) {
            const LoginDefsValue value = file.lookup(key);
            if (value.state != LoginDefsValueState::Unique ||
                !parseUid(value.value, out)) {
                log("Missing, ambiguous or invalid UID login.defs parameter: " +
                        std::string(key),
                    logLevel::ERROR);
                return false;
            }
            return true;
        };
        if (!readUid("UID_MIN", uidMin) || !readUid("UID_MAX", uidMax)) {
            return false;
        }
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
        if (before.shadowAccounts.count(account.name) != 1) {
            log("Local password aging state is missing for user=" +
                    account.name + " uid=" + std::to_string(account.uid),
                logLevel::ERROR);
            return false;
        }
    }
    for (const LocalPasswdAccount& account : targets) {
        const auto oldIt = before.shadowAccounts.find(account.name);
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
    long minDays, maxDays, warningDays;
    uid_t uidMin = 0;
    uid_t uidMax = 0;
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
        if (account.uid != 0 && account.uid >= uidMin && account.uid <= uidMax) {
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
    long minDays, maxDays, warningDays;
    uid_t uidMin = 0;
    uid_t uidMax = 0;
    if (!loadExpected(
            minDays, maxDays, warningDays, uidMin, uidMax, false)) return false;
    std::filesystem::path chage;
    LocalAccountSnapshot accounts;
    std::string error;
    if (!runtime_.preflight(chage, accounts, error)) {
        log("Root password aging preflight failed: " + error, logLevel::ERROR);
        return false;
    }
    std::vector<LocalPasswdAccount> rootEquivalent;
    for (const LocalPasswdAccount& account : accounts.passwdAccounts) {
        if (account.uid == 0) rootEquivalent.push_back(account);
    }
    if (rootEquivalent.empty()) {
        log("No local root-equivalent UID 0 account was found",
            logLevel::ERROR);
        return false;
    }
    return synchronize(
        rootEquivalent, accounts, chage, minDays, maxDays, warningDays);
}
