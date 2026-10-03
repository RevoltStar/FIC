#ifndef FIC_IDENTITY_LOGIN_DEFS_POLICY_SPEC_H
#define FIC_IDENTITY_LOGIN_DEFS_POLICY_SPEC_H

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <limits>
#include <string>
#include <sys/types.h>

namespace fic::identity::login_defs {

// Single source of truth for the shared /etc/login.defs ownership domain:
// the exact whitelist of enrolled policies with their owning submodule,
// managed key, canonical value domain and native-consumer relation. The
// managed-config validator, the transaction backend and the MutationJournal
// undo validation all read this one table, so the writer and the loader can
// never drift apart. There is no default-positive routing: any policy not
// present here is unknown and fails closed.

// Native-consumer relation kind of an enrolled policy.
enum class Relation {
    None,
    PasswordMinimum,
    PasswordMaximum,
    UidMinimum,
    UidMaximum
};

// Canonical value domain of an enrolled policy.
enum class ValueDomain {
    Boolean,           // exactly "yes" or "no"
    NonNegativeDays,   // 0..INT_MAX, canonical decimal
    DaysWithUnlimited, // -1..INT_MAX (unlimited), canonical decimal
    Uid                // 0..numeric_limits<uid_t>::max(), canonical decimal
};

struct SharedLoginDefsPolicySpec {
    const char* policyName;
    const char* submodule; // USER_CREATION / PASSWORD_AGING
    const char* key;       // managed login.defs key
    ValueDomain domain;
    Relation relation;
};

inline const SharedLoginDefsPolicySpec* findSharedLoginDefsPolicySpec(
    const std::string& policyName) {
    static const SharedLoginDefsPolicySpec kSpecs[] = {
        {"user_create_home", "USER_CREATION", "CREATE_HOME",
            ValueDomain::Boolean, Relation::None},
        {"user_create_private_group", "USER_CREATION", "USERGROUPS_ENAB",
            ValueDomain::Boolean, Relation::None},
        {"password_min_age_days", "PASSWORD_AGING", "PASS_MIN_DAYS",
            ValueDomain::NonNegativeDays, Relation::PasswordMinimum},
        {"password_max_age_days", "PASSWORD_AGING", "PASS_MAX_DAYS",
            ValueDomain::DaysWithUnlimited, Relation::PasswordMaximum},
        {"password_expiration_warning_days", "PASSWORD_AGING",
            "PASS_WARN_AGE", ValueDomain::DaysWithUnlimited, Relation::None},
        {"regular_user_uid_min", "PASSWORD_AGING", "UID_MIN",
            ValueDomain::Uid, Relation::UidMinimum},
        {"regular_user_uid_max", "PASSWORD_AGING", "UID_MAX",
            ValueDomain::Uid, Relation::UidMaximum},
    };
    for (const auto& spec : kSpecs) {
        if (policyName == spec.policyName) return &spec;
    }
    return nullptr;
}

// Canonical decimal form: optional '-' only, no '+', no leading zeros.
inline bool parseCanonicalSignedLong(const std::string& value, long minimum,
                                     long maximum, long& out) {
    if (value.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    if (errno != 0 || end != value.c_str() + value.size() ||
        parsed < minimum || parsed > maximum) {
        return false;
    }
    return value == std::to_string(parsed) && (out = parsed, true);
}

// Canonical uid_t decimal form: no sign, no leading zeros, full uid_t range.
inline bool parseCanonicalUid(const std::string& value,
                              unsigned long long& out) {
    if (value.empty() || value.front() == '-' || value.front() == '+') {
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (errno != 0 || end != value.c_str() + value.size() ||
        parsed > std::numeric_limits<uid_t>::max()) {
        return false;
    }
    return value == std::to_string(parsed) && (out = parsed, true);
}

// Exact canonical value validation of an enrolled policy. Used identically
// by the production apply path and by the journal write/read validation.
inline bool validateSharedLoginDefsPolicyValue(const std::string& policyName,
                                               const std::string& value,
                                               std::string& error) {
    const SharedLoginDefsPolicySpec* spec =
        findSharedLoginDefsPolicySpec(policyName);
    if (spec == nullptr) {
        error = "unknown shared login.defs policy: " + policyName;
        return false;
    }
    bool valid = false;
    switch (spec->domain) {
        case ValueDomain::Boolean:
            valid = value == "yes" || value == "no";
            break;
        case ValueDomain::NonNegativeDays: {
            long parsed = 0;
            valid = parseCanonicalSignedLong(value, 0, INT_MAX, parsed);
            break;
        }
        case ValueDomain::DaysWithUnlimited: {
            long parsed = 0;
            valid = parseCanonicalSignedLong(value, -1, INT_MAX, parsed);
            break;
        }
        case ValueDomain::Uid: {
            unsigned long long parsed = 0;
            valid = parseCanonicalUid(value, parsed);
            break;
        }
    }
    if (!valid) {
        error = std::string("invalid canonical value for ") + spec->key +
            ": '" + value + "'";
        return false;
    }
    return true;
}

} // namespace fic::identity::login_defs

#endif // FIC_IDENTITY_LOGIN_DEFS_POLICY_SPEC_H