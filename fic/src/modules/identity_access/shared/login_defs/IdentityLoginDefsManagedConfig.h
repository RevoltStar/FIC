#ifndef FIC_IDENTITY_LOGIN_DEFS_MANAGED_CONFIG_H
#define FIC_IDENTITY_LOGIN_DEFS_MANAGED_CONFIG_H

#include <fic/policy/PolicyDependency.h>

#include <optional>
#include <string>
#include <vector>

namespace fic::identity::login_defs {

// One FIC-owned container in /etc/login.defs shared by every enrolled
// IDENTITY_ACCESS scalar policy (USER_CREATION creation defaults and
// PASSWORD_AGING aging scalars). Exactly ONE container per file, placed at
// the logical EOF; every policy owns a typed sub-block with exactly one
// canonical assignment. The strict FIC grammar is intentionally separate
// from the native consumer semantics; foreign configuration outside the
// container is preserved byte-for-byte.
constexpr const char* kBlockBegin =
    "#@FIC_IDENTITY_LOGIN_DEFS_BLOCK_BEGIN version=1@";
constexpr const char* kBlockEnd = "#@FIC_IDENTITY_LOGIN_DEFS_BLOCK_END@";
constexpr const char* kPolicyBegin = "#@FIC_POLICY_BEGIN ref=";
constexpr const char* kPolicyEnd = "#@FIC_POLICY_END ref=";
constexpr const char* kMarkerIntroducer = "#@FIC_";

struct ManagedPolicyBlock {
    std::string policyRef; // "MODULE/SUBMODULE/policy"
    std::string key;       // managed login.defs key of the single assignment
    std::string value;     // canonical value of the single assignment
    std::string raw;       // byte-exact sub-block (begin marker .. end marker)
};

struct ManagedConfigModel {
    bool blockPresent = false;
    std::size_t blockOffset = 0;
    std::size_t blockLength = 0;
    std::vector<ManagedPolicyBlock> policies;
};

struct PolicyRoute {
    std::string policyRef;
    std::string key;
    std::string path;
};

// Native-consumer relation kind of an enrolled policy.
enum class Relation {
    None,
    PasswordMinimum,
    PasswordMaximum,
    UidMinimum,
    UidMaximum
};

// Native missing-key semantics of the PASS_* relations (the native shadow
// defaults when the peer key is absent); UID peers have no missing-key
// default and always fail closed.
struct MissingKeySemantics {
    long minDays = -1;
    long maxDays = -1;
};

// Resolves the managed route of an enrolled policy. Unknown policies fail
// closed (the exact 7-policy whitelist is the whole ownership domain).
bool policyRoute(const std::string& loginDefsPath, const PolicyRef& policy,
                 PolicyRoute& route, std::string& error);

Relation policyRelation(const PolicyRef& policy, std::string& error);

// Canonical value validation of an enrolled policy (typed, exact domain):
// yes/no booleans, PASS_MIN_DAYS 0..INT_MAX, PASS_MAX_DAYS/PASS_WARN_AGE
// -1..INT_MAX (unlimited allowed), UID_* the full uid_t range.
bool validatePolicyValue(const PolicyRef& policy, const std::string& value,
                         std::string& error);

// Strict FIC managed-container parser. Rejects unknown FIC markers,
// malformed sub-blocks, duplicate policy refs and foreign content inside
// the container (fail closed).
bool parseManagedConfig(const std::string& content, ManagedConfigModel& model,
                        std::string& error);

std::string canonicalPolicyBlock(const std::string& policyRef,
                                 const std::string& key,
                                 const std::string& value);

// Upserts the policy sub-block. Peer sub-blocks are preserved byte-for-byte;
// the container is always rebuilt at the logical EOF of the foreign bytes.
bool upsertPolicyBlock(const std::string& content, const std::string& policyRef,
                       const std::string& key, const std::string& value,
                       std::string& result, bool& changed, std::string& error);

// Removes the policy sub-block. When the last sub-block is removed the whole
// container is removed; foreign bytes are never touched.
bool removePolicyBlock(const std::string& content, const std::string& policyRef,
                       std::string& result, bool& removed, std::string& error);

const ManagedPolicyBlock* findPolicyBlock(const ManagedConfigModel& model,
                                          const std::string& policyRef);

// Native consumer-effective value of a login.defs key: leading whitespace
// and comment lines are skipped, the LAST valid assignment wins (last-wins),
// no-value assignments are ignored like native shadow does. A target-like
// line that cannot be parsed as a valid assignment fails closed instead of
// guessing the native consumer result.
bool effectiveValue(const std::string& content, const std::string& key,
                    std::optional<std::string>& value, std::string& error);

// Validates the resulting native-effective relations of the changed policy
// in the CANDIDATE content (apply candidate or rollback candidate): both
// members of the relation pair are read through the shared effective reader
// on the candidate itself, so the decision is made on the exact state that
// would become effective. Invalid resulting relations fail closed.
bool relationsValidInCandidate(const std::string& candidateContent,
                               const PolicyRef& policy,
                               const MissingKeySemantics& semantics,
                               std::string& error);

} // namespace fic::identity::login_defs

#endif // FIC_IDENTITY_LOGIN_DEFS_MANAGED_CONFIG_H