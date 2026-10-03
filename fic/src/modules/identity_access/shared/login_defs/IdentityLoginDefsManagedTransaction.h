#ifndef FIC_IDENTITY_LOGIN_DEFS_MANAGED_TRANSACTION_H
#define FIC_IDENTITY_LOGIN_DEFS_MANAGED_TRANSACTION_H

#include "modules/identity_access/shared/login_defs/IdentityLoginDefsManagedConfig.h"
#include "rollback/MutationJournal.h"

#include <functional>
#include <string>

namespace fic::identity::login_defs {

// Missing PASS_* key semantics of the native shadow defaults for the current
// platform; USER_CREATION policies carry no relations and ignore it.
struct IdentityLoginDefsSemantics {
    fic::identity::login_defs::MissingKeySemantics missingKey;
};

enum class ReleaseStatus { Success, NothingToDo, Conflict, Failed };

enum class InspectStatus { NothingToDo, Conflict, Failed };

// Applies the desired canonical value of ONE enrolled policy through the
// durable-target-first Prepared/Applied model: strict container parse,
// journal coherence proof, native-effective relation validation of the
// candidate, journal Prepared, single atomic CAS refresh (A→B is one
// physical replacement), full postcondition verification, compensation and
// durable Prepared→Applied commit.
bool applyManagedPolicy(const std::string& loginDefsPath,
                        const PolicyRef& policy, const std::string& value,
                        fic::rollback::MutationJournal& journal,
                        const IdentityLoginDefsSemantics& semantics,
                        std::string& error);

// Ownership release of ONE managed sub-block proven by the journal record.
// Release is never a historical restoration: the FIC sub-block is removed
// and the native foreign value (if any) becomes effective naturally.
ReleaseStatus releaseManagedPolicy(
    const std::string& loginDefsPath, const fic::rollback::MutationRecord& record,
    fic::rollback::MutationJournal& journal,
    const IdentityLoginDefsSemantics& semantics, std::string& error);

// No-record preflight for the rollback executor: proves the WHOLE shared
// ownership domain before deciding — a malformed container, an orphan peer
// sub-block or an owned same-policy sub-block without an active journal
// record is unattributable state and fails closed.
InspectStatus inspectUnrecordedState(const std::string& loginDefsPath,
                                     const PolicyRef& policy,
                                     fic::rollback::MutationJournal& journal,
                                     std::string& error);

// Deterministic unit-test seams. Production never installs these hooks.
void setBeforeIdentityLoginDefsWriteHookForTests(std::function<void()> hook);
void setAfterIdentityLoginDefsWriteHookForTests(std::function<void()> hook);

} // namespace fic::identity::login_defs

#endif // FIC_IDENTITY_LOGIN_DEFS_MANAGED_TRANSACTION_H