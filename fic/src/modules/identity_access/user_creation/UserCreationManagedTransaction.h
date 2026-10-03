#ifndef FIC_USER_CREATION_MANAGED_TRANSACTION_H
#define FIC_USER_CREATION_MANAGED_TRANSACTION_H

#include "modules/identity_access/user_creation/UserCreationManagedConfig.h"
#include "rollback/MutationJournal.h"

#include <functional>

namespace fic::identity::user_creation {

enum class ReleaseStatus { Success, NothingToDo, Conflict, Failed };

bool applyManagedPolicy(
    const fic::platform::UserCreationPlatformConfig& platform,
    const std::string& policyName, const std::vector<Assignment>& desired,
    fic::rollback::MutationJournal& journal, std::string& error);

ReleaseStatus releaseManagedPolicy(
    const fic::platform::UserCreationPlatformConfig& platform,
    const fic::rollback::MutationRecord& record,
    fic::rollback::MutationJournal& journal, std::string& error);

// Deterministic unit-test seams. Production never installs these hooks.
void setBeforeUserCreationWriteHookForTests(std::function<void()> hook);
void setAfterUserCreationWriteHookForTests(std::function<void()> hook);

} // namespace fic::identity::user_creation

#endif
