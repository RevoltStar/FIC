#include "modules/identity_access/user_creation/UserCreationManagedTransaction.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
#include <optional>

namespace fic::identity::user_creation {
namespace {

using namespace fic::rollback;

std::function<void()>& beforeWriteHook() {
    static std::function<void()> hook;
    return hook;
}
std::function<void()>& afterWriteHook() {
    static std::function<void()> hook;
    return hook;
}

PolicyRef ref(const std::string& policy) {
    return {"IDENTITY_ACCESS", "USER_CREATION", policy};
}

UserCreationConfigKind journalKind(ConfigKind kind) {
    if (kind == ConfigKind::LoginDefs) return UserCreationConfigKind::LoginDefs;
    if (kind == ConfigKind::Adduser) return UserCreationConfigKind::Adduser;
    return UserCreationConfigKind::UseraddDefaults;
}

ConfigKind configKind(UserCreationConfigKind kind) {
    if (kind == UserCreationConfigKind::LoginDefs) return ConfigKind::LoginDefs;
    if (kind == UserCreationConfigKind::Adduser) return ConfigKind::Adduser;
    return ConfigKind::UseraddDefaults;
}

std::vector<UserCreationManagedAssignment> journalAssignments(
    const std::vector<Assignment>& values) {
    std::vector<UserCreationManagedAssignment> result;
    for (const auto& value : values) result.push_back({value.key, value.line});
    return result;
}

std::vector<Assignment> assignments(
    const std::vector<UserCreationManagedAssignment>& values) {
    std::vector<Assignment> result;
    for (const auto& value : values) result.push_back({value.key, value.appliedLine});
    return result;
}

bool same(const PolicyBlock* block, const std::vector<Assignment>& expected) {
    return block != nullptr && block->assignments == expected;
}

const UndoRemoveUserCreationManagedPolicy* payload(const MutationRecord& record) {
    return std::get_if<UndoRemoveUserCreationManagedPolicy>(&record.undo.payload);
}

bool findActive(MutationJournal& journal, const std::string& policy,
                const std::string& path, std::optional<MutationRecord>& found,
                std::string& error) {
    found.reset();
    for (const auto& record : journal.activeRecords(ref(policy))) {
        if (record.undo.backend != MutationBackend::UserCreation) continue;
        const auto* undo = payload(record);
        if (undo == nullptr || record.resource != path || undo->configPath != path ||
            undo->policyName != policy) {
            error = "conflicting USER_CREATION journal identity";
            return false;
        }
        if (found.has_value()) {
            error = "multiple active USER_CREATION journal records";
            return false;
        }
        found = record;
    }
    return true;
}

bool proveCoherence(const fic::platform::UserCreationPlatformConfig& platform,
                    MutationJournal& journal, const std::string& path,
                    const ManagedConfigModel& model, std::string& error) {
    for (const auto& block : model.policies) {
        PolicyRoute route;
        if (!policyRoute(platform, block.policyName, route, error) ||
            route.path != path) {
            error = "orphan/unknown USER_CREATION policy block: " +
                block.policyName;
            return false;
        }
        std::optional<MutationRecord> active;
        if (!findActive(journal, block.policyName, path, active, error) ||
            !active.has_value()) {
            error = "FIC USER_CREATION block has no active provenance: " +
                block.policyName;
            return false;
        }
        const auto* undo = payload(*active);
        const auto target = assignments(undo->appliedAssignments);
        const auto previous = assignments(undo->previousAppliedAssignments);
        const bool accepted = same(&block, target) ||
            (active->status == MutationStatus::Prepared && !previous.empty() &&
             same(&block, previous));
        if (!accepted) {
            error = "USER_CREATION managed block conflicts with journal: " +
                block.policyName;
            return false;
        }
    }
    return true;
}

bool capture(const std::string& path, AtomicTargetState& snapshot,
             std::string& error) {
    return AtomicFileWriter::captureTargetState(path, snapshot, &error);
}

bool install(const std::string& path, const AtomicTargetState& before,
             const std::string& content, AtomicWriteResult& result,
             std::string& error) {
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.expectedTargetState = before;
    return AtomicFileWriter::writeWithResult(path, content, options, &error,
                                             &result) &&
        result.durabilityConfirmed;
}

bool compensate(const std::string& path, const AtomicWriteResult& write,
                const AtomicTargetState& before, std::string& error) {
    if (!write.installed || !write.installedTargetState.has_value()) return true;
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.expectedTargetState = *write.installedTargetState;
    AtomicWriteResult restored;
    return AtomicFileWriter::writeWithResult(path, before.content, options,
                                             &error, &restored) &&
        restored.durabilityConfirmed;
}

bool verify(const fic::platform::UserCreationPlatformConfig& platform,
            const PolicyRoute& route, const std::string& policy,
            const std::vector<Assignment>& expected,
            const AtomicTargetState& installed, std::string& error) {
    if (!AtomicFileWriter::targetStateMatches(route.path, installed, &error))
        return false;
    AtomicTargetState current;
    if (!capture(route.path, current, error)) return false;
    ManagedConfigModel model;
    if (!parseManagedConfig(current.content, route.kind, model, error)) return false;
    if (!same(findPolicyBlock(model, policy), expected) ||
        model.blockOffset + model.blockLength != current.content.size()) {
        error = "USER_CREATION ownership/EOF postcondition failed";
        return false;
    }
    return effectiveAssignmentsMatch(current.content, route.kind,
        platform.useraddDefaultsLookup, expected, error);
}

MutationRecord makeRecord(const PolicyRoute& route, const std::string& policy,
                          const std::vector<Assignment>& desired,
                          const std::vector<Assignment>& previous) {
    MutationRecord record;
    record.policy = ref(policy);
    record.resource = route.path;
    record.undo = {MutationBackend::UserCreation,
        UndoRemoveUserCreationManagedPolicy{
            policy, journalKind(route.kind), route.path,
            journalAssignments(desired), journalAssignments(previous)}};
    return record;
}

} // namespace

bool applyManagedPolicy(
    const fic::platform::UserCreationPlatformConfig& platform,
    const std::string& policyName, const std::vector<Assignment>& desired,
    MutationJournal& journal, std::string& error) {
    PolicyRoute route;
    if (!policyRoute(platform, policyName, route, error)) return false;
    AtomicTargetState before;
    if (!capture(route.path, before, error)) return false;
    ManagedConfigModel model;
    if (!parseManagedConfig(before.content, route.kind, model, error) ||
        !proveCoherence(platform, journal, route.path, model, error)) return false;

    std::optional<MutationRecord> active;
    if (!findActive(journal, policyName, route.path, active, error)) return false;
    std::vector<Assignment> previous;
    if (active.has_value()) {
        if (active->status == MutationStatus::RollbackFailed) {
            error = "USER_CREATION provenance is RollbackFailed";
            return false;
        }
        const auto* undo = payload(*active);
        const auto target = assignments(undo->appliedAssignments);
        const auto old = assignments(undo->previousAppliedAssignments);
        const PolicyBlock* block = findPolicyBlock(model, policyName);
        if (active->status == MutationStatus::Prepared) {
            if (same(block, target)) {
                if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                        route.path, before, &error) ||
                    !effectiveAssignmentsMatch(before.content, route.kind,
                        platform.useraddDefaultsLookup, target, error) ||
                    !journal.setStatus(active->id, MutationStatus::Applied, error))
                    return false;
                active->status = MutationStatus::Applied;
                active->undo.payload = *undo;
            } else if (!old.empty() && same(block, old)) {
                previous = old;
            } else if (block == nullptr) {
                if (!journal.discard(active->id, error)) return false;
                active.reset();
            } else {
                error = "unresolved USER_CREATION Prepared state conflicts";
                return false;
            }
        }
        if (active.has_value() && active->status == MutationStatus::Applied) {
            const auto* applied = payload(*active);
            const auto current = assignments(applied->appliedAssignments);
            const PolicyBlock* now = findPolicyBlock(model, policyName);
            if (now == nullptr) {
                if (!journal.setStatus(active->id, MutationStatus::RolledBack,
                                       error)) return false;
                active.reset();
            } else if (!same(now, current)) {
                error = "manual edit of USER_CREATION managed block";
                return false;
            } else if (current == desired &&
                       model.blockOffset + model.blockLength == before.content.size() &&
                       effectiveAssignmentsMatch(before.content, route.kind,
                           platform.useraddDefaultsLookup, desired, error)) {
                return true;
            } else {
                previous = current;
            }
        }
    }

    if (!active.has_value() && findPolicyBlock(model, policyName) != nullptr) {
        error = "unrecorded USER_CREATION ownership (fail closed)";
        return false;
    }
    if (!active.has_value()) {
        std::string semanticError;
        if (effectiveAssignmentsMatch(before.content, route.kind,
                platform.useraddDefaultsLookup, desired, semanticError)) {
            return true; // compliant foreign state is never adopted
        }
    }

    std::string candidate;
    bool changed = false;
    if (!upsertPolicyBlock(before.content, route.kind, policyName, desired,
                           candidate, changed, error)) return false;
    if (!changed) {
        error = "USER_CREATION transaction planned no physical change "
                "without a proven no-op";
        return false;
    }
    MutationId id = 0;
    if (!journal.prepareMutation(makeRecord(route, policyName, desired, previous),
                                 id, error)) return false;
    AtomicWriteResult write;
    if (beforeWriteHook()) beforeWriteHook()();
    if (!install(route.path, before, candidate, write, error)) {
        std::string recoveryError;
        const bool restored = write.installed
            ? compensate(route.path, write, before, recoveryError) : true;
        if (restored) {
            if (previous.empty()) journal.discard(id, recoveryError);
            else {
                MutationId ignored = 0;
                journal.prepareMutation(makeRecord(route, policyName, previous, {}),
                                        ignored, recoveryError);
                journal.setStatus(id, MutationStatus::Applied, recoveryError);
            }
        }
        return false;
    }
    if (afterWriteHook()) afterWriteHook()();
    if (!write.installedTargetState.has_value() ||
        !verify(platform, route, policyName, desired,
                *write.installedTargetState, error)) {
        std::string compensationError;
        if (compensate(route.path, write, before, compensationError)) {
            if (previous.empty()) journal.discard(id, compensationError);
            else {
                MutationId ignored = 0;
                journal.prepareMutation(makeRecord(route, policyName, previous, {}),
                                        ignored, compensationError);
                journal.setStatus(id, MutationStatus::Applied, compensationError);
            }
        }
        return false;
    }
    return journal.setStatus(id, MutationStatus::Applied, error);
}

ReleaseStatus releaseManagedPolicy(
    const fic::platform::UserCreationPlatformConfig& platform,
    const MutationRecord& record, MutationJournal& journal, std::string& error) {
    const auto* undo = payload(record);
    if (undo == nullptr) return ReleaseStatus::Failed;
    PolicyRoute route;
    if (!policyRoute(platform, undo->policyName, route, error) ||
        route.path != undo->configPath || route.path != record.resource ||
        configKind(undo->configKind) != route.kind) {
        error = "USER_CREATION rollback route does not match current platform";
        return ReleaseStatus::Conflict;
    }
    AtomicTargetState before;
    if (!capture(route.path, before, error)) return ReleaseStatus::Failed;
    ManagedConfigModel model;
    if (!parseManagedConfig(before.content, route.kind, model, error) ||
        !proveCoherence(platform, journal, route.path, model, error))
        return ReleaseStatus::Conflict;
    const PolicyBlock* block = findPolicyBlock(model, undo->policyName);
    if (block == nullptr) return ReleaseStatus::NothingToDo;
    const auto target = assignments(undo->appliedAssignments);
    const auto previous = assignments(undo->previousAppliedAssignments);
    const std::vector<Assignment>* owned = same(block, target) ? &target :
        (!previous.empty() && record.status == MutationStatus::Prepared &&
         same(block, previous) ? &previous : nullptr);
    if (owned == nullptr) {
        error = "USER_CREATION managed body differs from journal ownership";
        return ReleaseStatus::Conflict;
    }
    std::string candidate;
    bool removed = false;
    if (!removePolicyBlock(before.content, route.kind, undo->policyName, *owned,
                           candidate, removed, error))
        return ReleaseStatus::Conflict;
    AtomicWriteResult write;
    if (beforeWriteHook()) beforeWriteHook()();
    if (!install(route.path, before, candidate, write, error)) {
        if (write.installed) {
            std::string compensationError;
            compensate(route.path, write, before, compensationError);
        }
        return write.preconditionFailed ? ReleaseStatus::Conflict
                                        : ReleaseStatus::Failed;
    }
    if (afterWriteHook()) afterWriteHook()();
    AtomicTargetState after;
    ManagedConfigModel afterModel;
    if (!write.installedTargetState.has_value() ||
        !AtomicFileWriter::targetStateMatches(
            route.path, *write.installedTargetState, &error) ||
        !capture(route.path, after, error) ||
        !parseManagedConfig(after.content, route.kind, afterModel, error) ||
        findPolicyBlock(afterModel, undo->policyName) != nullptr) {
        std::string compensationError;
        compensate(route.path, write, before, compensationError);
        return ReleaseStatus::Failed;
    }
    return ReleaseStatus::Success;
}

void setBeforeUserCreationWriteHookForTests(std::function<void()> hook) {
    beforeWriteHook() = std::move(hook);
}

void setAfterUserCreationWriteHookForTests(std::function<void()> hook) {
    afterWriteHook() = std::move(hook);
}

} // namespace fic::identity::user_creation
