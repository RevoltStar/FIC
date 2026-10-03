#include "modules/identity_access/shared/login_defs/IdentityLoginDefsManagedTransaction.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <optional>
#include <utility>

namespace fic::identity::login_defs {
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

const UndoRemoveIdentityLoginDefsManagedPolicy* payload(
    const MutationRecord& record) {
    return std::get_if<UndoRemoveIdentityLoginDefsManagedPolicy>(
        &record.undo.payload);
}

bool findActive(MutationJournal& journal, const PolicyRef& policy,
                const std::string& path, const std::string& key,
                std::optional<MutationRecord>& found, std::string& error) {
    found.reset();
    for (const auto& record : journal.activeRecords(policy)) {
        if (record.undo.backend != MutationBackend::IdentityLoginDefs) {
            continue;
        }
        const auto* undo = payload(record);
        if (undo == nullptr || record.resource != path ||
            undo->configPath != path || undo->key != key ||
            undo->policyName != policy.policyName) {
            error = "conflicting shared login.defs journal identity";
            return false;
        }
        if (found.has_value()) {
            error = "multiple active shared login.defs journal records";
            return false;
        }
        found = record;
    }
    return true;
}

// Container coherence: every physical FIC sub-block must be proven by the
// journal — a known enrolled policy, exactly one active record with the
// matching identity, and a body equal to the record's applied line (or, for
// an unresolved Prepared refresh, the durable previous side).
bool proveCoherence(MutationJournal& journal, const std::string& path,
                    const ManagedConfigModel& model, std::string& error) {
    for (const auto& block : model.policies) {
        const std::size_t first = block.policyRef.find('/');
        const std::size_t second = first == std::string::npos
            ? std::string::npos
            : block.policyRef.find('/', first + 1);
        if (first == std::string::npos || second == std::string::npos) {
            error = "malformed shared login.defs policy ref: " +
                block.policyRef;
            return false;
        }
        PolicyRef policy{block.policyRef.substr(0, first),
                         block.policyRef.substr(first + 1, second - first - 1),
                         block.policyRef.substr(second + 1)};
        PolicyRoute route;
        if (!policyRoute(path, policy, route, error)) {
            error = "orphan/unknown shared login.defs policy sub-block: " +
                block.policyRef;
            return false;
        }
        std::optional<MutationRecord> active;
        if (!findActive(journal, policy, path, route.key, active, error) ||
            !active.has_value()) {
            error = "FIC login.defs sub-block has no active provenance: " +
                block.policyRef;
            return false;
        }
        const auto* undo = payload(*active);
        const std::string target = undo->appliedLine;
        const std::string previous = undo->previousAppliedLine;
        const std::string body = block.key + " " + block.value;
        const bool accepted = body == target ||
            (active->status == MutationStatus::Prepared &&
             !previous.empty() && body == previous);
        if (!accepted) {
            error = "FIC login.defs sub-block conflicts with journal: " +
                block.policyRef;
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
    if (!write.installed || !write.installedTargetState.has_value()) {
        return true;
    }
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.expectedTargetState = *write.installedTargetState;
    AtomicWriteResult restored;
    return AtomicFileWriter::writeWithResult(path, before.content, options,
                                             &error, &restored) &&
        restored.durabilityConfirmed;
}

MutationRecord makeRecord(const std::string& path, const PolicyRef& policy,
                          const std::string& key, const std::string& target,
                          const std::string& previous) {
    MutationRecord record;
    record.policy = policy;
    record.resource = path;
    record.undo = {MutationBackend::IdentityLoginDefs,
        UndoRemoveIdentityLoginDefsManagedPolicy{
            policy.policyName, path, key, target, previous}};
    return record;
}

// Postcondition of an installed target: exact owned body, container at the
// logical EOF, native-effective desired value and valid relations.
bool verify(const std::string& path, const PolicyRef& policy,
            const std::string& key, const std::string& desiredLine,
            const std::string& desiredValue,
            const IdentityLoginDefsSemantics& semantics,
            const AtomicTargetState& installed, std::string& error) {
    if (!AtomicFileWriter::targetStateMatches(path, installed, &error)) {
        return false;
    }
    AtomicTargetState current;
    if (!capture(path, current, error)) return false;
    ManagedConfigModel model;
    if (!parseManagedConfig(current.content, model, error)) return false;
    const ManagedPolicyBlock* block =
        findPolicyBlock(model, policy.moduleName + "/" + policy.submoduleName +
            "/" + policy.policyName);
    if (block == nullptr || block->key + " " + block->value != desiredLine ||
        model.blockOffset + model.blockLength != current.content.size()) {
        error = "shared login.defs ownership/EOF postcondition failed";
        return false;
    }
    std::optional<std::string> effective;
    if (!effectiveValue(current.content, key, effective, error) ||
        !effective.has_value() || *effective != desiredValue) {
        error = error.empty()
            ? "shared login.defs native-effective postcondition failed"
            : error;
        return false;
    }
    return relationsValidInCandidate(current.content, policy,
                                     semantics.missingKey, error);
}

} // namespace

bool applyManagedPolicy(const std::string& loginDefsPath,
                        const PolicyRef& policy, const std::string& value,
                        MutationJournal& journal,
                        const IdentityLoginDefsSemantics& semantics,
                        std::string& error) {
    PolicyRoute route;
    if (!policyRoute(loginDefsPath, policy, route, error) ||
        !validatePolicyValue(policy, value, error)) {
        return false;
    }
    const std::string desiredLine = route.key + " " + value;
    AtomicTargetState before;
    if (!capture(route.path, before, error)) return false;
    ManagedConfigModel model;
    if (!parseManagedConfig(before.content, model, error) ||
        !proveCoherence(journal, route.path, model, error)) {
        return false;
    }
    const ManagedPolicyBlock* block = findPolicyBlock(model, route.policyRef);

    std::optional<std::string> currentEffective;
    if (!effectiveValue(before.content, route.key, currentEffective, error)) {
        return false;
    }

    std::string previous; // previous FIC-owned line of an in-place refresh

    std::optional<MutationRecord> active;
    if (!findActive(journal, policy, route.path, route.key, active, error)) {
        return false;
    }
    if (active.has_value()) {
        const auto* undo = payload(*active);
        const std::string target = undo->appliedLine;
        const std::string previousDurable = undo->previousAppliedLine;
        if (active->status == MutationStatus::Prepared) {
            if (block != nullptr && block->key + " " + block->value == target) {
                // Crash after the physical write: complete the durable
                // transition exactly as install would have verified it.
                if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                        route.path, before, &error) ||
                    !verify(route.path, policy, route.key, target,
                            target.substr(route.key.size() + 1), semantics,
                            before, error) ||
                    !journal.setStatus(active->id, MutationStatus::Applied,
                                       error)) {
                    return false;
                }
                active->status = MutationStatus::Applied;
                active->undo.payload = *undo;
            } else if (!previousDurable.empty() && block != nullptr &&
                       block->key + " " + block->value == previousDurable) {
                // Crash before the physical refresh: continue the prepared
                // A→B transition.
                previous = previousDurable;
            } else if (block == nullptr) {
                // Fresh Prepared never written: provenance-only, discard.
                if (!journal.discard(active->id, error)) return false;
                active.reset();
            } else {
                error =
                    "unresolved shared login.defs Prepared state conflicts";
                return false;
            }
        }
        if (active.has_value() && active->status == MutationStatus::Applied) {
            const auto* applied = payload(*active);
            const ManagedPolicyBlock* owned =
                findPolicyBlock(model, route.policyRef);
            if (owned == nullptr) {
                // Externally released: honest journal resolution.
                if (!journal.setStatus(active->id, MutationStatus::RolledBack,
                                       error)) {
                    return false;
                }
                active.reset();
            } else if (owned->key + " " + owned->value !=
                       applied->appliedLine) {
                error = "manual edit of the shared login.defs managed line";
                return false;
            } else if (applied->appliedLine == desiredLine &&
                       model.blockOffset + model.blockLength ==
                           before.content.size() &&
                       currentEffective.has_value() &&
                       *currentEffective == value &&
                       relationsValidInCandidate(before.content, policy,
                                                 semantics.missingKey,
                                                 error)) {
                return true; // proven idempotent no-op
            } else {
                previous = applied->appliedLine;
            }
        }
    }
    if (!active.has_value() &&
        findPolicyBlock(model, route.policyRef) != nullptr) {
        error = "unrecorded shared login.defs ownership (fail closed)";
        return false;
    }
    if (!active.has_value()) {
        std::string relationError;
        if (currentEffective.has_value() && *currentEffective == value &&
            relationsValidInCandidate(before.content, policy,
                                      semantics.missingKey, relationError)) {
            return true; // compliant foreign state is never adopted
        }
        // A compliant-looking value with provably invalid native relations
        // still requires the FIC-owned write below; fall through.
    }

    std::string candidate;
    bool changed = false;
    if (!upsertPolicyBlock(before.content, route.policyRef, route.key, value,
                           candidate, changed, error)) {
        return false;
    }
    if (!changed) {
        error = "shared login.defs transaction planned no physical change "
                "without a proven no-op";
        return false;
    }
    // Candidate relations are validated on the exact candidate state.
    if (!relationsValidInCandidate(candidate, policy, semantics.missingKey,
                                   error)) {
        return false;
    }
    MutationId id = 0;
    if (!journal.prepareMutation(makeRecord(route.path, policy, route.key,
                                            desiredLine, previous),
                                 id, error)) {
        return false;
    }
    AtomicWriteResult write;
    if (beforeWriteHook()) beforeWriteHook()();
    if (!install(route.path, before, candidate, write, error)) {
        std::string recoveryError;
        const bool restored = write.installed
            ? compensate(route.path, write, before, recoveryError) : true;
        if (restored) {
            if (previous.empty()) {
                journal.discard(id, recoveryError);
            } else if (journal.normalizeIdentityLoginDefsPreparedToProvenState(
                           id, previous, recoveryError)) {
                journal.setStatus(id, MutationStatus::Applied, recoveryError);
            }
        }
        return false;
    }
    if (afterWriteHook()) afterWriteHook()();
    if (!write.installedTargetState.has_value() ||
        !verify(route.path, policy, route.key, desiredLine, value, semantics,
                *write.installedTargetState, error)) {
        std::string compensationError;
        if (compensate(route.path, write, before, compensationError)) {
            if (previous.empty()) {
                journal.discard(id, compensationError);
            } else if (journal.normalizeIdentityLoginDefsPreparedToProvenState(
                           id, previous, compensationError)) {
                journal.setStatus(id, MutationStatus::Applied,
                                  compensationError);
            }
        }
        return false;
    }
    return journal.setStatus(id, MutationStatus::Applied, error);
}

ReleaseStatus releaseManagedPolicy(const std::string& loginDefsPath,
                                   const MutationRecord& record,
                                   MutationJournal& journal,
                                   const IdentityLoginDefsSemantics& semantics,
                                   std::string& error) {
    const auto* undo = payload(record);
    if (undo == nullptr) return ReleaseStatus::Failed;
    PolicyRoute route;
    if (!policyRoute(loginDefsPath, record.policy, route, error) ||
        route.key != undo->key || route.path != undo->configPath ||
        route.path != record.resource) {
        error = "shared login.defs rollback route does not match the current "
                "platform";
        return ReleaseStatus::Conflict;
    }
    AtomicTargetState before;
    if (!capture(route.path, before, error)) return ReleaseStatus::Failed;
    ManagedConfigModel model;
    if (!parseManagedConfig(before.content, model, error) ||
        !proveCoherence(journal, route.path, model, error)) {
        return ReleaseStatus::Conflict;
    }
    const ManagedPolicyBlock* block = findPolicyBlock(model, route.policyRef);
    if (block == nullptr) return ReleaseStatus::NothingToDo;
    const std::string body = block->key + " " + block->value;
    const std::string target = undo->appliedLine;
    const std::string previous = undo->previousAppliedLine;
    const bool ownsTarget = body == target;
    const bool ownsPrevious = record.status == MutationStatus::Prepared &&
        !previous.empty() && body == previous;
    if (!ownsTarget && !ownsPrevious) {
        error = "shared login.defs managed line differs from journal ownership";
        return ReleaseStatus::Conflict;
    }
    if (ownsPrevious &&
        !journal.normalizeIdentityLoginDefsPreparedToProvenState(
            record.id, previous, error)) {
        return ReleaseStatus::Failed;
    }
    std::string candidate;
    bool removed = false;
    if (!removePolicyBlock(before.content, route.policyRef, candidate, removed,
                           error)) {
        return ReleaseStatus::Conflict;
    }
    if (!removed) {
        error = "shared login.defs release removed nothing";
        return ReleaseStatus::Conflict;
    }
    // Rollback candidate relation validation on the exact post-release
    // native-effective state (fail closed — no hidden workarounds).
    if (!relationsValidInCandidate(candidate, record.policy,
                                   semantics.missingKey, error)) {
        error = "shared login.defs rollback would create an invalid native "
                "relation: " + error;
        return ReleaseStatus::Conflict;
    }
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
        !parseManagedConfig(after.content, afterModel, error) ||
        findPolicyBlock(afterModel, route.policyRef) != nullptr) {
        std::string compensationError;
        compensate(route.path, write, before, compensationError);
        return ReleaseStatus::Failed;
    }
    return ReleaseStatus::Success;
}

InspectStatus inspectUnrecordedState(const std::string& loginDefsPath,
                                     const PolicyRef& policy,
                                     std::string& error) {
    PolicyRoute route;
    if (!policyRoute(loginDefsPath, policy, route, error)) {
        return InspectStatus::Failed;
    }
    AtomicTargetState snapshot;
    if (!capture(route.path, snapshot, error)) return InspectStatus::Failed;
    ManagedConfigModel model;
    if (!parseManagedConfig(snapshot.content, model, error)) {
        return InspectStatus::Conflict;
    }
    if (findPolicyBlock(model, route.policyRef) != nullptr) {
        error = "shared login.defs FIC sub-block exists without journal "
                "provenance";
        return InspectStatus::Conflict;
    }
    return InspectStatus::NothingToDo;
}

void setBeforeIdentityLoginDefsWriteHookForTests(std::function<void()> hook) {
    beforeWriteHook() = std::move(hook);
}

void setAfterIdentityLoginDefsWriteHookForTests(std::function<void()> hook) {
    afterWriteHook() = std::move(hook);
}

} // namespace fic::identity::login_defs