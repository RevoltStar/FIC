#include "rollback/ScopeTransition.h"

namespace fic::rollback {
namespace {
PolicyRef scopePolicy(ScopeTransition::Domain domain) {
    return domain == ScopeTransition::Domain::Desktop
        ? PolicyRef{"OSS", "DesktopEnvironment", "controlled_desktop_environments"}
        : PolicyRef{"OSS", "DisplayManager", "controlled_display_managers"};
}
std::string scopeResource(ScopeTransition::Domain domain) {
    return domain == ScopeTransition::Domain::Desktop ? "scope/de" : "scope/dm";
}
MutationRecord checkpointRecord(ScopeTransition::Domain domain, const ScopeTransitionState& previous,
                                const std::vector<std::string>& target,
                                const std::string& phase) {
    MutationRecord record;
    record.policy = scopePolicy(domain);
    record.resource = scopeResource(domain);
    record.undo = {MutationBackend::Scope,
                   ScopeTransitionCheckpoint{previous.committed, target, phase}};
    return record;
}
}

bool ScopeTransition::state(ScopeTransitionState& result,
                            std::string& error) const {
    if (!journal_.usable()) {
        error = "Scope transition journal is not healthy";
        return false;
    }
    result = {};
    for (const auto& record : journal_.records()) {
        if (!record.isActive() || record.undo.backend != MutationBackend::Scope || record.resource != scopeResource(domain_))
            continue;
        if (record.policy != scopePolicy(domain_) || record.resource != scopeResource(domain_) || result.id) {
            error = "Scope checkpoint ownership/identity conflict";
            return false;
        }
        const auto* checkpoint = std::get_if<ScopeTransitionCheckpoint>(&record.undo.payload);
        if (!checkpoint || (record.status == MutationStatus::Applied &&
                            checkpoint->phase != "committed")) {
            error = "Scope checkpoint payload mismatch";
            return false;
        }
        result.id = record.id;
        result.target = checkpoint->targetScope;
        result.committed = record.status == MutationStatus::Applied
            ? checkpoint->targetScope : checkpoint->committedScope;
        result.phase = record.status == MutationStatus::Applied ? "committed" : checkpoint->phase;
        if (record.status != MutationStatus::Applied && result.phase == "committed")
            result.phase = "pending";
        if (record.status == MutationStatus::RollbackFailed && result.phase == "pending")
            result.phase = "failed";
    }
    error.clear();
    return true;
}

bool ScopeTransition::requireCommitted(const std::vector<std::string>& configured,
                                       std::string& error) const {
    ScopeTransitionState current;
    if (!state(current, error)) return false;
    if (configured.empty()) {
        error = "Controlled graphical scope is empty (UNCONFIGURED)";
        return false;
    }
    if (!current.id || current.phase != "committed" || current.committed != configured) {
        error = "Configured graphical scope has no successfully committed transition";
        return false;
    }
    error.clear();
    return true;
}

bool ScopeTransition::invalidate(const std::string& reason, std::string& error) {
    ScopeTransitionState previous;
    if (!state(previous, error)) return false;
    if (!previous.id) return true;
    MutationId id = 0;
    if (!journal_.prepareMutation(checkpointRecord(domain_, previous, previous.target, "partial"), id, error)) return false;
    return journal_.setStatusWithMessage(id, MutationStatus::RollbackFailed, reason, error);
}

bool ScopeTransition::reconcile(const std::vector<std::string>& configured,
                                const Operation& preflight,
                                const Operation& ensure,
                                const Operation& release,
                                const Operation& verify,
                                std::string& error) {
    ScopeTransitionState previous;
    if (!state(previous, error)) return false;
    if (!preflight || !ensure || !release || !verify) {
        error = "Scope transition requires all four verification stages";
        return false;
    }
    MutationId id = 0;
    const auto fail = [&](const std::string& phase, const std::string& reason) {
        std::string persistenceError;
        auto record = checkpointRecord(domain_, previous, configured, phase);
        bool saved = journal_.prepareMutation(record, id, persistenceError);
        if (saved) saved = journal_.setStatusWithMessage(
            id, MutationStatus::RollbackFailed, reason, persistenceError);
        error = reason;
        if (!saved) error += "; checkpoint persistence failed: " + persistenceError;
        return false;
    };
    // This stage has no permission to mutate physical resources.
    if (configured.empty()) return fail("failed", "Graphical scope is UNCONFIGURED");
    if (!preflight(error)) return fail("failed", error);
    if (!journal_.prepareMutation(checkpointRecord(domain_, previous, configured, "pending"),
                                  id, error)) return false;
    // Callbacks may have partially changed multiple files even when false.
    // Preserve checkpoint and resource provenance; never claim old protection.
    if (!ensure(error)) return fail("partial", error);
    if (!release(error)) return fail("partial", error);
    if (!verify(error)) return fail("partial", error);
    // Configured version must be re-proved by verify before this commit.
    if (!journal_.prepareMutation(checkpointRecord(domain_, previous, configured, "committed"),
                                  id, error)) return false;
    return journal_.setStatus(id, MutationStatus::Applied, error);
}
} // namespace fic::rollback
