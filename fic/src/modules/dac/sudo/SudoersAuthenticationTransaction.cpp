#include "SudoersAuthenticationTransaction.h"
#include "SudoersAuthenticationGrammar.h"
#include "SudoersGlobalDefaultsTransaction.h"

#include <algorithm>
#include <map>
#include <set>
#include <sys/stat.h>

namespace fic::sudoers {
using namespace fic::rollback;
namespace {
const PolicyRef policy{"DAC", "SudoEdit", kAuthenticationPolicy};
bool inside(std::size_t line, const std::vector<AuthenticationWrapper>& frames) {
    return std::any_of(frames.begin(), frames.end(), [&](const auto& frame) {
        return line >= frame.first && line <= frame.last;
    });
}
bool write(const CapturedSudoersDocument& doc, const std::string& content,
           AtomicWriteResult& result, std::string& error) {
    AtomicWriteOptions options;
    options.rejectSymlink = true; options.expectedTargetState = doc.state;
    return AtomicFileWriter::writeWithResult(doc.path.string(), content, options, &error, &result);
}
std::vector<std::vector<std::string>> topology(const SudoersConfiguration& config) {
    std::vector<std::vector<std::string>> result;
    for (const auto& doc : config.graphDocuments()) result.push_back({"file", canonicalizeSudoProofPath(doc.path)});
    for (const auto& dir : config.includedDirectoryTopology()) {
        std::vector<std::string> item{"directory", dir.canonicalPath.string(), dir.existed ? "present" : "absent"};
        item.insert(item.end(), dir.eligibleMembers.begin(), dir.eligibleMembers.end());
        result.push_back(std::move(item));
    }
    return result;
}
bool rewriteFrames(std::vector<SudoPhysicalLine>& lines, const std::filesystem::path& path,
                   const std::vector<AuthenticationProof>& allowed, bool& changed,
                   std::string& error) {
    changed = false; std::vector<AuthenticationWrapper> frames;
    if (!parseAuthenticationWrappers(lines, frames, error)) return false;
    for (auto it = frames.rbegin(); it != frames.rend(); ++it) {
        if (std::find(allowed.begin(), allowed.end(), it->proof(path)) == allowed.end()) continue;
        auto restored = splitPhysicalLines(it->original);
        // An unterminated original must still be physically final.
        if (!restored.empty() && restored.back().terminator.empty() && it->last + 1 != lines.size()) {
            error = "Conflict: foreign suffix after unterminated authentication original"; return false;
        }
        lines.erase(lines.begin() + it->first, lines.begin() + it->last + 1);
        lines.insert(lines.begin() + it->first, restored.begin(), restored.end());
        changed = true;
    }
    return true;
}
}
AuthenticationTransaction::AuthenticationTransaction(SudoersConfigurationOptions options,
    MutationJournal& journal, AuthenticationHooks hooks)
    : options_(std::move(options)), journal_(journal), hooks_(std::move(hooks)) {}

bool AuthenticationTransaction::boundary(SudoersConfiguration& config, std::string& error, bool compensation) {
    if (!journal_.usable()) { error = "Mutation journal unavailable"; return false; }
    if (options_.verifyProviderUnchanged && !options_.verifyProviderUnchanged(error)) return false;
    auto proofOptions = options_;
    if (compensation) {
        // A rejected native candidate must still be compensatable. ONLY this
        // pre-restore structural check omits native syntax validation; provider,
        // globals, wrappers, CAS and topology remain proven. Native validation
        // is mandatory after restore and before resolving the journal.
        proofOptions.validatorPath.clear(); proofOptions.requireValidator = false;
    }
    if (!GlobalDefaultsTransaction(proofOptions, journal_).verifyNoOwnedSetting("", error, true)) return false;
    if (hooks_.verifySharedOwnership && !hooks_.verifySharedOwnership(error)) return false;
    std::vector<SudoScopedDefaultsWrapperProof> scopedProofs;
    const auto scopedRecords = journal_.activeRecords({"DAC", "SudoEdit", std::string(kScopedDefaultsPolicyName)});
    if (scopedRecords.size() > 1) { error = "Multiple scoped Defaults records"; return false; }
    if (!scopedRecords.empty()) {
        const auto* payload = std::get_if<UndoReleaseSudoScopedDefaults>(&scopedRecords.front().undo.payload);
        if (!payload) { error = "Unexpected scoped Defaults payload"; return false; }
        scopedProofs = payload->targetProofs;
    }
    error = ScopedDefaultsTransaction(config, std::string(kScopedDefaultsPolicyName)).validateCurrentOwnership(scopedProofs);
    if (!error.empty()) return false;

    return config.verifyIncludedDirectoryTopologyUnchanged(error);
}
bool AuthenticationTransaction::capture(SudoersConfiguration& config,
    const std::vector<AuthenticationProof>& proofs, ScopedDefaultsCapturedState& out, std::string& error) {
    std::vector<SudoScopedDefaultsWrapperProof> paths;
    for (const auto& proof : proofs) paths.push_back({proof.wrapperId, proof.canonicalPath, proof.originalDigest});
    return ScopedDefaultsTransaction(config, kAuthenticationPolicy).captureProofAndGraphState(paths, out, error);
}
bool AuthenticationTransaction::prove(const ScopedDefaultsCapturedState& state,
    const std::vector<AuthenticationProof>& proofs, bool exact, bool fullyReleased,
    bool semantics, std::string& error) {
    std::set<std::string> ids, expectedIds;
    for (const auto& proof : proofs) if (!expectedIds.insert(proof.wrapperId).second) {
        error = "Duplicate authentication journal id"; return false;
    }
    for (const auto& doc : state.documents) {
        if (doc.kind == CapturedPathKind::Absent) continue;
        // Detached proof paths need the same source trust rules as the loaded
        // graph, bound to THIS capture instead of a second pathname lookup.
        if (options_.enforceOwnership && (doc.state.owner != 0 ||
            (doc.state.mode & (S_IWGRP | S_IWOTH)) != 0)) {
            error = "Untrusted captured sudoers source metadata: " + doc.path.string(); return false;
        }
        auto lines = splitPhysicalLines(doc.state.content);
        std::vector<AuthenticationWrapper> frames;
        if (!parseAuthenticationWrappers(lines, frames, error)) return false;
        for (const auto& frame : frames) {
            if (!ids.insert(frame.id).second || fullyReleased ||
                std::find(proofs.begin(), proofs.end(), frame.proof(doc.path)) == proofs.end()) {
                error = "Conflict: unknown, moved, duplicate or drifted authentication frame"; return false;
            }
        }
        // Scoped wrappers have their own journal authority. Validate this
        // family too; it cannot be used to hide an active FIC-like frame.
        std::vector<SudoDisabledWrapper> scoped;
        if (parseSudoDisabledWrappers(lines, scoped, error) != SudoWrapperParseStatus::Ok) return false;
        std::vector<SudoScopedDefaultsWrapperProof> scopedProofs;
        auto scopedRecords = journal_.activeRecords({"DAC", "SudoEdit", std::string(kScopedDefaultsPolicyName)});
        if (scopedRecords.size() > 1) { error = "Multiple scoped Defaults owners"; return false; }
        if (!scopedRecords.empty()) {
            const auto* payload = std::get_if<UndoReleaseSudoScopedDefaults>(&scopedRecords.front().undo.payload);
            if (!payload || scopedRecords.front().resource != kScopedDefaultsResource) { error = "Unexpected scoped journal payload"; return false; }
            scopedProofs = payload->targetProofs;
            for (const auto& proof : scopedProofs) if (expectedIds.count(proof.wrapperId)) {
                error = "Wrapper id reused across authentication and scoped ownership"; return false;
            }
        }
        if (!checkSudoWrapperProvenance(scoped, doc.path, std::string(kScopedDefaultsPolicyName), scopedProofs).safeToRelease()) {
            error = "Conflict: unproven scoped Defaults ownership"; return false;
        }
        for (const auto& wrapper : scoped)
            if (wrapper.policy != kScopedDefaultsPolicyName) { error = "Unknown scoped wrapper policy"; return false; }
        if (semantics) {
            for (const auto& entry : assembleSudoLogicalEntries(lines, true)) {
                if (inside(entry.firstPhysicalLine, frames)) continue;
                AuthenticationRule rule;
                if (!parseAuthenticationRule(entry, rule, error)) return false;
                if (!rule.edits.empty()) { error = "Active authentication bypass remains"; return false; }
                // Classic contextual exemptions may override the independent
                // global exemption owner. Never claim they are harmless.
                if (rule.kind == AuthenticationStatement::Defaults && rule.scopedDefaults &&
                    entry.text.find("exempt_group") != std::string::npos) {
                    error = "Unsupported contextual exempt_group; suppress scoped Defaults first"; return false;
                }
            }
        }
    }
    if (exact && ids != expectedIds) { error = "Missing authentication ownership"; return false; }
    return true;
}
bool AuthenticationTransaction::verifyOwnership(std::string& error, bool rejectScopedFrames) {
    SudoersConfiguration config(options_);
    if (!config.load(error) || !config.validateConfiguration(error) ||
        !GlobalDefaultsTransaction(options_, journal_).verifyNoOwnedSetting("", error, true)) return false;
    auto records = journal_.activeRecords(policy);
    if (records.size() > 1) { error = "Multiple authentication records"; return false; }
    std::vector<AuthenticationProof> proofs;
    if (!records.empty()) {
        const auto* payload = std::get_if<UndoReleaseSudoAuthentication>(&records.front().undo.payload);
        if (!payload) { error = "Unexpected authentication journal payload"; return false; }
        proofs = payload->targetProofs;
    }
    ScopedDefaultsCapturedState state;
    if (!capture(config, proofs, state, error) || !prove(state, proofs, false, false, false, error)) return false;
    if (rejectScopedFrames) for (const auto& doc : state.documents) {
        std::vector<AuthenticationWrapper> frames;
        if (doc.kind == CapturedPathKind::Present && !parseAuthenticationWrappers(splitPhysicalLines(doc.state.content), frames, error)) return false;
        for (const auto& frame : frames) if (frame.scoped) {
            error = "Conflict: contextual Defaults owned by authentication; disable authentication first"; return false;
        }
    }
    return config.verifyIncludedDirectoryTopologyUnchanged(error) &&
        ScopedDefaultsTransaction::proveCapturedStateDurable(state, error) &&
        (!options_.verifyProviderUnchanged || options_.verifyProviderUnchanged(error));
}
bool AuthenticationTransaction::compensate(SudoersConfiguration& config,
    const std::vector<AuthenticationProof>& previous, const std::vector<AuthenticationProof>& target,
    std::string& error) {
    ScopedDefaultsCapturedState state;
    if (!capture(config, target, state, error) || !prove(state, target, false, false, false, error)) return false;
    std::vector<AuthenticationProof> fresh;
    for (const auto& proof : target)
        if (std::find(previous.begin(), previous.end(), proof) == previous.end()) fresh.push_back(proof);
    for (const auto& doc : state.documents) {
        if (doc.kind == CapturedPathKind::Absent) continue;
        auto lines = splitPhysicalLines(doc.state.content); bool changed;
        if (!rewriteFrames(lines, doc.path, fresh, changed, error)) return false;
        if (changed) {
            if (!boundary(config, error, true)) return false;
            AtomicWriteResult result;
            if (!write(doc, joinPhysicalLines(lines), result, error)) return false;
        }
    }
    if (!config.load(error) || !config.validateConfiguration(error) || !boundary(config, error)) return false;
    if (!capture(config, target, state, error) || !prove(state, previous, true, false, false, error) ||
        !ScopedDefaultsTransaction::proveCapturedStateDurable(state, error)) return false;
    return boundary(config, error);
}

SudoersOperationResult AuthenticationTransaction::reconcile() {
    SudoersOperationResult result; std::string error;
    SudoersConfiguration config(options_);
    auto fail = [&](const std::string& e) { result.message = e; return result; };
    if (!config.load(error) || !config.validateConfiguration(error) || !boundary(config, error)) return fail(error);
    const auto exemption = config.inspectGlobalDefault("exempt_group");
    if (exemption.found && exemption.value != "DISABLE" && exemption.value != """")
        return fail("Authentication requires independent exempt_group prohibition");
    auto records = journal_.activeRecords(policy);
    if (records.size() > 1) return fail("Multiple authentication mutation records");
    std::vector<AuthenticationProof> previous;
    MutationId id = 0;
    if (!records.empty()) {
        const auto& record = records.front();
        const auto* payload = std::get_if<UndoReleaseSudoAuthentication>(&record.undo.payload);
        if (!payload || record.resource != kAuthenticationResource) return fail("Unexpected authentication ownership record");
        if (record.status == MutationStatus::RollbackFailed) return fail("Resolve RollbackFailed authentication ownership before apply");
        if (record.status == MutationStatus::Prepared) {
            ScopedDefaultsCapturedState state;
            if (!capture(config, payload->targetProofs, state, error)) return fail(error);
            if (prove(state, payload->targetProofs, true, false, true, error)) {
                if (!ScopedDefaultsTransaction::proveCapturedStateDurable(state, error) || !boundary(config, error) ||
                    !journal_.setStatus(record.id, MutationStatus::Applied, error)) return fail(error);
            } else {
                if (!compensate(config, payload->previousProofs, payload->targetProofs, error)) return fail(error);
                if (payload->previousProofs.empty()) {
                    if (!journal_.discard(record.id, error)) return fail(error);
                } else if (!journal_.normalizeSudoAuthenticationPreparedToPrevious(record.id, payload->previousProofs, error)) return fail(error);
            }
            // Journal writes may invalidate record references; re-read.
            return reconcile();
        }
        previous = payload->targetProofs;
        id = record.id;
    }
    ScopedDefaultsCapturedState state;
    if (!capture(config, previous, state, error) || !prove(state, previous, true, false, false, error)) return fail(error);
    const auto originalTopology = topology(config);
    std::map<std::string, AtomicTargetState> expectedStates;
    for (const auto& doc : state.documents) if (doc.kind == CapturedPathKind::Present)
        expectedStates.emplace(doc.path.string(), doc.state);
    struct Plan { const CapturedSudoersDocument* doc; std::string target; };
    std::vector<Plan> plans;
    auto target = previous;
    for (const auto& doc : state.documents) {
        if (doc.kind == CapturedPathKind::Absent) continue;
        // Detached proof files remain ownership authority, but new mutations
        // are limited to files in the actual loaded include graph.
        auto graph = config.graphDocuments();
        if (std::none_of(graph.begin(), graph.end(), [&](const auto& x) { return canonicalizeSudoProofPath(x.path) == doc.path.string(); })) continue;
        auto lines = splitPhysicalLines(doc.state.content);
        std::vector<AuthenticationWrapper> frames;
        if (!parseAuthenticationWrappers(lines, frames, error)) return fail(error);
        auto entries = assembleSudoLogicalEntries(lines, true);
        bool changed = false;
        for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
            if (inside(it->firstPhysicalLine, frames)) continue;
            AuthenticationRule rule;
            if (!parseAuthenticationRule(*it, rule, error)) return fail("Unsupported: " + error);
            if (rule.kind == AuthenticationStatement::Defaults && rule.scopedDefaults && it->text.find("exempt_group") != std::string::npos)
                return fail("Unsupported contextual exempt_group; suppress scoped Defaults first");
            if (rule.edits.empty()) continue;
            // Never interpose a second owner on an active entry of a frame.
            std::vector<SudoPhysicalLine> originalLines(lines.begin() + it->firstPhysicalLine,
                lines.begin() + it->firstPhysicalLine + it->lineCount);
            auto original = joinPhysicalLines(originalLines);
            std::string replacement; bool scoped;
            if (!authenticationReplacement(original, replacement, scoped, error)) return fail("Unsupported: " + error);
            auto wrapperId = generateSudoWrapperMutationId(static_cast<int>(target.size()));
            AuthenticationWrapper wrapper{wrapperId, original, replacement};
            auto frame = makeAuthenticationWrapper(wrapperId, original, replacement);
            lines.erase(lines.begin() + it->firstPhysicalLine, lines.begin() + it->firstPhysicalLine + it->lineCount);
            lines.insert(lines.begin() + it->firstPhysicalLine, frame.begin(), frame.end());
            target.push_back(wrapper.proof(doc.path)); changed = true;
        }
        if (changed) plans.push_back({&doc, joinPhysicalLines(lines)});
    }
    if (plans.empty()) {
        if (!boundary(config, error)) return fail(error);
        for (const auto& [path, expected] : expectedStates)
            if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(path, expected, &error)) return fail(error);
        if (!config.load(error) || !capture(config, previous, state, error) || !prove(state, previous, true, false, true, error) ||
            !ScopedDefaultsTransaction::proveCapturedStateDurable(state, error) || !boundary(config, error)) return fail(error);
        result.ok = true; result.message = "Authentication rules already proven"; return result;
    }
    if (!boundary(config, error)) return fail(error);
    if (hooks_.checkpoint) hooks_.checkpoint("before_prepared");
    MutationRecord record;
    record.policy = policy; record.resource = kAuthenticationResource;
    record.undo.backend = MutationBackend::Sudo;
    record.undo.payload = UndoReleaseSudoAuthentication{previous, target};
    if (!journal_.prepareMutation(record, id, error)) return fail(error);
    if (hooks_.checkpoint) hooks_.checkpoint("prepared");
    bool success = true;
    for (const auto& plan : plans) {
        if (hooks_.beforeWrite) hooks_.beforeWrite(plan.doc->path);
        if (!boundary(config, error)) { success = false; break; }
        AtomicWriteResult written;
        if (!write(*plan.doc, plan.target, written, error)) { success = false; break; }
        result.changed = true;
        if (!written.installedTargetState) { error = "Missing installed state proof"; success = false; break; }
        expectedStates[plan.doc->path.string()] = *written.installedTargetState;
        if (hooks_.checkpoint) hooks_.checkpoint("file");
    }
    if (success) {
        for (const auto& [path, expected] : expectedStates)
            if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(path, expected, &error)) { success = false; break; }
        if (success) success = boundary(config, error);
    }
    if (success) success = config.validateConfiguration(error) && config.load(error) && boundary(config, error);
    if (success && topology(config) != originalTopology) {
        error = "Include graph changed during authentication apply"; success = false;
    }
    if (success) success = capture(config, target, state, error) && prove(state, target, true, false, true, error) &&
        ScopedDefaultsTransaction::proveCapturedStateDurable(state, error) && boundary(config, error);
    if (success) {
        if (hooks_.checkpoint) hooks_.checkpoint("postcondition");
        if (!journal_.setStatus(id, MutationStatus::Applied, error)) return fail(error);
        result.ok = true; result.message = "Authentication rules applied with reversible ownership"; return result;
    }
    const auto originalError = error;
    if (compensate(config, previous, target, error)) {
        if (previous.empty()) success = journal_.discard(id, error);
        else success = journal_.normalizeSudoAuthenticationPreparedToPrevious(id, previous, error);
        result.message = originalError + (success ? "; compensated" : "; compensation journal unresolved: " + error);
    } else result.message = originalError + "; ownership remains Prepared: " + error;
    return result;
}

SudoersOperationResult AuthenticationTransaction::release(const UndoReleaseSudoAuthentication& payload) {
    SudoersOperationResult result; std::string error;
    SudoersConfiguration config(options_);
    auto fail = [&](const std::string& e) { result.conflict = true; result.message = e; return result; };
    if (!config.load(error) || !boundary(config, error) || !config.validateConfiguration(error)) return fail(error);
    ScopedDefaultsCapturedState state;
    if (!capture(config, payload.targetProofs, state, error) || !prove(state, payload.targetProofs, false, false, false, error)) return fail(error);
    bool scopedRequested = false;
    if (!hooks_.requestedScopedState || !hooks_.requestedScopedState(scopedRequested, error))
        return fail("Cannot prove surviving scoped Defaults intent: " + error);
    struct Plan { const CapturedSudoersDocument* doc; std::string target; };
    std::vector<Plan> plans;
    for (const auto& doc : state.documents) {
        if (doc.kind == CapturedPathKind::Absent) continue;
        auto lines = splitPhysicalLines(doc.state.content);
        std::vector<AuthenticationWrapper> frames;
        if (!parseAuthenticationWrappers(lines, frames, error)) return fail(error);
        for (const auto& frame : frames) if (scopedRequested && frame.scoped)
            return fail("Conflict: authentication rollback would restore contextual Defaults while scoped suppression is requested");
        bool changed;
        if (!rewriteFrames(lines, doc.path, payload.targetProofs, changed, error)) return fail(error);
        if (changed) plans.push_back({&doc, joinPhysicalLines(lines)});
    }
    // Keep the journal unresolved on a partial release. Existing wrappers
    // that disappeared are a released subset and will never be recreated.
    for (const auto& plan : plans) {
        if (hooks_.beforeWrite) hooks_.beforeWrite(plan.doc->path);
        if (!boundary(config, error)) return fail(error);
        AtomicWriteResult written;
        if (!write(*plan.doc, plan.target, written, error)) return fail(error);
        result.changed = true;
        if (hooks_.checkpoint) hooks_.checkpoint("release_file");
    }
    if (!config.load(error) || !config.validateConfiguration(error) || !capture(config, payload.targetProofs, state, error) ||
        !prove(state, {}, false, true, false, error) || !ScopedDefaultsTransaction::proveCapturedStateDurable(state, error) ||
        !boundary(config, error)) return fail(error);
    result.ok = true; result.targetMissing = plans.empty(); result.message = "Authentication ownership released byte-exact";
    return result;
}
}

#include <fic/core/config/ModuleConfigFileHandler.h>
namespace fic::sudoers {
bool readSudoRequestedState(bool& authentication, bool& scoped, std::string& error) {
    ModuleConfigFileHandler config("DAC");
    if (!config.loadConfig() || !config.hasPolicyStatus(kAuthenticationPolicy) ||
        !config.hasPolicyStatus(std::string(kScopedDefaultsPolicyName))) {
        error = "Cannot prove requested SUDO policy configuration"; return false;
    }
    const auto auth = config.getPolicyStatus(kAuthenticationPolicy);
    const auto scope = config.getPolicyStatus(std::string(kScopedDefaultsPolicyName));
    if ((auth != "ENABLE" && auth != "DISABLE") || (scope != "ENABLE" && scope != "DISABLE")) {
        error = "Invalid requested SUDO policy state"; return false;
    }
    authentication = auth == "ENABLE"; scoped = scope == "ENABLE";
    return true;
}
bool guardScopedAuthenticationRelease(SudoersConfiguration& config,
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    bool requested, std::string& error) {
    if (!requested) return true;
    ScopedDefaultsCapturedState state;
    ScopedDefaultsTransaction transaction(config, std::string(kScopedDefaultsPolicyName));
    if (!transaction.captureProofAndGraphState(proofs, state, error)) return false;
    for (const auto& doc : state.documents) {
        if (doc.kind == CapturedPathKind::Absent) continue;
        std::vector<SudoDisabledWrapper> wrappers;
        if (parseSudoDisabledWrappers(splitPhysicalLines(doc.state.content), wrappers, error) != SudoWrapperParseStatus::Ok) return false;
        for (const auto& wrapper : wrappers) {
            if (wrapper.policy != kScopedDefaultsPolicyName) { error = "Unknown scoped wrapper policy"; return false; }
            auto entries = assembleSudoLogicalEntries(wrapper.originalLines, true);
            for (const auto& entry : entries) {
                AuthenticationRule rule;
                if (!parseAuthenticationRule(entry, rule, error) || !rule.edits.empty() ||
                    entry.text.find("exempt_group") != std::string::npos) {
                    error = "Conflict: scoped Defaults release would restore an authentication bypass while authentication is requested";
                    return false;
                }
            }
        }
    }
    return true;
}
}
