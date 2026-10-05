#include "modules/dac/sudo/SudoersLogicalEntries.h"
#include "modules/dac/sudo/SudoersScopedDefaults.h"
#include "modules/dac/sudo/SudoersScopedDefaultsTransaction.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/integrity/ContentDigest.h>

#include <algorithm>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace fic::sudoers {
namespace {

// Offset of the 1-based physical line number inside a lines vector.
std::size_t lineOffset(const std::vector<SudoPhysicalLine>& lines,
                       size_t lineNumber) {
    return lineNumber >= 1 ? lineNumber - 1 : 0;
}

std::vector<SudoPhysicalLine> linesOf(const std::string& content) {
    return splitPhysicalLines(content);
}

// The exact bytes FIC will suppress for one physical target, and their
// fingerprint. Shared by planning and by the pre-write digest check so both
// sides can never compute different bytes.
std::string suppressedDigest(
    const std::vector<SudoersConfiguration::GraphDocument>& documents,
    const ScopedDefaultsTarget& target) {
    for (const SudoersConfiguration::GraphDocument& document : documents) {
        if (document.path != target.path) {
            continue;
        }
        const std::vector<SudoPhysicalLine> lines = linesOf(document.content);
        const std::size_t offset = lineOffset(lines, target.firstLine);
        std::vector<SudoPhysicalLine> suppressed;
        for (size_t n = 0; n < target.lineCount; ++n) {
            if (offset + n >= lines.size()) {
                return {};
            }
            suppressed.push_back(lines[offset + n]);
        }
        return SudoDisabledWrapper{{}, {}, suppressed, 0, 0}.payloadDigest();
    }
    return {};
}

} // namespace


bool ScopedDefaultsTransaction::captureProofAndGraphState(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    ScopedDefaultsCapturedState& out,
    std::string& error) const {
    // Capture set = every current graph document UNION every proof path.
    std::set<std::string> paths;
    for (const SudoersConfiguration::GraphDocument& document :
         configuration_.graphDocuments()) {
        paths.insert(canonicalizeSudoProofPath(document.path));
    }
    for (const SudoScopedDefaultsWrapperProof& proof : proofs) {
        paths.insert(proof.canonicalPath);
    }
    out.documents.clear();
    out.documents.reserve(paths.size());
    for (const std::string& path : paths) {
        CapturedSudoersDocument document;
        document.path = std::filesystem::path(path);
        std::string captureError;
        if (AtomicFileWriter::captureTargetState(path, document.state,
                                                  &captureError)) {
            document.kind = CapturedPathKind::Present;
            out.documents.push_back(std::move(document));
            continue;
        }
        // A capture failure is NOT an absence. Only the typed absence primitive
        // may classify a path as proven absent; anything else fails closed.
        std::string absenceError;
        if (!AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
                path, &absenceError)) {
            error = "не удалось классифицировать sudoers-путь " + path + ": " +
                    captureError + "; " + absenceError;
            return false;
        }
        document.kind = CapturedPathKind::Absent;
        out.documents.push_back(std::move(document));
    }
    return true;
}

bool ScopedDefaultsTransaction::proveCapturedStateDurable(
    const ScopedDefaultsCapturedState& captured, std::string& error) {
    // Confirms EXACTLY the captures that were parsed and proven. A filesystem
    // that changed since the capture fails closed, so the barrier can never
    // legitimize a different state than the one ownership was proven against.
    for (const CapturedSudoersDocument& document : captured.documents) {
        std::string durabilityError;
        if (document.kind == CapturedPathKind::Absent) {
            // Absence must still be durable, and an object that reappeared
            // since the capture fails closed.
            if (!AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
                    document.path.string(), &durabilityError)) {
                error += "absence barrier не пройден для " +
                         document.path.string() + ": " + durabilityError + "; ";
                return false;
            }
            continue;
        }
        if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                document.path.string(), document.state, &durabilityError)) {
            error += "durability barrier не пройден для " +
                     document.path.string() + ": " + durabilityError + "; ";
            return false;
        }
    }
    return true;
}


PreparedRecovery ScopedDefaultsTransaction::classifyCaptured(
    const std::vector<SudoScopedDefaultsWrapperProof>& previousProofs,
    const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
    const ScopedDefaultsCapturedState& captured,
    std::string& error) const {
    // Identity of what is physically present, from the CAPTURES only.
    std::map<std::string, std::pair<std::string, std::string>> actual;
    std::map<std::string, std::string> idOwner;
    for (const CapturedSudoersDocument& document : captured.documents) {
        if (document.kind == CapturedPathKind::Absent) {
            continue;
        }
        const std::vector<SudoPhysicalLine> lines = linesOf(document.state.content);
        std::vector<SudoDisabledWrapper> wrappers;
        if (parseSudoDisabledWrappers(lines, wrappers, error) !=
            SudoWrapperParseStatus::Ok) {
            return PreparedRecovery::Indeterminate;
        }
        const std::string canonical =
            canonicalizeSudoProofPath(document.path);
        for (const SudoDisabledWrapper& wrapper : wrappers) {
            if (wrapper.policy != policyName_) {
                continue;
            }
            // A duplicate id across files makes the state unclassifiable.
            const auto seen = idOwner.find(wrapper.mutationId);
            if (seen != idOwner.end() && seen->second != canonical) {
                return PreparedRecovery::Indeterminate;
            }
            idOwner.emplace(wrapper.mutationId, canonical);
            actual[wrapper.mutationId] =
                std::make_pair(canonical, wrapper.payloadDigest());
        }
    }
    const auto matchesExactly = [&actual](
            const std::vector<SudoScopedDefaultsWrapperProof>& expected) {
        std::map<std::string, std::pair<std::string, std::string>> wanted;
        for (const SudoScopedDefaultsWrapperProof& proof : expected) {
            wanted[proof.wrapperId] =
                std::make_pair(proof.canonicalPath, proof.payloadDigest);
        }
        return wanted == actual;
    };
    if (matchesExactly(targetProofs)) {
        return PreparedRecovery::CompleteTarget;
    }
    if (matchesExactly(previousProofs)) {
        return PreparedRecovery::CompletePrevious;
    }
    return PreparedRecovery::Indeterminate;
}

ScopedDefaultsStateProof ScopedDefaultsTransaction::proveCapturedState(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    const ScopedDefaultsCapturedState& captured,
    ScopedDefaultsProofMode mode,
    bool requireNoActiveScopedDefaults) const {
    ScopedDefaultsStateProof proof;
    proof.captured = captured;

    std::map<std::string, std::vector<SudoDisabledWrapper>> byPath;
    std::map<std::string, std::filesystem::path> idOwner;
    for (const CapturedSudoersDocument& document : captured.documents) {
        if (document.kind == CapturedPathKind::Absent) {
            continue;
        }
        const std::vector<SudoPhysicalLine> lines =
            linesOf(document.state.content);
        std::vector<SudoDisabledWrapper> wrappers;
        std::string parseError;
        if (parseSudoDisabledWrappers(lines, wrappers, parseError) !=
            SudoWrapperParseStatus::Ok) {
            proof.message = "Не удалось разобрать FIC-маркеры " +
                            document.path.string() + ": " + parseError;
            return proof;
        }
        for (const SudoDisabledWrapper& wrapper : wrappers) {
            if (wrapper.policy != policyName_) {
                continue;
            }
            // GLOBAL uniqueness over the captured snapshot: one id is
            // permission for exactly one physical wrapper.
            const std::string canonical =
                canonicalizeSudoProofPath(document.path);
            const auto seen = idOwner.find(wrapper.mutationId);
            if (seen != idOwner.end() && seen->second != canonical) {
                proof.message = "wrapper id '" + wrapper.mutationId +
                                "' встречается в двух sudoers-файлах (" +
                                seen->second.string() + " и " + canonical +
                                "); владение не может быть доказано";
                return proof;
            }
            idOwner.emplace(wrapper.mutationId, canonical);
            byPath[canonical].push_back(wrapper);
        }
    }

    if (mode == ScopedDefaultsProofMode::FullyReleased) {
        // NONE of the expected wrappers may exist anywhere in the captured
        // graph, and no unknown/duplicate/owned wrapper may survive.
        if (!idOwner.empty()) {
            proof.message =
                "ожидаемая обёртка всё ещё физически присутствует: ";
            for (const auto& [id, path] : idOwner) {
                proof.message += id + " (" + path.string() + ") ";
            }
            return proof;
        }
        for (const SudoScopedDefaultsWrapperProof& expected : proofs) {
            std::vector<SudoPhysicalLine> lines;
            for (const CapturedSudoersDocument& document : captured.documents) {
                if (canonicalizeSudoProofPath(document.path) !=
                    expected.canonicalPath) {
                    continue;
                }
                if (document.kind == CapturedPathKind::Absent) {
                    continue;
                }
                lines = linesOf(document.state.content);
            }
            if (lines.empty()) {
                continue;
            }
            std::vector<SudoDisabledWrapper> parsed;
            std::string parseError;
            if (parseSudoDisabledWrappers(lines, parsed, parseError) !=
                SudoWrapperParseStatus::Ok) {
                proof.message = parseError;
                return proof;
            }
            for (const SudoDisabledWrapper& wrapper : parsed) {
                if (wrapper.policy == policyName_) {
                    proof.message = "обёртка '" + wrapper.mutationId +
                                    "' всё ещё присутствует в " +
                                    expected.canonicalPath;
                    return proof;
                }
            }
        }
        proof.ok = true;
        proof.captured = captured;
        return proof;
    }

    const SudoWrapperProofMode wrapperMode =
        mode == ScopedDefaultsProofMode::Exact
            ? SudoWrapperProofMode::Exact
            : SudoWrapperProofMode::ReleaseSubset;
    for (const auto& [path, wrappers] : byPath) {
        const SudoWrapperProvenanceCheck check = checkSudoWrapperProvenance(
            wrappers, std::filesystem::path(path), policyName_, proofs,
            wrapperMode);
        if (!check.safeToRelease()) {
            proof.message = describeSudoWrapperProvenance(check, policyName_);
            return proof;
        }
    }

    // Missing expected proofs, decided over the WHOLE captured snapshot (not
    // per file). In Exact mode any missing proof is a failure; in
    // ReleaseSubset mode it is an already released subset.
    std::vector<std::string> missing;
    for (const SudoScopedDefaultsWrapperProof& expected : proofs) {
        if (idOwner.find(expected.wrapperId) == idOwner.end()) {
            missing.push_back(expected.wrapperId);
        }
    }
    if (mode == ScopedDefaultsProofMode::Exact && !missing.empty()) {
        proof.message =
            "ожидаемая обёртка отсутствует на диске, target/previous-state не "
            "доказан: ";
        for (const std::string& id : missing) {
            proof.message += id + " ";
        }
        return proof;
    }

    // SEMANTIC verification on the SAME captures: an active scoped Defaults is a
    // start line that is NOT inside a FIC wrapper.
    for (const CapturedSudoersDocument& document :
         requireNoActiveScopedDefaults ? captured.documents
                                       : ScopedDefaultsCapturedState{}.documents) {
        if (document.kind == CapturedPathKind::Absent) {
            continue;
        }
        const std::vector<SudoPhysicalLine> lines =
            linesOf(document.state.content);
        std::vector<SudoDisabledWrapper> wrappers;
        std::string parseError;
        if (parseSudoDisabledWrappers(lines, wrappers, parseError) !=
            SudoWrapperParseStatus::Ok) {
            proof.message = parseError;
            return proof;
        }
        // THE shared logical-entry assembler: the semantic decision is taken on
        // whole logical entries, exactly like SudoersConfiguration builds them,
        // so a multi-line scoped Defaults can no longer be classified one
        // physical line at a time.
        const std::vector<SudoLogicalEntry> entries =
            assembleSudoLogicalEntries(lines);
        // beginLine/endLine index the BEGIN/END MARKER lines themselves, and a
        // FIC-created wrapper replaces the original entry with its marker
        // payload, so the suppressed PAYLOAD is strictly BETWEEN the markers.
        // Marking the marker lines as suppressed would misattribute them to a
        // logical entry and invent a boundary conflict FIC never produces.
        std::vector<bool> suppressed(lines.size(), false);
        for (const SudoDisabledWrapper& wrapper : wrappers) {
            const std::size_t payloadBegin = wrapper.beginLine + 1;
            const std::size_t payloadEnd =
                wrapper.endLine > wrapper.beginLine ? wrapper.endLine - 1
                                                    : wrapper.beginLine;
            for (std::size_t n = payloadBegin; n <= payloadEnd &&
                                                n < suppressed.size(); ++n) {
                suppressed[n] = true;
            }
        }
        for (const SudoLogicalEntry& entry : entries) {
            std::size_t suppressedCount = 0;
            for (std::size_t offset = 0; offset < entry.lineCount; ++offset) {
                const std::size_t index = entry.firstPhysicalLine + offset;
                if (index < suppressed.size() && suppressed[index]) {
                    ++suppressedCount;
                }
            }
            if (suppressedCount == entry.lineCount) {
                continue;
            }
            // Some physical lines of this logical entry are inside a FIC
            // wrapper and some are not.
            const bool entryPartiallySuppressed = suppressedCount > 0;
            // A FIC-created wrapper always owns a WHOLE logical entry, so a
            // logical entry straddling a wrapper boundary means the file was
            // edited into a shape FIC never produces. Its semantics cannot be
            // guessed, so the proof fails closed.
            if (entryPartiallySuppressed) {
                proof.message =
                    "логическая запись частично пересекает границу "
                    "FIC-обёртки в " +
                    document.path.string() + "; доказательство невозможно";
                return proof;
            }
            if (scopedDefaultsScope(entry.text).empty()) {
                continue;
            }
            proof.message = "активный контекстный Defaults остаётся вне "
                            "FIC-обёртки в " + document.path.string();
            return proof;
        }
    }

    proof.ok = true;
    return proof;
}

ScopedDefaultsTransaction::ScopedDefaultsTransaction(
    SudoersConfiguration& configuration,
    std::string policyName)
    : configuration_(configuration), policyName_(std::move(policyName)) {}

std::vector<ScopedDefaultsTarget> ScopedDefaultsTransaction::targets() const {
    // Semantic occurrences may repeat the same physical entry when a file is
    // included several times, so they are de-duplicated by
    // (canonical path, first physical line, physical line count).
    const std::vector<SudoersConfiguration::GraphDocument> documents =
        configuration_.graphDocuments();
    const std::vector<SudoersConfiguration::GraphEntry> entries =
        configuration_.graphEntries();

    std::set<std::tuple<std::string, size_t, size_t>> seen;
    std::vector<ScopedDefaultsTarget> result;
    for (const SudoersConfiguration::GraphEntry& entry : entries) {
        if (scopedDefaultsScope(entry.text).empty()) {
            continue;
        }
        if (entry.documentIndex >= documents.size()) {
            continue;
        }
        const std::filesystem::path& path = documents[entry.documentIndex].path;
        if (!seen.insert(std::make_tuple(path.string(), entry.firstLine,
                                         entry.lineCount)).second) {
            continue;
        }
        result.push_back({path, entry.firstLine, entry.lineCount});
    }
    return result;
}

bool ScopedDefaultsTransaction::globalInventory(
    std::vector<OwnedWrapper>& inventory,
    std::string& error) const {
    inventory.clear();
    // One id is permission for EXACTLY one physical wrapper. The same id in two
    // files would let a single journal entry unwrap foreign content, so it is
    // refused before ANY write.
    std::map<std::string, std::filesystem::path> idOwner;
    for (const SudoersConfiguration::GraphDocument& document :
         configuration_.graphDocuments()) {
        const std::vector<SudoPhysicalLine> lines = linesOf(document.content);
        std::vector<SudoDisabledWrapper> wrappers;
        if (parseSudoDisabledWrappers(lines, wrappers, error) !=
            SudoWrapperParseStatus::Ok) {
            return false;
        }
        for (const SudoDisabledWrapper& wrapper : wrappers) {
            const auto owner = idOwner.find(wrapper.mutationId);
            if (owner != idOwner.end() && owner->second != document.path) {
                error = "wrapper id '" + wrapper.mutationId +
                    "' встречается в двух sudoers-файлах (" +
                    owner->second.string() + " и " + document.path.string() +
                    "); владение не может быть доказано";
                return false;
            }
            idOwner.emplace(wrapper.mutationId, document.path);
            inventory.push_back({wrapper, document.path});
        }
    }
    return true;
}

std::string ScopedDefaultsTransaction::validateCurrentOwnership(
    const std::vector<SudoScopedDefaultsWrapperProof>& activeProofs) const {
    // The current include graph is NOT the ownership authority. An external
    // process may have removed an @include while the journal still proves
    // ownership of a wrapper that physically remains at its canonical path, so
    // a graph-only inventory would silently stop inspecting exactly the files
    // the journal claims.
    //
    // The capture set is therefore the current graph UNION every active proof
    // path. Ownership is then decided ON THAT SNAPSHOT:
    //   * GLOBAL uniqueness of wrapper ids across the combined set, so a
    //     duplicate id in a graph file and in a proof-only path is detected;
    //   * per file, an existing wrapper must be proven by an active proof that
    //     names that EXACT file with an EXACT payload digest. Drift, a moved
    //     wrapper, an unknown id, a duplicate inside one file and malformed
    //     markers all fail closed;
    //   * a proven wrapper that is physically gone stays an already released
    //     subset, which is the pre-existing external-release contract and is
    //     deliberately NOT redefined here;
    //   * a capture failure (symlink, directory, permission, I/O) fails closed
    //     and is never reclassified as an absence.
    //
    // Durability is intentionally NOT required: this is a read-only preflight
    // and no journal transition happens here.
    ScopedDefaultsCapturedState captured;
    std::string captureError;
    if (!captureProofAndGraphState(activeProofs, captured, captureError)) {
        return "не удалось захватить sudoers-пути для проверки владения: " +
               captureError;
    }
    const ScopedDefaultsStateProof proof = proveCapturedState(
        activeProofs, captured, ScopedDefaultsProofMode::ReleaseSubset,
        /*requireNoActiveScopedDefaults=*/false);
    return proof.ok ? std::string() : proof.message;
}

std::string ScopedDefaultsTransaction::noopPreflight(
    const std::vector<SudoScopedDefaultsWrapperProof>& activeProofs) const {
    if (!targets().empty()) {
        return "активные контекстные Defaults всё ещё присутствуют";
    }
    return validateCurrentOwnership(activeProofs);
}

ScopedDefaultsPlan ScopedDefaultsTransaction::plan(
    const std::vector<SudoScopedDefaultsWrapperProof>& owned) const {
    ScopedDefaultsPlan result;
    result.owned = owned;
    const std::vector<SudoersConfiguration::GraphDocument> documents =
        configuration_.graphDocuments();
    const std::vector<ScopedDefaultsTarget> physical = targets();
    for (size_t index = 0; index < physical.size(); ++index) {
        PlannedScopedDefaultsMutation mutation;
        mutation.target = physical[index];
        mutation.proof.wrapperId =
            generateSudoWrapperMutationId(static_cast<int>(index));
        mutation.proof.canonicalPath =
            canonicalizeSudoProofPath(physical[index].path);
        mutation.proof.payloadDigest =
            suppressedDigest(documents, physical[index]);
        result.fresh.push_back(std::move(mutation));
    }
    return result;
}

namespace {

// One file participating in the transaction, with the exact state it was
// captured in and the state FIC published.
struct FileTransaction {
    std::filesystem::path path;
    AtomicTargetState captured;               // precondition (CAS)
    std::optional<AtomicTargetState> installed; // what FIC published, if any
    std::string newContent;
};

// State-bound compensation: restores `original` ONLY when the target still is
// exactly the state FIC installed. An externally changed file is preserved and
// reported, never overwritten with FIC's historical content.
// Invokes a user/injection hook, converting a thrown exception into a normal
// failure string. A hook is the deterministic fault-injection seam, so an
// escaping exception must never skip the compensation step.
bool invokeHook(const std::function<void(const std::filesystem::path&)>& hook,
                const std::filesystem::path& path,
                std::string& error) {
    if (!hook) {
        return true;
    }
    try {
        hook(path);
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    } catch (...) {
        error = "неизвестная ошибка в hook записи " + path.string();
        return false;
    }
    return true;
}

bool compensateFiles(std::vector<FileTransaction>& transactions,
                     const std::function<void(const std::filesystem::path&)>& hook,
                     std::string& error) {
    bool allRestored = true;
    for (auto item = transactions.rbegin(); item != transactions.rend(); ++item) {
        if (!item->installed.has_value()) {
            continue;
        }
        std::string hookError;
        if (!invokeHook(hook, item->path, hookError)) {
            allRestored = false;
            error += "компенсация " + item->path.string() +
                " прервана инжектированной ошибкой: " + hookError + "; ";
            continue;
        }
        AtomicWriteOptions options;
        options.rejectSymlink = true;
        options.expectedTargetState = *item->installed;
        AtomicWriteResult result;
        std::string writeError;
        if (!AtomicFileWriter::writeWithResult(
                item->path.string(), item->captured.content, options,
                &writeError, &result)) {
            allRestored = false;
            error += "компенсация " + item->path.string() + " не выполнена: " +
                (writeError.empty() ? std::string("причина неизвестна")
                                    : writeError) + "; ";
            continue;
        }
        item->installed = result.installedTargetState;
        if (!result.durabilityConfirmed) {
            allRestored = false;
            error += "компенсация " + item->path.string() +
                " не подтверждена долговечно; ";
        }
    }
    return allRestored;
}


// Durability barrier for an ALREADY OBSERVED state.
//
// Seeing a wrapper on disk proves nothing about power-loss durability: the
// rename(2) that published it may never have been followed by a parent-directory
// fsync before a crash. This re-proves the exact current state of every path and
// only then confirms the directory entry, so a journal transition is never
// justified by a merely VISIBLE file.
} // namespace

bool proveObservedStateDurable(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    std::string& error) {
    for (const std::filesystem::path& path : proofPaths(proofs)) {
        AtomicTargetState current;
        std::string captureError;
        if (!AtomicFileWriter::captureTargetState(path.string(), current,
                                                  &captureError)) {
            // A capture failure is NOT an absence: a symlink, a directory, a
            // permission or I/O error would be silently accepted here. Only the
            // typed absence barrier proves "the target is gone" durably; any
            // other condition stays a hard failure.
            std::string absenceError;
            if (AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
                    path.string(), &absenceError)) {
                continue;
            }
            error += "не удалось доказать durable-состояние " + path.string() +
                     ": " + captureError + "; " + absenceError + "; ";
            return false;
        }
        std::string durabilityError;
        if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                path.string(), current, &durabilityError)) {
            error += "durability barrier не пройден для " + path.string() +
                     ": " + durabilityError + "; ";
            return false;
        }
    }
    return true;
}

// The paths a proof set refers to, deduplicated and deterministically ordered.
// The durability barrier runs over exactly the files the proofs authorize.
static std::vector<std::filesystem::path> proofPathsImpl(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs) {
    std::set<std::string> unique;
    for (const SudoScopedDefaultsWrapperProof& proof : proofs) {
        unique.insert(proof.canonicalPath);
    }
    std::vector<std::filesystem::path> result;
    result.reserve(unique.size());
    for (const std::string& path : unique) {
        result.emplace_back(path);
    }
    return result;
}


namespace {

// Terminal-state helper used by EVERY failure branch of apply() and release().
//
// The filesystem state is derived from the transaction as a WHOLE, never from
// the result of the single write that happened to fail: a failure on the last
// file must not report "nothing was written" while an earlier file still holds
// an installed wrapper.
SudoScopedDefaultsFilesystemState settleFilesystemState(
    const std::vector<FileTransaction>& transactions) {
    for (const FileTransaction& item : transactions) {
        if (item.installed.has_value()) {
            return SudoScopedDefaultsFilesystemState::PartialOrUnknown;
        }
    }
    return SudoScopedDefaultsFilesystemState::Unchanged;
}

// Attempts to restore every installed file. Returns the resulting state:
// Unchanged when nothing had been installed, Compensated when every installed
// file was provably restored, PartialOrUnknown otherwise.
SudoScopedDefaultsFilesystemState settleWithCompensation(
    std::vector<FileTransaction>& transactions,
    const std::function<void(const std::filesystem::path&)>& hook,
    std::string& error) {
    if (settleFilesystemState(transactions) ==
        SudoScopedDefaultsFilesystemState::Unchanged) {
        return SudoScopedDefaultsFilesystemState::Unchanged;
    }
    return compensateFiles(transactions, hook, error)
        ? SudoScopedDefaultsFilesystemState::Compensated
        : SudoScopedDefaultsFilesystemState::PartialOrUnknown;
}

} // namespace

std::vector<std::filesystem::path> proofPaths(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs) {
    return proofPathsImpl(proofs);
}

SudoScopedDefaultsTransactionResult ScopedDefaultsTransaction::apply(
    const std::vector<PlannedScopedDefaultsMutation>& fresh,
    const SudoScopedDefaultsHooks& hooks) {
    SudoScopedDefaultsTransactionResult result;
    result.filesystemState = SudoScopedDefaultsFilesystemState::Unchanged;
    std::string error;

    // Every early return below happens BEFORE the first write, so the
    // filesystem is provably untouched and the Prepared record may be discarded.
    const auto refuse = [&](const std::string& message) {
        result.kind = SudoScopedDefaultsResultKind::Conflict;
        result.operation.conflict = true;
        result.operation.message = message;
        result.filesystemState = SudoScopedDefaultsFilesystemState::Unchanged;
        return result;
    };

    std::vector<OwnedWrapper> inventory;
    if (!globalInventory(inventory, error)) {
        return refuse(error);
    }
    std::set<std::string> usedIds;
    for (const OwnedWrapper& owned : inventory) {
        usedIds.insert(owned.wrapper.mutationId);
    }
    const std::vector<SudoersConfiguration::GraphDocument> documents =
        configuration_.graphDocuments();

    if (fresh.empty()) {
        result.kind = SudoScopedDefaultsResultKind::Success;
        result.operation.ok = true;
        result.operation.message = "Активных контекстных Defaults не обнаружено";
        return result;
    }

    for (const PlannedScopedDefaultsMutation& mutation : fresh) {
        const SudoScopedDefaultsWrapperProof& proof = mutation.proof;
        if (!isCanonicalSudoWrapperId(proof.wrapperId) ||
            !fic::core::ContentDigest::isCanonicalSha256Hex(
                proof.payloadDigest)) {
            return refuse("Некорректная provenance новой обёртки");
        }
        if (!usedIds.insert(proof.wrapperId).second) {
            return refuse("wrapper id '" + proof.wrapperId +
                          "' уже используется другим FIC_SUDO_DISABLED блоком");
        }
        // The proof must name the EXACT file FIC is about to modify.
        if (proof.canonicalPath !=
            canonicalizeSudoProofPath(mutation.target.path)) {
            return refuse("Подготовленный proof для обёртки '" +
                          proof.wrapperId +
                          "' ссылается на другой sudoers-файл");
        }
        // The proof must describe the bytes this very target suppresses.
        if (proof.payloadDigest !=
            suppressedDigest(documents, mutation.target)) {
            return refuse("Подготовленный digest для обёртки '" +
                          proof.wrapperId +
                          "' не совпадает с подавляемыми байтами");
        }
    }

    // Group WHOLE (target, proof) pairs per file, then sort bottom-up. Sorting
    // moves the pair, never the proof alone, so a proof can never end up on a
    // different entry.
    std::map<std::filesystem::path,
             std::vector<PlannedScopedDefaultsMutation>> perDocument;
    for (const PlannedScopedDefaultsMutation& mutation : fresh) {
        perDocument[mutation.target.path].push_back(mutation);
    }

    std::vector<FileTransaction> transactions;
    for (auto& entry : perDocument) {
        FileTransaction transaction;
        transaction.path = entry.first;
        // State-bound precondition: capture the exact target state now.
        if (!AtomicFileWriter::captureTargetState(
                entry.first.string(), transaction.captured, &error)) {
            return refuse("Не удалось зафиксировать состояние sudoers-файла " +
                          entry.first.string() + ": " + error);
        }
        // Bind every planned line range to the SNAPSHOT it was computed from.
        // Without this, an external writer that inserted or removed a line
        // between load() and captureTargetState() would make FIC wrap a
        // different entry than the one the journal proof describes. The range
        // is never silently recomputed: the caller must reload and re-plan.
        for (const auto& document : documents) {
            if (document.path == entry.first) {
                if (document.content != transaction.captured.content) {
                    return refuse(
                        "Sudoers-файл изменился между загрузкой графа и "
                        "захватом состояния: " + entry.first.string() +
                        "; требуется перезагрузка графа и новое планирование");
                }
                break;
            }
        }
        std::vector<SudoPhysicalLine> lines = linesOf(transaction.captured.content);
        std::sort(entry.second.begin(), entry.second.end(),
                  [](const PlannedScopedDefaultsMutation& left,
                     const PlannedScopedDefaultsMutation& right) {
                      return left.target.firstLine > right.target.firstLine;
                  });
        for (const PlannedScopedDefaultsMutation& mutation : entry.second) {
            const std::size_t offset =
                lineOffset(lines, mutation.target.firstLine);
            if (offset + mutation.target.lineCount > lines.size()) {
                return refuse("Диапазон строк вышел за пределы файла " +
                              entry.first.string());
            }
            // Re-verify against the CAPTURED bytes, immediately before the
            // wrapper is generated, not only at planning time.
            std::vector<SudoPhysicalLine> capturedLines = lines;
            const PlannedScopedDefaultsMutation unchanged = mutation;
            // digest of exactly the lines this wrap will suppress
            std::vector<SudoPhysicalLine> suppressed;
            for (size_t n = 0; n < unchanged.target.lineCount; ++n) {
                suppressed.push_back(capturedLines[offset + n]);
            }
            if (unchanged.proof.payloadDigest !=
                SudoDisabledWrapper{{}, {}, suppressed, 0, 0}.payloadDigest()) {
                return refuse("Подготовленный digest для обёртки '" +
                              unchanged.proof.wrapperId +
                              "' не совпадает с байтами захваченного снимка");
            }
            disableSudoEntry(lines, offset, unchanged.target.lineCount,
                             policyName_, unchanged.proof.wrapperId);
        }
        transaction.newContent = joinPhysicalLines(lines);
        transactions.push_back(std::move(transaction));
    }

    const auto fail = [&](SudoScopedDefaultsResultKind kind,
                       const std::string& message) {
        result.kind = kind;
        result.operation.message = message;
        // The state is derived from the WHOLE transaction, so a failure on a
        // later file never hides a wrapper already installed into an earlier
        // one.
        std::string compensationError;
        result.filesystemState = settleWithCompensation(
            transactions, hooks.beforeRestore, compensationError);
        if (!compensationError.empty()) {
            result.operation.diagnostics.push_back(compensationError);
        }
        return result;
    };

    for (FileTransaction& transaction : transactions) {
        std::string hookError;
        if (!invokeHook(hooks.beforeWrite, transaction.path, hookError)) {
            return fail(SudoScopedDefaultsResultKind::Failed,
                        "инжектированная ошибка записи " +
                            transaction.path.string() + ": " + hookError);
        }
        AtomicWriteOptions options;
        options.rejectSymlink = true;
        options.expectedTargetState = transaction.captured;
        AtomicWriteResult writeResult;
        std::string writeError;
        if (!AtomicFileWriter::writeWithResult(
                transaction.path.string(), transaction.newContent, options,
                &writeError, &writeResult)) {
            if (writeResult.preconditionFailed) {
                // The file changed after our snapshot: FIC must not overwrite
                // foreign content. Any wrapper installed earlier is still real
                // and must be compensated, so this goes through fail().
                return fail(SudoScopedDefaultsResultKind::Conflict,
                            "Sudoers-файл изменён после чтения: " +
                                transaction.path.string());
            }
            if (writeResult.installed) {
                transaction.installed = writeResult.installedTargetState;
            }
            // Even a write that failed BEFORE installing anything must not
            // report "no mutation" while an earlier file holds a wrapper.
            return fail(SudoScopedDefaultsResultKind::Failed,
                        "Не удалось записать " + transaction.path.string() +
                            ": " + writeError);
        }
        transaction.installed = writeResult.installedTargetState;
        if (!writeResult.durabilityConfirmed) {
            return fail(SudoScopedDefaultsResultKind::Failed,
                        "Не удалось подтвердить долговечность записи " +
                            transaction.path.string());
        }
        if (hooks.validate) {
            std::string validationError;
            if (!hooks.validate(validationError)) {
                return fail(SudoScopedDefaultsResultKind::Failed,
                            "Конфигурация не прошла visudo после изменения " +
                                transaction.path.string() + ": " +
                                validationError);
            }
        }
    }

    // Semantic postcondition over the RELOADED graph.
    if (hooks.reloadAndVerify) {
        std::string reloadError;
        if (!hooks.reloadAndVerify(reloadError)) {
            return fail(SudoScopedDefaultsResultKind::Failed, reloadError);
        }
    }

    result.kind = SudoScopedDefaultsResultKind::Success;
    result.operation.ok = true;
    result.operation.changed = true;
    result.operation.message =
        "Активные контекстные Defaults временно отключены (" +
        std::to_string(fresh.size()) + " новых обёрток)";
    result.filesystemState =
        SudoScopedDefaultsFilesystemState::TargetInstalled;
    return result;
}

SudoScopedDefaultsTransactionResult ScopedDefaultsTransaction::release(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    const SudoScopedDefaultsHooks& hooks) {
    SudoScopedDefaultsTransactionResult result;
    result.filesystemState = SudoScopedDefaultsFilesystemState::Unchanged;
    std::string error;

    // Every early return below precedes the first write.
    const auto refuse = [&](const std::string& message) {
        result.kind = SudoScopedDefaultsResultKind::Conflict;
        result.operation.conflict = true;
        result.operation.message = message;
        result.filesystemState = SudoScopedDefaultsFilesystemState::Unchanged;
        return result;
    };

    std::vector<OwnedWrapper> inventory;
    if (!globalInventory(inventory, error)) {
        return refuse(error);
    }

    // FULL capture-first: EVERY current graph document AND every journal proof
    // path is captured, and the global inventory is rebuilt from exactly those
    // captures. Deriving the capture set from an OLD wrapper inventory would miss
    // a file that only now acquired a wrapper -- precisely how a duplicate id
    // could survive a rollback unnoticed.
    if (hooks.beforeCapture) {
        hooks.beforeCapture();
    }
    ScopedDefaultsCapturedState captured;
    if (!captureProofAndGraphState(proofs, captured, error)) {
        return refuse(error);
    }
    std::map<std::filesystem::path, std::vector<SudoDisabledWrapper>> byPath;
    std::map<std::filesystem::path, AtomicTargetState> capturedByPath;
    {
        std::map<std::string, std::filesystem::path> idOwner;
        for (const CapturedSudoersDocument& document : captured.documents) {
            const std::string canonical =
                canonicalizeSudoProofPath(document.path);
            const std::vector<SudoPhysicalLine> lines =
                linesOf(document.state.content);
            std::vector<SudoDisabledWrapper> parsed;
            std::string parseError;
            if (parseSudoDisabledWrappers(lines, parsed, parseError) !=
                SudoWrapperParseStatus::Ok) {
                return refuse("Не удалось разобрать FIC-маркеры " +
                              canonical + ": " + parseError);
            }
            for (const SudoDisabledWrapper& wrapper : parsed) {
                if (wrapper.policy != policyName_) {
                    continue;
                }
                // One id authorizes exactly ONE physical wrapper, globally.
                const auto seen = idOwner.find(wrapper.mutationId);
                if (seen != idOwner.end() && seen->second != canonical) {
                    return refuse(
                        "wrapper id '" + wrapper.mutationId +
                        "' встречается в двух sudoers-файлах (" +
                        seen->second.string() + " и " + canonical +
                        "); глобальная уникальность не доказана");
                }
                idOwner.emplace(wrapper.mutationId, canonical);
                byPath[document.path].push_back(wrapper);
            }
            capturedByPath.emplace(document.path, document.state);
        }
    }
    if (byPath.empty()) {
        // "Wrappers are gone" is an OBSERVATION, not a durable outcome: an
        // interrupted unwrap may have published the disappearance without a
        // completed directory fsync.
        // byPath.empty() is NOT evidence on its own: prove FullyReleased on
        // the SAME capture that produced the empty inventory, then confirm the
        // durability of exactly that capture.
        const ScopedDefaultsStateProof released = proveCapturedState(
            proofs, captured, ScopedDefaultsProofMode::FullyReleased, false);
        if (!released.ok) {
            return refuse("отсутствие обёрток не доказано: " + released.message);
        }
        std::string durabilityError;
        if (!proveCapturedStateDurable(released.captured, durabilityError)) {
            return refuse("отсутствие обёрток не подтверждено durable: " +
                          durabilityError);
        }
        result.kind = SudoScopedDefaultsResultKind::Success;
        result.operation.ok = true;
        result.operation.targetMissing = true;
        result.operation.message = "Обёртки FIC_SUDO_DISABLED политики '" +
            policyName_ + "' отсутствуют: владение уже освобождено";
        return result;
    }

    // Provenance is verified for EVERY file BEFORE the first write, so an
    // unknown id or a drifted payload anywhere in the graph means zero writes.
    for (const auto& [path, wrappers] : byPath) {
        const SudoWrapperProvenanceCheck check =
            checkSudoWrapperProvenance(wrappers, path, policyName_, proofs);
        if (!check.safeToRelease()) {
            return refuse(describeSudoWrapperProvenance(check, policyName_));
        }
    }

    std::vector<FileTransaction> transactions;
    for (const auto& [path, wrappers] : byPath) {
        FileTransaction transaction;
        transaction.path = path;
        // Reuse the inventory capture: one snapshot generation for reasoning
        // AND for the CAS precondition.
        transaction.captured = capturedByPath.at(path);
        std::vector<SudoPhysicalLine> lines = linesOf(transaction.captured.content);
        bool changed = false;
        std::string restoreError;
        if (!restoreSudoDisabledEntries(lines, path, policyName_, proofs, changed,
                                        restoreError)) {
            return refuse(restoreError);
        }
        if (!changed) {
            continue;
        }
        transaction.newContent = joinPhysicalLines(lines);
        transactions.push_back(std::move(transaction));
    }
    if (transactions.empty()) {
        result.kind = SudoScopedDefaultsResultKind::Success;
        result.operation.ok = true;
        result.operation.targetMissing = true;
        result.operation.message = "Обёртки FIC_SUDO_DISABLED политики '" +
            policyName_ + "' отсутствуют: владение уже освобождено";
        return result;
    }

    // A partial release must never be reported as a completed rollback: if one
    // wrapper is already unwrapped while another is not, and compensation
    // cannot restore the first, the journal record MUST stay active.
    const auto fail = [&](SudoScopedDefaultsResultKind kind,
                          const std::string& message) {
        result.kind = kind;
        result.operation.message = message;
        std::string compensationError;
        result.filesystemState = settleWithCompensation(
            transactions, hooks.beforeRestore, compensationError);
        if (!compensationError.empty()) {
            result.operation.diagnostics.push_back(compensationError);
        }
        return result;
    };

    for (FileTransaction& transaction : transactions) {
        std::string hookError;
        if (!invokeHook(hooks.beforeWrite, transaction.path, hookError)) {
            return fail(SudoScopedDefaultsResultKind::Failed,
                        "инжектированная ошибка записи " +
                            transaction.path.string() + ": " + hookError);
        }
        AtomicWriteOptions options;
        options.rejectSymlink = true;
        options.expectedTargetState = transaction.captured;
        AtomicWriteResult writeResult;
        std::string writeError;
        if (!AtomicFileWriter::writeWithResult(
                transaction.path.string(), transaction.newContent, options,
                &writeError, &writeResult)) {
            if (writeResult.preconditionFailed) {
                return fail(SudoScopedDefaultsResultKind::Conflict,
                            "Sudoers-файл изменён после чтения: " +
                                transaction.path.string());
            }
            if (writeResult.installed) {
                transaction.installed = writeResult.installedTargetState;
            }
            return fail(SudoScopedDefaultsResultKind::Failed,
                        "Не удалось восстановить " + transaction.path.string() +
                            ": " + writeError);
        }
        transaction.installed = writeResult.installedTargetState;
        bool valid = writeResult.durabilityConfirmed;
        if (valid && hooks.validate) {
            std::string validationError;
            valid = hooks.validate(validationError);
            if (!valid) {
                result.operation.diagnostics.push_back(validationError);
            }
        }
        if (!valid) {
            return fail(SudoScopedDefaultsResultKind::Failed,
                        "Восстановление не подтверждено для " +
                            transaction.path.string());
        }
    }

    // The released state must be DURABLE before the rollback may be reported as
    // successful: an unwrap published by a rename whose directory fsync never
    // completed must not be mistaken for a finished rollback.
    std::vector<std::filesystem::path> releasedPaths;
    for (const FileTransaction& item : transactions) {
        releasedPaths.push_back(item.path);
    }
    for (const SudoScopedDefaultsWrapperProof& proof : proofs) {
        bool covered = false;
        for (const FileTransaction& item : transactions) {
            if (item.path.string() == proof.canonicalPath) {
                covered = true;
                break;
            }
        }
        if (!covered) {
            releasedPaths.emplace_back(proof.canonicalPath);
        }
    }
    // FullyReleased on a NEW post-write capture, then durability of THAT
    // capture. A writer that restored a wrapper after the unwrap fails here, so
    // Success never rests on a state different from the released one.
    ScopedDefaultsCapturedState postWrite;
    std::string postError;
    if (!captureProofAndGraphState(proofs, postWrite, postError)) {
        return fail(SudoScopedDefaultsResultKind::Failed,
                    "не удалось захватить released-состояние: " + postError);
    }
    const ScopedDefaultsStateProof released = proveCapturedState(
        proofs, postWrite, ScopedDefaultsProofMode::FullyReleased, false);
    if (!released.ok) {
        return fail(SudoScopedDefaultsResultKind::Failed,
                    "released-состояние не доказано: " + released.message);
    }
    std::string durabilityError;
    if (!proveCapturedStateDurable(released.captured, durabilityError)) {
        return fail(SudoScopedDefaultsResultKind::Failed,
                    "восстановленное состояние не подтверждено durable: " +
                        durabilityError);
    }

    result.kind = SudoScopedDefaultsResultKind::Success;
    result.operation.ok = true;
    result.operation.changed = true;
    result.operation.message = "Контекстные Defaults восстановлены в " +
        std::to_string(transactions.size()) + " файлах";
    return result;
}

bool ScopedDefaultsTransaction::compensateToPrevious(
    const std::vector<SudoScopedDefaultsWrapperProof>& previousProofs,
    const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
    const SudoScopedDefaultsHooks& hooks,
    SudoScopedDefaultsFilesystemState& state,
    std::string& error) const {
    state = SudoScopedDefaultsFilesystemState::Unchanged;

    // Only wrappers that belong to TARGET but not to PREVIOUS are removed; the
    // already-owned ones are never touched.
    std::map<std::string, std::string> previousIds;
    for (const SudoScopedDefaultsWrapperProof& proof : previousProofs) {
        previousIds.emplace(proof.wrapperId, proof.payloadDigest);
    }
    std::vector<SudoScopedDefaultsWrapperProof> targetOnly;
    for (const SudoScopedDefaultsWrapperProof& proof : targetProofs) {
        if (previousIds.find(proof.wrapperId) == previousIds.end()) {
            targetOnly.push_back(proof);
        }
    }
    if (targetOnly.empty()) {
        // Nothing target-only exists; the only sane reason to be here is that a
        // previous wrapper vanished, which cannot be repaired by unwrapping.
        error = "частичное состояние Prepared невозможно компенсировать: "
                "отсутствуют целевые обёртки, но состояние не совпадает с previous";
        return false;
    }

    std::vector<OwnedWrapper> inventory;
    if (!globalInventory(inventory, error)) {
        return false;
    }
    std::map<std::filesystem::path, std::vector<SudoDisabledWrapper>> byPath;
    for (const OwnedWrapper& owned : inventory) {
        if (owned.wrapper.policy == policyName_) {
            byPath[owned.path].push_back(owned.wrapper);
        }
    }

    std::vector<FileTransaction> transactions;
    for (const auto& [path, wrappers] : byPath) {
        FileTransaction transaction;
        transaction.path = path;
        if (!AtomicFileWriter::captureTargetState(
                path.string(), transaction.captured, &error)) {
            return false;
        }
        std::vector<SudoPhysicalLine> lines = linesOf(transaction.captured.content);
        bool changed = false;
        std::string restoreError;
        // Selective rewind: the ENTIRE current state is proven against the full
        // TARGET proof set, and only target-only wrappers are unwrapped. The
        // previous wrappers are left untouched, so a partial refresh can really
        // be rewound instead of failing closed forever.
        std::vector<std::string> targetOnlyIds;
        for (const SudoScopedDefaultsWrapperProof& proof : targetOnly) {
            targetOnlyIds.push_back(proof.wrapperId);
        }
        if (!restoreSelectedSudoDisabledEntries(lines, path, policyName_, targetProofs,
                                                 targetOnlyIds, changed,
                                                 restoreError)) {
            error = restoreError;
            return false;
        }
        if (!changed) {
            continue;
        }
        transaction.newContent = joinPhysicalLines(lines);
        transactions.push_back(std::move(transaction));
    }
    if (transactions.empty()) {
        return false;
    }

    for (FileTransaction& transaction : transactions) {
        std::string hookError;
        if (!invokeHook(hooks.beforeWrite, transaction.path, hookError)) {
            state = SudoScopedDefaultsFilesystemState::PartialOrUnknown;
            error = "компенсация частичного Prepared прервана для " +
                    transaction.path.string() + ": " + hookError;
            return false;
        }
        AtomicWriteOptions options;
        options.rejectSymlink = true;
        options.expectedTargetState = transaction.captured;
        AtomicWriteResult writeResult;
        std::string writeError;
        if (!AtomicFileWriter::writeWithResult(
                transaction.path.string(), transaction.newContent, options,
                &writeError, &writeResult)) {
            state = SudoScopedDefaultsFilesystemState::PartialOrUnknown;
            error = "компенсация частичного Prepared не удалась для " +
                    transaction.path.string() + ": " + writeError;
            return false;
        }
        transaction.installed = writeResult.installedTargetState;
    }
    // `writeWithResult() == true` is NOT durability. When the directory fsync
    // was not confirmed, retry the barrier against the exact state FIC just
    // installed; a still-failing barrier leaves the transition unproven.
    for (FileTransaction& item : transactions) {
        if (!item.installed.has_value()) {
            continue;
        }
        std::string durabilityError;
        if (AtomicFileWriter::ensureTargetDurableIfCurrentState(
                item.path.string(), *item.installed, &durabilityError)) {
            continue;
        }
        state = SudoScopedDefaultsFilesystemState::PartialOrUnknown;
        error += "компенсация не подтверждена durable для " + item.path.string() +
                 ": " + durabilityError + "; ";
        return false;
    }
    // Compensated means the exact PREVIOUS side is now durably on disk.
    state = SudoScopedDefaultsFilesystemState::Compensated;
    return true;
}

PreparedRecovery ScopedDefaultsTransaction::classifyPrepared(
    const std::vector<SudoScopedDefaultsWrapperProof>& previousProofs,
    const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
    std::string& error) const {
    std::vector<OwnedWrapper> inventory;
    if (!globalInventory(inventory, error)) {
        return PreparedRecovery::Indeterminate;
    }
    std::vector<SudoDisabledWrapper> wrappers;
    for (const OwnedWrapper& owned : inventory) {
        if (owned.wrapper.policy == policyName_) {
            wrappers.push_back(owned.wrapper);
        }
    }
    // Both sides are compared by EXACT wrapper identity + payload digest. A
    // state matching neither side (or only partially) is ambiguous and is
    // never guessed.
    const auto matchesExactly = [&wrappers](
            const std::vector<SudoScopedDefaultsWrapperProof>& expected) {
        std::map<std::string, std::string> expectedById;
        for (const SudoScopedDefaultsWrapperProof& proof : expected) {
            expectedById[proof.wrapperId] = proof.payloadDigest;
        }
        std::map<std::string, std::string> actualById;
        for (const SudoDisabledWrapper& wrapper : wrappers) {
            actualById[wrapper.mutationId] = wrapper.payloadDigest();
        }
        return expectedById == actualById;
    };
    if (matchesExactly(targetProofs)) {
        return PreparedRecovery::CompleteTarget;
    }
    if (matchesExactly(previousProofs)) {
        return PreparedRecovery::CompletePrevious;
    }
    return PreparedRecovery::Indeterminate;
}

} // namespace fic::sudoers