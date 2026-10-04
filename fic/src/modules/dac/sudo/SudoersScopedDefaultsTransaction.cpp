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
    std::string error;
    std::vector<OwnedWrapper> inventory;
    // Malformed FIC markers anywhere in the graph fail closed before any
    // ownership reasoning.
    if (!globalInventory(inventory, error)) {
        return error;
    }
    std::vector<SudoDisabledWrapper> wrappers;
    wrappers.reserve(inventory.size());
    for (const OwnedWrapper& owned : inventory) {
        if (owned.wrapper.policy == policyName_) {
            wrappers.push_back(owned.wrapper);
        }
    }
    // Every existing wrapper of this policy must be proven by the ACTIVE journal
    // ownership set with an exact digest. An orphan is never adopted.
    std::vector<SudoScopedDefaultsWrapperProof> fileProofs;
    std::map<std::string, std::vector<SudoDisabledWrapper>> byPath;
    for (const OwnedWrapper& owned : inventory) {
        if (owned.wrapper.policy == policyName_) {
            byPath[owned.path].push_back(owned.wrapper);
        }
    }
    // Ownership is proven PER FILE against the proofs that name that exact
    // file, so one proof can never authorize a wrapper in another document.
    for (const auto& [path, fileWrappers] : byPath) {
        const SudoWrapperProvenanceCheck check = checkSudoWrapperProvenance(
            fileWrappers, path, policyName_, activeProofs);
        if (!check.safeToRelease()) {
            return describeSudoWrapperProvenance(check, policyName_);
        }
    }
    return {};
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
    const std::vector<std::filesystem::path>& paths,
    std::string& error) {
    for (const std::filesystem::path& path : paths) {
        AtomicTargetState current;
        std::string captureError;
        if (!AtomicFileWriter::captureTargetState(path.string(), current,
                                                  &captureError)) {
            // The file may have disappeared externally; that absence is only
            // provable by confirming the directory entry itself.
            std::string durabilityError;
            if (!AtomicFileWriter::fsyncParentDirectoryForPath(path.string(),
                                                                &durabilityError)) {
                error += "не удалось подтвердить durable-состояние " +
                         path.string() + ": " + captureError + "; " +
                         durabilityError + "; ";
                return false;
            }
            continue;
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

    // CAPTURE FIRST: the global inventory is rebuilt from the very same
    // captured states the writes are later CAS-bound to. Reasoning about
    // "one proof authorizes exactly one wrapper globally" on an older graph
    // snapshot while writing against a newer capture would prove nothing.
    std::map<std::filesystem::path, std::vector<SudoDisabledWrapper>> byPath;
    std::map<std::filesystem::path, AtomicTargetState> capturedByPath;
    {
        std::map<std::string, std::filesystem::path> idOwner;
        for (const OwnedWrapper& owned : inventory) {
            if (owned.wrapper.policy != policyName_) {
                continue;
            }
            const auto seen = idOwner.find(owned.wrapper.mutationId);
            if (seen != idOwner.end() &&
                seen->second != owned.path) {
                return refuse(
                    "wrapper id '" + owned.wrapper.mutationId +
                    "' встречается в двух sudoers-файлах; глобальная "
                    "уникальность не доказана");
            }
            idOwner.emplace(owned.wrapper.mutationId, owned.path);
            if (capturedByPath.count(owned.path) != 0) {
                continue;
            }
            AtomicTargetState captured;
            if (!AtomicFileWriter::captureTargetState(
                    owned.path.string(), captured, &error)) {
                return refuse("Не удалось зафиксировать состояние " +
                              owned.path.string() + ": " + error);
            }
            capturedByPath.emplace(owned.path, std::move(captured));
        }
        // One capture per distinct file; the inventory is then rebuilt from
        // exactly those captured contents (never mixed with the graph snapshot).
        for (const auto& entry : capturedByPath) {
            const std::filesystem::path& path = entry.first;
            const AtomicTargetState& captured = entry.second;
            std::vector<fic::sudoers::SudoPhysicalLine> lines =
                linesOf(captured.content);
            std::vector<SudoDisabledWrapper> parsed;
            std::string parseError;
            if (parseSudoDisabledWrappers(lines, parsed, parseError) !=
                SudoWrapperParseStatus::Ok) {
                return refuse("Не удалось разобрать FIC-маркеры " +
                              path.string() + ": " + parseError);
            }
            for (const SudoDisabledWrapper& wrapper : parsed) {
                if (wrapper.policy == policyName_) {
                    byPath[path].push_back(wrapper);
                }
            }
        }
    }
    if (byPath.empty()) {
        // "Wrappers are gone" is an OBSERVATION, not a durable outcome: an
        // interrupted unwrap may have published the disappearance without a
        // completed directory fsync.
        std::string durabilityError;
        if (!proveObservedStateDurable(proofPaths(proofs), durabilityError)) {
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
    std::string durabilityError;
    if (!proveObservedStateDurable(releasedPaths, durabilityError)) {
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