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

std::string ScopedDefaultsTransaction::noopPreflight(
    const std::vector<SudoScopedDefaultsWrapperProof>& activeProofs) const {
    std::string error;
    std::vector<OwnedWrapper> inventory;
    // Malformed FIC markers anywhere in the graph fail closed before any
    // ownership reasoning.
    if (!globalInventory(inventory, error)) {
        return error;
    }
    if (!targets().empty()) {
        return "активные контекстные Defaults всё ещё присутствуют";
    }
    std::vector<SudoDisabledWrapper> wrappers;
    wrappers.reserve(inventory.size());
    for (const OwnedWrapper& owned : inventory) {
        wrappers.push_back(owned.wrapper);
    }
    // Every FIC wrapper of this policy must be proven by the ACTIVE journal
    // ownership set; an orphan is never adopted here.
    const SudoWrapperProvenanceCheck check =
        checkSudoWrapperProvenance(wrappers, policyName_, activeProofs);
    if (!check.safeToRelease()) {
        return describeSudoWrapperProvenance(check, policyName_);
    }
    return {};
}

std::vector<SudoScopedDefaultsWrapperProof>
ScopedDefaultsTransaction::planRefresh(
    const std::vector<SudoScopedDefaultsWrapperProof>& owned) const {
    std::vector<SudoScopedDefaultsWrapperProof> proofs = owned;
    const std::vector<SudoersConfiguration::GraphDocument> documents =
        configuration_.graphDocuments();
    const std::vector<ScopedDefaultsTarget> physical = targets();
    for (size_t index = 0; index < physical.size(); ++index) {
        SudoScopedDefaultsWrapperProof proof;
        proof.wrapperId = generateSudoWrapperMutationId(static_cast<int>(index));
        proof.payloadDigest = suppressedDigest(documents, physical[index]);
        proofs.push_back(std::move(proof));
    }
    return proofs;
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
bool compensateFiles(std::vector<FileTransaction>& transactions,
                     const std::function<void(const std::filesystem::path&)>& hook,
                     std::string& error) {
    bool allRestored = true;
    for (auto item = transactions.rbegin(); item != transactions.rend(); ++item) {
        if (!item->installed.has_value()) {
            continue;
        }
        if (hook) {
            hook(item->path);
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

} // namespace

SudoersOperationResult ScopedDefaultsTransaction::apply(
    const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
    SudoScopedDefaultsOutcome& outcome,
    const SudoScopedDefaultsHooks& hooks) {
    outcome = SudoScopedDefaultsOutcome::NoMutation;
    SudoersOperationResult result;
    std::string error;

    std::vector<OwnedWrapper> inventory;
    if (!globalInventory(inventory, error)) {
        outcome = SudoScopedDefaultsOutcome::Conflict;
        result.conflict = true;
        result.message = error;
        return result;
    }
    // A planned id must not collide with an id that already exists anywhere in
    // the graph.
    std::set<std::string> usedIds;
    for (const OwnedWrapper& owned : inventory) {
        usedIds.insert(owned.wrapper.mutationId);
    }
    const std::vector<SudoersConfiguration::GraphDocument> documents =
        configuration_.graphDocuments();

    // Each planned proof must match the suppressed bytes FIC is about to
    // suppress, computed here from the graph. This replaces any count-based
    // agreement: a mismatched plan fails closed before the first write.
    const std::vector<ScopedDefaultsTarget> physical = targets();
    if (physical.empty()) {
        result.ok = true;
        result.message = "Активных контекстных Defaults не обнаружено";
        return result;
    }
    if (targetProofs.size() != physical.size()) {
        outcome = SudoScopedDefaultsOutcome::Conflict;
        result.conflict = true;
        result.message = "Число новых обёрток (" +
            std::to_string(targetProofs.size()) + ") не совпадает с числом "
            "физических целей (" + std::to_string(physical.size()) + ")";
        return result;
    }
    for (size_t index = 0; index < physical.size(); ++index) {
        const SudoScopedDefaultsWrapperProof& proof = targetProofs[index];
        if (!isCanonicalSudoWrapperId(proof.wrapperId) ||
            !fic::core::ContentDigest::isCanonicalSha256Hex(
                proof.payloadDigest)) {
            outcome = SudoScopedDefaultsOutcome::Conflict;
            result.conflict = true;
            result.message = "Некорректная provenance новой обёртки";
            return result;
        }
        if (!usedIds.insert(proof.wrapperId).second) {
            outcome = SudoScopedDefaultsOutcome::Conflict;
            result.conflict = true;
            result.message = "wrapper id '" + proof.wrapperId +
                "' уже используется другим FIC_SUDO_DISABLED блоком";
            return result;
        }
        // The digest must equal the digest of the exact bytes that will be
        // suppressed, otherwise the record would prove content FIC never wrote.
        if (proof.payloadDigest != suppressedDigest(documents, physical[index])) {
            outcome = SudoScopedDefaultsOutcome::Conflict;
            result.conflict = true;
            result.message = "Подготовленный digest для обёртки '" +
                proof.wrapperId + "' не совпадает с подавляемыми байтами";
            return result;
        }
    }

    // Per-file plan: bottom-up wrapping so each wrap never shifts the line
    // indices of the entries still to be handled.
    std::map<std::filesystem::path,
             std::vector<const ScopedDefaultsTarget*>> perDocument;
    for (const ScopedDefaultsTarget& target : physical) {
        perDocument[target.path].push_back(&target);
    }

    std::vector<FileTransaction> transactions;
    size_t proofCursor = targetProofs.size() - physical.size();
    for (auto& entry : perDocument) {
        FileTransaction transaction;
        transaction.path = entry.first;
        // State-bound precondition: capture the exact target state now.
        if (!AtomicFileWriter::captureTargetState(
                entry.first.string(), transaction.captured, &error)) {
            outcome = SudoScopedDefaultsOutcome::Conflict;
            result.conflict = true;
            result.message = "Не удалось зафиксировать состояние sudoers-файла " +
                entry.first.string() + ": " + error;
            return result;
        }
        std::vector<SudoPhysicalLine> lines = linesOf(transaction.captured.content);
        std::sort(entry.second.begin(), entry.second.end(),
                  [](const ScopedDefaultsTarget* left,
                     const ScopedDefaultsTarget* right) {
                      return left->firstLine > right->firstLine;
                  });
        for (const ScopedDefaultsTarget* target : entry.second) {
            const std::size_t offset = lineOffset(lines, target->firstLine);
            if (offset + target->lineCount > lines.size()) {
                outcome = SudoScopedDefaultsOutcome::Conflict;
                result.conflict = true;
                result.message = "Диапазон строк вышел за пределы файла " +
                    entry.first.string();
                return result;
            }
            disableSudoEntry(lines, offset, target->lineCount, policyName_,
                             targetProofs[proofCursor++].wrapperId);
        }
        transaction.newContent = joinPhysicalLines(lines);
        transactions.push_back(std::move(transaction));
    }

    const auto fail = [&](const std::string& message) {
        result.message = message;
        std::string compensationError;
        if (compensateFiles(transactions, hooks.beforeRestore,
                            compensationError)) {
            outcome = SudoScopedDefaultsOutcome::MutatedAndCompensated;
        } else {
            outcome = SudoScopedDefaultsOutcome::MutatedAndStillPresent;
        }
        if (!compensationError.empty()) {
            result.diagnostics.push_back(compensationError);
        }
        return result;
    };

    for (FileTransaction& transaction : transactions) {
        if (hooks.beforeWrite) {
            hooks.beforeWrite(transaction.path);
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
                // Someone else changed the file after our snapshot: FIC must
                // not overwrite foreign content.
                outcome = SudoScopedDefaultsOutcome::Conflict;
                result.conflict = true;
                result.message = "Sudoers-файл изменён после чтения: " +
                    transaction.path.string();
                return result;
            }
            if (writeResult.installed) {
                transaction.installed = writeResult.installedTargetState;
                return fail("Не удалось записать " + transaction.path.string() +
                            ": " + writeError);
            }
            outcome = SudoScopedDefaultsOutcome::NoMutation;
            result.message = "Не удалось записать " + transaction.path.string() +
                ": " + writeError;
            return result;
        }
        transaction.installed = writeResult.installedTargetState;
        if (!writeResult.durabilityConfirmed) {
            return fail("Не удалось подтвердить долговечность записи " +
                        transaction.path.string());
        }
        if (hooks.validate) {
            std::string validationError;
            if (!hooks.validate(validationError)) {
                return fail("Конфигурация не прошла visudo после изменения " +
                            transaction.path.string() + ": " + validationError);
            }
        }
    }

    // Semantic postcondition over the RELOADED graph.
    if (hooks.reloadAndVerify) {
        std::string reloadError;
        if (!hooks.reloadAndVerify(reloadError)) {
            return fail(reloadError);
        }
    }

    outcome = SudoScopedDefaultsOutcome::Success;
    result.ok = true;
    result.changed = true;
    result.message = "Активные контекстные Defaults временно отключены (" +
        std::to_string(physical.size()) + " новых обёрток)";
    return result;
}

SudoersOperationResult ScopedDefaultsTransaction::release(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    SudoScopedDefaultsOutcome& outcome,
    const SudoScopedDefaultsHooks& hooks) {
    outcome = SudoScopedDefaultsOutcome::NoMutation;
    SudoersOperationResult result;
    std::string error;

    std::vector<OwnedWrapper> inventory;
    if (!globalInventory(inventory, error)) {
        outcome = SudoScopedDefaultsOutcome::Conflict;
        result.conflict = true;
        result.message = error;
        return result;
    }

    std::map<std::filesystem::path, std::vector<SudoDisabledWrapper>> byPath;
    for (const OwnedWrapper& owned : inventory) {
        if (owned.wrapper.policy == policyName_) {
            byPath[owned.path].push_back(owned.wrapper);
        }
    }
    if (byPath.empty()) {
        result.ok = true;
        result.targetMissing = true;
        result.message = "Обёртки FIC_SUDO_DISABLED политики '" + policyName_ +
            "' отсутствуют: владение уже освобождено";
        return result;
    }

    // Provenance is verified for EVERY file BEFORE the first write, so an
    // unknown id or a drifted payload anywhere in the graph means zero writes.
    for (const auto& [path, wrappers] : byPath) {
        (void)path;
        const SudoWrapperProvenanceCheck check =
            checkSudoWrapperProvenance(wrappers, policyName_, proofs);
        if (!check.safeToRelease()) {
            outcome = SudoScopedDefaultsOutcome::Conflict;
            result.conflict = true;
            result.message = describeSudoWrapperProvenance(check, policyName_);
            return result;
        }
    }

    std::vector<FileTransaction> transactions;
    for (const auto& [path, wrappers] : byPath) {
        FileTransaction transaction;
        transaction.path = path;
        if (!AtomicFileWriter::captureTargetState(
                path.string(), transaction.captured, &error)) {
            outcome = SudoScopedDefaultsOutcome::Conflict;
            result.conflict = true;
            result.message = "Не удалось зафиксировать состояние sudoers-файла " +
                path.string() + ": " + error;
            return result;
        }
        std::vector<SudoPhysicalLine> lines = linesOf(transaction.captured.content);
        bool changed = false;
        std::string restoreError;
        if (!restoreSudoDisabledEntries(lines, policyName_, proofs, changed,
                                        restoreError)) {
            outcome = SudoScopedDefaultsOutcome::Conflict;
            result.conflict = true;
            result.message = restoreError;
            return result;
        }
        if (!changed) {
            continue;
        }
        transaction.newContent = joinPhysicalLines(lines);
        transactions.push_back(std::move(transaction));
    }
    if (transactions.empty()) {
        result.ok = true;
        result.targetMissing = true;
        result.message = "Обёртки FIC_SUDO_DISABLED политики '" + policyName_ +
            "' отсутствуют: владение уже освобождено";
        return result;
    }

for (FileTransaction& transaction : transactions) {
        if (hooks.beforeWrite) {
            hooks.beforeWrite(transaction.path);
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
                outcome = SudoScopedDefaultsOutcome::Conflict;
                result.conflict = true;
                result.message = "Sudoers-файл изменён после чтения: " +
                    transaction.path.string();
                return result;
            }
            if (writeResult.installed) {
                transaction.installed = writeResult.installedTargetState;
            }
            result.message = "Не удалось восстановить " + transaction.path.string() +
                ": " + writeError;
            std::string compensationError;
            outcome = compensateFiles(transactions, hooks.beforeRestore,
                                     compensationError)
                ? SudoScopedDefaultsOutcome::MutatedAndCompensated
                : SudoScopedDefaultsOutcome::MutatedAndStillPresent;
            if (!compensationError.empty()) {
                result.diagnostics.push_back(compensationError);
            }
            return result;
        }
        transaction.installed = writeResult.installedTargetState;
        bool valid = writeResult.durabilityConfirmed;
        if (valid && hooks.validate) {
            std::string validationError;
            valid = hooks.validate(validationError);
            if (!valid) {
                result.diagnostics.push_back(validationError);
            }
        }
        if (!valid) {
            result.message = "Восстановление не подтверждено для " +
                transaction.path.string();
            std::string compensationError;
            outcome = compensateFiles(transactions, hooks.beforeRestore,
                                     compensationError)
                ? SudoScopedDefaultsOutcome::MutatedAndCompensated
                : SudoScopedDefaultsOutcome::MutatedAndStillPresent;
            if (!compensationError.empty()) {
                result.diagnostics.push_back(compensationError);
            }
            return result;
        }
    }

    outcome = SudoScopedDefaultsOutcome::Success;
    result.ok = true;
    result.changed = true;
    result.message = "Контекстные Defaults восстановлены в " +
        std::to_string(transactions.size()) + " файлах";
    return result;
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