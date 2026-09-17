#include "modules/net/ssh/SshRollback.h"

#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshConfigTransaction.h"
#include "modules/net/ssh/SshManagedBlock.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
#include <utility>

namespace {

SshRuntime makeRuntime(const SshRollbackOptions& options) {
    SshRuntimeOptions runtimeOptions;
    runtimeOptions.configPath = options.configPath;
    runtimeOptions.includeBasePath = options.includeBasePath;
    runtimeOptions.serviceUnits = options.serviceUnits;
    return SshRuntime(runtimeOptions, *options.executables, options.runner);
}

SshConfigTransactionHooks makeHooks(const SshRollbackOptions& options) {
    SshConfigTransactionHooks hooks;
    hooks.beforeWrite = options.beforeWrite;
    hooks.beforeRestore = options.beforeRestore;
    return hooks;
}

} // namespace

SshRestoreOutcome restoreSshConfigContentIfCurrentState(
    const std::filesystem::path& path,
    const std::string& content,
    const AtomicTargetState& expectedTargetState,
    std::string& error) {
    // Conditional restore: the replacement happens only when the target is
    // still exactly the state FIC proved to install (expectedTargetState —
    // the state captured at rename time, never a fresh capture, which could
    // silently legitimize an external modification made after the FIC write).
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::PreserveExisting;
    options.expectedTargetState = expectedTargetState;
    SshRestoreOutcome outcome;
    AtomicWriteResult result;
    if (!AtomicFileWriter::writeWithResult(
            path.string(), content, options, &error, &result)) {
        if (result.installed) {
            // The replacement itself succeeded (rename published the target);
            // only a later durability step (directory fsync) failed.
            outcome.installed = true;
            outcome.durable = false;
            outcome.installedState = result.installedTargetState;
            return outcome;
        }
        if (result.preconditionFailed) {
            outcome.preconditionFailed = true;
            error = "Файл изменился после FIC-записи; восстановление отменено, "
                    "внешнее содержимое сохранено: " + error;
        }
        return outcome;
    }
    outcome.installed = true;
    outcome.durable = result.durabilityConfirmed;
    outcome.installedState = result.installedTargetState;
    return outcome;
}

bool ensureSshConfigDurableIfCurrentState(
    const std::filesystem::path& path,
    const AtomicTargetState& installedState,
    std::string& error) {
    // Re-prove ownership before the barrier: the durability confirmation
    // applies to the exact FIC-installed state, never to whatever happens to
    // occupy the path now (an external replacement must not be fsynced into
    // legitimacy).
    if (!AtomicFileWriter::targetStateMatches(path.string(), installedState,
                                              &error)) {
        error = "Текущее состояние sshd_config не соответствует "
                "FIC-installed state; durability не подтверждается: " + error;
        return false;
    }
    if (!AtomicFileWriter::ensureTargetDurable(path.string(), &error)) {
        error = "Durability-барьер sshd_config не выполнен: " + error;
        return false;
    }
    return true;
}

SshRollbackResult undoSshManagedPolicyMutation(
    const SshRollbackOptions& options,
    const fic::rollback::UndoRemoveSshManagedPolicy& undo) {
    SshRollbackResult result;
    if (options.executables == nullptr || options.configPath.empty() ||
        undo.policyName.empty() || undo.directive.empty() ||
        undo.appliedValue.empty()) {
        result.message = "SSH rollback backend настроен неполно или undo payload "
                         "повреждён";
        return result;
    }

    SshConfigFileHandler handler(options.configPath.string());
    if (!handler.loadConfig()) {
        // Malformed FIC markers are a drifted FIC ownership state: classify
        // as a conflict, never as a transient error.
        result.conflict = handler.lastLoadMarkerMalformed();
        result.message = "Не удалось проанализировать " +
                         options.configPath.string() +
                         " (в том числе структуру FIC-маркеров)";
        return result;
    }

    SshManagedModel model;
    std::string modelError;
    const SshManagedParseStatus status = parseSshManagedModel(
        handler.lines(), model, modelError);
    if (status != SshManagedParseStatus::Ok) {
        result.conflict = true;
        result.message = "Структура FIC-маркеров sshd_config повреждена "
                         "(файл не изменён): " + modelError;
        return result;
    }

    const std::string expectedDirectiveLine =
        sshManagedDirectiveLine(undo.directive, undo.appliedValue);
    bool blockOwned = false;
    const bool blockPresent = sshManagedModelHasPolicy(model, undo.policyName);
    if (blockPresent) {
        for (const SshManagedPolicyBlock& block : model.policies) {
            if (block.name == undo.policyName) {
                blockOwned =
                    block.directiveLine == expectedDirectiveLine;
                break;
            }
        }
    }
    const bool wrappersPresent =
        sshManagedModelHasDisabledForPolicy(model, undo.policyName);

    // Ownership-release provenance check (subset semantics): every wrapper
    // that still exists in the file must be proven by the journal payload;
    // payload ids whose wrappers have already disappeared are treated as
    // released and are not an error. A corrupted payload is refused
    // unconditionally; the existing-wrapper proof is required whenever any
    // FIC-owned state of the policy remains in the file (the neither-block-
    // nor-wrapper case below is the already-rolled-back / never-applied /
    // externally cleaned recovery state).
    const SshDisabledProvenanceCheck provenance = checkSshDisabledProvenance(
        model, undo.policyName, undo.disabledMutationIds);
    if (provenance.payloadMalformed) {
        result.conflict = true;
        result.message = "Journal payload политики '" + undo.policyName +
                         "' повреждён (дублирующийся mutation id); владение "
                         "не может быть доказано (файл не изменён)";
        return result;
    }
    if (blockPresent || wrappersPresent) {
        if (!provenance.safeToRelease()) {
            result.conflict = true;
            result.message =
                describeSshDisabledProvenance(provenance, undo.policyName) +
                "; владение не может быть доказано (файл не изменён)";
            return result;
        }
    }

    if (!blockPresent && !wrappersPresent) {
        // Nothing FIC-owned remains for this policy: the mutation was never
        // applied or already factually rolled back (e.g. crash after the
        // file write but before the journal update). The runtime must still
        // be reconciled before the journal record is resolved.
        result.nothingToDo = true;
        SshRuntime runtime = makeRuntime(options);
        std::string validationError;
        if (!runtime.validateConfiguration(validationError)) {
            result.nothingToDo = false;
            result.message = "FIC не владеет состоянием политики '" +
                             undo.policyName +
                             "', но sshd -T не принимает текущую "
                             "конфигурацию; откат не подтверждён: " +
                             validationError;
            return result;
        }
        if (!handler.loadSnapshot().has_value()) {
            result.nothingToDo = false;
            result.message = "in-memory snapshot sshd_config недоступен; "
                             "durability не может быть привязана к "
                             "состоянию отката";
            return result;
        }
        std::string barrierError;
        if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                options.configPath.string(), *handler.loadSnapshot(),
                &barrierError)) {
            result.nothingToDo = false;
            result.message = "Durability состояния sshd_config не "
                             "подтверждена; откат не подтверждён: " +
                             barrierError;
            return result;
        }
        const SshActivationResult activation = runtime.activateIfRunning();
        if (!activation.ok) {
            result.nothingToDo = false;
            result.message = "Откат уже выполнен в sshd_config, но "
                             "перезагрузка SSH-сервиса не удалась: " +
                             activation.message;
            return result;
        }
        result.message = "FIC не владеет состоянием политики '" +
                         undo.policyName + "'; откат не требуется";
        return result;
    }
    // Wrapper provenance was already proven above (subset semantics: every
    // existing wrapper id is in the payload; payload ids whose wrappers have
    // disappeared are already released): the transaction below may restore
    // exactly the wrappers that still exist and nothing else.
    if (blockPresent && !blockOwned) {
        // The managed sub-block exists but its directive line does not match
        // the recorded applied value: the block was manually edited and FIC
        // refuses to overwrite user content by guesswork.
        result.conflict = true;
        result.message = "Содержимое FIC policy-блока '" + undo.policyName +
                         "' изменено вручную; владение не может быть "
                         "доказано (файл не изменён)";
        return result;
    }

    // Build the rollback edits in memory: remove the policy sub-block and
    // restore only the disabled lines this mutation owns. Other policies'
    // sub-blocks and wrappers are untouched.
    const SshConfigTransactionHooks hooks = makeHooks(options);
    SshRuntime runtime = makeRuntime(options);

    SshConfigTransactionResult transaction = runSshConfigTransaction(
        handler, runtime, hooks,
        [&handler, &undo, &expectedDirectiveLine](std::string& error) {
            bool removed = false;
            if (!removeSshManagedPolicyBlock(handler.lines(), undo.policyName,
                                             expectedDirectiveLine, removed,
                                             error)) {
                return false;
            }
            bool restored = false;
            if (!restoreSshDisabledLines(handler.lines(), undo.policyName,
                                         undo.disabledMutationIds, restored,
                                         error)) {
                return false;
            }
            return true;
        },
        // Rollback postcondition: the restored configuration must be
        // accepted by sshd (-t/-T). No policy value is expected here.
        [](std::string&) { return true; },
        "FIC-владение политикой '" + undo.policyName +
            "' в sshd_config отозвано");

    result.ok = transaction.ok;
    result.conflict = transaction.conflict;
    result.message = transaction.message;
    return result;
}
