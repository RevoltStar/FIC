#include "modules/identity_access/sssd/SssdRollback.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <filesystem>
#include <optional>
#include <utility>

namespace {

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "command timed out";
    }
    if (!result.standardError.empty()) {
        return result.standardError;
    }
    return "exit code " + std::to_string(result.exitCode);
}

} // namespace

bool reconcileSssdRuntime(
    const SssdRollbackOptions& options,
    std::string& error) {
    if (options.executables == nullptr) {
        error = "SSSD rollback runtime недоступен: resolver executables не задан";
        return false;
    }
    std::filesystem::path systemctl;
    if (!options.executables->resolve(
            fic::platform::ExecutableId::Systemctl, systemctl, error)) {
        return false;
    }
    const auto runner = options.runner
        ? options.runner
        : fic::identity::sssd::SssdCommandRunner(
              &VerifiedProcessExecutor::execute);
    ProcessOptions processOptions;
    processOptions.clearEnvironment = true;
    std::string activeUnit;
    for (const auto& unit : options.serviceUnits) {
        const auto status = runner(
            systemctl.string(), {"is-active", "--quiet", unit}, processOptions);
        if (!status.started || status.timedOut || !status.error.empty()) {
            error = "failed to inspect SSSD service " + unit + ": " +
                processFailure(status);
            return false;
        }
        if (status.success()) {
            activeUnit = unit;
            break;
        }
        if (status.exitCode != 3 && status.exitCode != 4) {
            error = "failed to inspect SSSD service " + unit + ": " +
                processFailure(status);
            return false;
        }
    }
    if (activeUnit.empty()) {
        // SSSD is inactive: nothing to restart.
        return true;
    }
    const auto restart = runner(
        systemctl.string(), {"restart", activeUnit}, processOptions);
    if (!restart.success()) {
        error = "failed to restart " + activeUnit + ": " +
            processFailure(restart);
        return false;
    }
    const auto verify = runner(
        systemctl.string(), {"is-active", "--quiet", activeUnit},
        processOptions);
    if (!verify.success()) {
        error = activeUnit + " is not active after rollback restart: " +
            processFailure(verify);
        return false;
    }
    return true;
}

SssdRollbackResult undoSssdManagedSetting(
    const SssdRollbackOptions& options,
    const fic::rollback::UndoRemoveSssdManagedSetting& undo) {
    SssdRollbackResult result;
    bool sourceAlreadyAbsent = false;
    std::optional<std::string> effectiveAfterRelease;
    fic::identity::sssd::SssdConfiguration configuration(options.configuration);

    // Classification of the CURRENT FIC-owned drop-in state. Any failure to
    // read the foreign topology fails closed without touching anything.
    fic::identity::sssd::SssdManagedSnippetObservation observation;
    std::string error;
    if (!configuration.inspectManagedSnippet(
            undo.section, undo.option, observation, error)) {
        result.message = "Не удалось проанализировать SSSD конфигурацию: " +
            error;
        return result;
    }
    using DropInState = fic::identity::sssd::SssdManagedSnippetObservation::
        DropInState;
    if (observation.optionPresent) {
        if (observation.dropInState == DropInState::Unsafe ||
            observation.dropInState == DropInState::Malformed) {
            result.conflict = true;
            result.message =
                "FIC-owned SSSD drop-in повреждён или небезопасен, откат "
                "отклонён (Conflict): " +
                options.configuration.managedSnippetFile.string();
            return result;
        }
        if (!observation.laterConflictingSnippets.empty()) {
            result.conflict = true;
            result.message = "Топология SSSD snippets конфликтует с FIC-owned "
                             "drop-in, откат отклонён (Conflict): " +
                observation.laterConflictingSnippets.front().string();
            return result;
        }
        if (observation.optionValue != undo.appliedValue) {
            result.conflict = true;
            result.message = "FIC-owned SSSD значение [" + undo.section +
                "]/" + undo.option + " изменилось извне ('" +
                observation.optionValue + "' вместо '" + undo.appliedValue +
                "'): откат отклонён (Conflict)";
            return result;
        }

        // AFTER: remove only the target option from the FIC-owned drop-in;
        // an empty drop-in is removed entirely. The foreign main
        // configuration and foreign snippets are never modified.
        auto prepared = configuration.prepareManagedSnippetRemoval(
            undo.section, undo.option);
        if (!prepared.ok()) {
            result.message = "Не удалось подготовить удаление FIC-owned SSSD "
                             "setting: " +
                prepared.error;
            return result;
        }
        if (!fic::identity::executePreparedFileChange(
                std::move(prepared.change), error)) {
            result.message =
                "Не удалось удалить FIC-owned SSSD setting: " + error;
            return result;
        }

        // Re-read the topology: the FIC-owned option must be gone.
        fic::identity::sssd::SssdManagedSnippetObservation released;
        if (!configuration.inspectManagedSnippet(
                undo.section, undo.option, released, error) ||
            released.optionPresent) {
            result.message = "Постусловие отката SSSD не выполнено: " +
                (error.empty() ? std::string("setting всё ещё присутствует")
                               : error);
            return result;
        }
        effectiveAfterRelease = released.effectiveValue;
    } else {
        // Source ownership is already released (e.g. a previous rollback
        // attempt removed the option but failed before the runtime
        // reconciliation completed). The option absence proves the source
        // undo only — the rollback lifecycle is NOT complete yet.
        sourceAlreadyAbsent = true;
    }

    // Runtime reconciliation is a MANDATORY postcondition of EVERY active
    // rollback lifecycle, including retries where the source undo already
    // happened: an active journal record means the rollback operation must
    // still prove the runtime state before it may complete. A failed
    // restart/verification keeps the record active (RollbackFailed) so the
    // next retry re-attempts the reconciliation.
    if (!reconcileSssdRuntime(options, error)) {
        result.message = "Не удалось завершить runtime-реконсиляцию SSSD "
                         "после отката: " +
            error;
        return result;
    }

    result.ok = true;
    result.nothingToDo = sourceAlreadyAbsent;
    if (sourceAlreadyAbsent) {
        result.message = "FIC-owned SSSD setting [" + undo.section + "]/" +
            undo.option + " уже отсутствует; runtime SSSD реконсиляция "
                          "завершена";
    } else {
        result.message = "FIC-owned SSSD setting [" + undo.section + "]/" +
            undo.option + " удалён; эффективное значение: " +
            (effectiveAfterRelease.has_value()
                 ? "'" + *effectiveAfterRelease + "'"
                 : std::string("отсутствует"));
    }
    return result;
}