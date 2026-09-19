#include "modules/identity_access/sssd/SssdRollback.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <filesystem>
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

// Restarts the ACTIVE SSSD service unit (if any) and verifies it comes back
// active. Inactive units are skipped: FIC never activates SSSD on its own.
bool restartActiveSssd(const SssdRollbackOptions& options,
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

} // namespace

SssdRollbackResult undoSssdManagedSetting(
    const SssdRollbackOptions& options,
    const fic::rollback::UndoRemoveSssdManagedSetting& undo) {
    SssdRollbackResult result;
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
    if (!observation.optionPresent) {
        // Ownership already released (e.g. crash after source rollback):
        // nothing to change, the foreign value is already effective.
        result.ok = true;
        result.nothingToDo = true;
        result.message = "FIC-owned SSSD setting [" + undo.section + "]/" +
            undo.option + " уже отсутствует";
        return result;
    }
    if (observation.optionValue != undo.appliedValue) {
        result.conflict = true;
        result.message = "FIC-owned SSSD значение [" + undo.section + "]/" +
            undo.option + " изменилось извне ('" + observation.optionValue +
            "' вместо '" + undo.appliedValue + "'): откат отклонён "
            "(Conflict)";
        return result;
    }

    // AFTER: remove only the target option from the FIC-owned drop-in; an
    // empty drop-in is removed entirely. The foreign main configuration and
    // foreign snippets are never modified.
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

    // Restart the active SSSD service (if any) and verify the postcondition.
    if (!restartActiveSssd(options, error)) {
        result.message = "Не удалось перезапустить SSSD после отката: " +
            error;
        return result;
    }

    result.ok = true;
    result.message = "FIC-owned SSSD setting [" + undo.section + "]/" +
        undo.option + " удалён; эффективное значение: " +
        (released.effectiveValue.has_value()
             ? "'" + *released.effectiveValue + "'"
             : std::string("отсутствует"));
    return result;
}