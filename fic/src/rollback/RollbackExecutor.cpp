#include "rollback/RollbackExecutor.h"

#include <fic/core/config/ModuleConfigFileHandler.h>

#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/firewall/FirewallPolicies.h"
#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/sysctl/SysctlConfiguration.h"
#include "modules/sysctl/SysctlKey.h"
#include "modules/sysctl/SysctlRuntime.h"
#include "rollback/DaemonMutationJournal.h"

#include <algorithm>
#include <map>
#include <mutex>
#include <utility>

namespace fic::rollback {
namespace {

// Serializes concurrent sysctl/sudoers backend access with policy apply.
std::mutex& rollbackBackendMutex() {
    static std::mutex mutex;
    return mutex;
}

bool isDcCategoryFeature(const std::string& feature) {
    return feature == "block_usb_storage" ||
           feature == "block_printers_scanners" ||
           feature == "block_optical_drives";
}

bool isSupportedFirewallPolicy(const std::string& policyName) {
    return policyName == "block_rdp" ||
           policyName == "block_ftp" ||
           policyName == "custom_rules";
}

// Explicit whitelist: a future SUDO policy must never become automatically
// rollback-supported without its own journal integration and undo action.
bool isSupportedSudoPolicy(const std::string& policyName) {
    return policyName == "sudo_env_reset" ||
           policyName == "sudo_passwd_tries" ||
           policyName == "sudo_securepath" ||
           policyName == "sudo_timeout";
}

// Explicit whitelist: a future NET/SshEdit policy must never become
// automatically rollback-supported without its own journal integration and
// undo action.
bool isSupportedSshPolicy(const std::string& policyName) {
    return policyName == "ssh_port" ||
           policyName == "ssh_max_auth_tries" ||
           policyName == "ssh_root_login" ||
           policyName == "ssh_pubkey_auth";
}

MutationRollbackOutcome outcomeFromOperation(
    MutationId id,
    const std::string& resource,
    const SysctlOperationResult& operation) {
    MutationRollbackOutcome outcome;
    outcome.id = id;
    outcome.resource = resource;
    if (operation.ok && operation.conflict) {
        outcome.status = RollbackStatus::Conflict;
    } else if (operation.ok && operation.targetMissing) {
        outcome.status = RollbackStatus::NothingToDo;
    } else if (operation.ok) {
        outcome.status = RollbackStatus::Success;
    } else if (operation.conflict) {
        outcome.status = RollbackStatus::Conflict;
    } else {
        outcome.status = RollbackStatus::Failed;
    }
    outcome.message = operation.message;
    return outcome;
}

MutationRollbackOutcome undoSysctlSetting(
    const RollbackExecutorDeps& deps,
    const MutationRecord& record,
    const UndoRemoveManagedSetting& undo) {
    const std::lock_guard<std::mutex> lock(rollbackBackendMutex());

    SysctlConfigurationOptions options = deps.sysctlOptions
        ? deps.sysctlOptions()
        : SysctlConfigurationOptions{};

    SysctlConfiguration configuration(options);
    std::string error;
    if (!configuration.load(error)) {
        MutationRollbackOutcome outcome;
        outcome.id = record.id;
        outcome.resource = record.resource;
        outcome.status = RollbackStatus::Failed;
        outcome.message = "Не удалось проанализировать конфигурацию sysctl: " + error;
        return outcome;
    }

    const std::string canonical = fic::sysctl::internalKeyToCanonicalPath(undo.key);

    // Ownership is determined by the FIC managed artifact, not by the current
    // effective source: an external file may shadow the FIC entry, but the
    // entry must still be removed so it cannot become effective again later.
    const SysctlValueObservation managed =
        configuration.inspectManagedValue(undo.key);
    if (!managed.found) {
        // No FIC-owned persistent entry: an idempotent retry (or the entry
        // was already removed). Never touch any foreign configuration.
        MutationRollbackOutcome outcome;
        outcome.id = record.id;
        outcome.resource = record.resource;
        outcome.status = RollbackStatus::NothingToDo;
        outcome.message = "Managed sysctl-значение '" + undo.key +
                          "' отсутствует в managed sysctl-файле FIC";
        return outcome;
    }

    const SysctlOperationResult removal =
        configuration.removeManagedKey(undo.key, undo.appliedValue);
    MutationRollbackOutcome outcome =
        outcomeFromOperation(record.id, record.resource, removal);
    if (!removal.ok) {
        return outcome;
    }
    if (!removal.changed) {
        return outcome; // NothingToDo
    }

    // Recompute the effective persistent value after the FIC override removal
    // and move runtime sysctl to it. Never guess a default value.
    SysctlConfiguration verification(options);
    if (!verification.load(error)) {
        outcome.status = RollbackStatus::Failed;
        outcome.message = "Не удалось перечитать sysctl после удаления managed значения: " +
                          error;
        return outcome;
    }
    const SysctlValueObservation after = verification.inspect(canonical);
    if (!after.found) {
        outcome.message += ". Управляющий источник удалён; runtime-значение оставлено";
        return outcome;
    }

    SysctlRuntimeOptions runtimeOptions;
    if (!deps.sysctlRuntimeRoot.empty()) {
        runtimeOptions.root = deps.sysctlRuntimeRoot;
    }
    SysctlRuntime runtime(runtimeOptions);
    const SysctlRuntimeResult runtimeResult =
        runtime.ensureValue(canonical, after.value);
    if (!runtimeResult.ok) {
        outcome.status = RollbackStatus::Failed;
        outcome.message = "Managed значение удалено, но runtime sysctl не приведён "
                          "к значению оставшейся конфигурации: " +
                          runtimeResult.message;
        return outcome;
    }
    outcome.message += ". Runtime sysctl приведён к значению '" + after.value +
                       "' из " + after.source.path.string();
    return outcome;
}

MutationRollbackOutcome undoSudoSetting(
    const RollbackExecutorDeps& deps,
    const MutationRecord& record,
    const UndoRemoveManagedSetting& undo) {
    const std::lock_guard<std::mutex> lock(rollbackBackendMutex());

    SudoersConfigurationOptions options = deps.sudoersOptions
        ? deps.sudoersOptions()
        : SudoersConfigurationOptions{};

    SudoersConfiguration configuration(options);
    std::string error;
    if (!configuration.load(error)) {
        MutationRollbackOutcome outcome;
        outcome.id = record.id;
        outcome.resource = record.resource;
        outcome.status = RollbackStatus::Failed;
        outcome.message = "Не удалось проанализировать sudoers: " + error;
        return outcome;
    }

    const SudoersOperationResult removal =
        configuration.removeManagedGlobalDefault(undo.key, undo.appliedValue);
    MutationRollbackOutcome outcome;
    outcome.id = record.id;
    outcome.resource = record.resource;
    outcome.message = removal.message;
    if (removal.ok && removal.conflict) {
        outcome.status = RollbackStatus::Conflict;
    } else if (removal.ok && removal.targetMissing) {
        outcome.status = RollbackStatus::NothingToDo;
    } else if (removal.ok) {
        outcome.status = RollbackStatus::Success;
    } else if (removal.conflict) {
        outcome.status = RollbackStatus::Conflict;
    } else {
        outcome.status = RollbackStatus::Failed;
    }
    return outcome;
}

MutationRollbackOutcome undoSshDirective(
    const RollbackExecutorDeps& deps,
    const MutationRecord& record,
    const UndoRestoreSshDirective& undo) {
    const std::lock_guard<std::mutex> lock(rollbackBackendMutex());

    MutationRollbackOutcome outcome;
    outcome.id = record.id;
    outcome.resource = record.resource;
    if (!deps.sshOptions) {
        outcome.status = RollbackStatus::Failed;
        outcome.message = "SSH rollback backend не настроен";
        return outcome;
    }
    SshRollbackOptions options = deps.sshOptions();
    if (options.executables == nullptr || options.configPath.empty()) {
        outcome.status = RollbackStatus::Failed;
        outcome.message = "SSH rollback backend настроен неполно: путь к "
                          "sshd_config или resolver executables не задан";
        return outcome;
    }

    const SshRollbackResult result = undoSshDirectiveMutation(options, undo);
    outcome.message = result.message;
    if (result.ok) {
        outcome.status = RollbackStatus::Success;
    } else if (result.nothingToDo) {
        // The recorded mutation is already factually rolled back (e.g. a
        // crash after a successful undo but before the journal update).
        outcome.status = RollbackStatus::NothingToDo;
    } else if (result.conflict) {
        outcome.status = RollbackStatus::Conflict;
    } else {
        outcome.status = RollbackStatus::Failed;
    }
    return outcome;
}

MutationRollbackOutcome undoFirewallPolicyMutation(
    const RollbackExecutorDeps& deps,
    const MutationRecord& record,
    const UndoRemoveFirewallPolicy& undo) {
    MutationRollbackOutcome outcome;
    outcome.id = record.id;
    outcome.resource = record.resource;
    if (!deps.undoFirewallPolicy) {
        outcome.status = RollbackStatus::Failed;
        outcome.message = "FIREWALL undo backend не настроен";
        return outcome;
    }
    std::string error;
    if (!deps.undoFirewallPolicy(undo.policyName, error)) {
        outcome.status = RollbackStatus::Failed;
        outcome.message = "Не удалось удалить managed firewall policy '" +
                          undo.policyName + "': " + error;
        return outcome;
    }
    outcome.status = RollbackStatus::Success;
    outcome.message = "Managed firewall policy '" + undo.policyName +
                      "' удалена из nftables";
    return outcome;
}

MutationRollbackOutcome undoDeviceFeature(
    const RollbackExecutorDeps& deps,
    const MutationRecord& record,
    const UndoDisableDeviceFeature& undo) {
    MutationRollbackOutcome outcome;
    outcome.id = record.id;
    outcome.resource = record.resource;
    if (!isDcCategoryFeature(undo.feature)) {
        outcome.status = RollbackStatus::Unsupported;
        outcome.message = "Автоматический откат DC feature '" + undo.feature +
                          "' не поддерживается";
        return outcome;
    }
    if (!deps.disableDeviceFeature) {
        outcome.status = RollbackStatus::Failed;
        outcome.message = "DC undo backend не настроен";
        return outcome;
    }
    std::string error;
    if (!deps.disableDeviceFeature(undo.feature, error)) {
        outcome.status = RollbackStatus::Failed;
        outcome.message = "Не удалось отключить DC feature '" + undo.feature +
                          "': " + error;
        return outcome;
    }
    outcome.status = RollbackStatus::Success;
    outcome.message = "DC feature '" + undo.feature + "' отключена";
    return outcome;
}

MutationRollbackOutcome undoMutation(
    const RollbackExecutorDeps& deps,
    const MutationRecord& record) {
    if (const auto* setting =
            std::get_if<UndoRemoveManagedSetting>(&record.undo.payload)) {
        if (record.undo.backend == MutationBackend::Sysctl) {
            return undoSysctlSetting(deps, record, *setting);
        }
        if (record.undo.backend == MutationBackend::Sudo) {
            return undoSudoSetting(deps, record, *setting);
        }
    }
    if (const auto* sshDirective =
            std::get_if<UndoRestoreSshDirective>(&record.undo.payload)) {
        if (record.undo.backend == MutationBackend::Ssh) {
            return undoSshDirective(deps, record, *sshDirective);
        }
    }
    if (const auto* firewallPolicy =
            std::get_if<UndoRemoveFirewallPolicy>(&record.undo.payload)) {
        return undoFirewallPolicyMutation(deps, record, *firewallPolicy);
    }
    if (const auto* feature =
            std::get_if<UndoDisableDeviceFeature>(&record.undo.payload)) {
        return undoDeviceFeature(deps, record, *feature);
    }
    MutationRollbackOutcome outcome;
    outcome.id = record.id;
    outcome.resource = record.resource;
    outcome.status = RollbackStatus::Unsupported;
    outcome.message = "Undo action не поддерживается rollback executor'ом";
    return outcome;
}

RollbackReport provenanceUnavailable(const PolicyRef& policy) {
    RollbackReport report;
    report.status = RollbackStatus::Unsupported;
    report.message = "Rollback provenance unavailable for legacy-applied policy " +
                     formatPolicyRef(policy) +
                     ". Automatic rollback is not possible.";
    return report;
}

} // namespace

std::string rollbackStatusToString(RollbackStatus status) {
    switch (status) {
    case RollbackStatus::Success: return "success";
    case RollbackStatus::NothingToDo: return "nothing_to_do";
    case RollbackStatus::Conflict: return "conflict";
    case RollbackStatus::Unsupported: return "unsupported";
    case RollbackStatus::Failed: return "failed";
    case RollbackStatus::Partial: return "partial";
    }
    return "unknown";
}

RollbackEnrollment rollbackEnrollment(const PolicyRef& policy) {
    if (policy.moduleName == "SYSCTL") {
        return RollbackEnrollment::Supported;
    }
    if (policy.moduleName == "DAC" && policy.submoduleName == "SudoEdit") {
        if (policy.policyName == "sudo_require_authentication") {
            return RollbackEnrollment::Unsupported;
        }
        return isSupportedSudoPolicy(policy.policyName)
            ? RollbackEnrollment::Supported
            : RollbackEnrollment::Unsupported;
    }
    if (policy.moduleName == "FIREWALL" && policy.submoduleName == "HostFiltering") {
        if (policy.policyName == "exclusive_firewall_control") {
            return RollbackEnrollment::Unsupported;
        }
        // No default-positive enrollment for unknown firewall policies.
        return isSupportedFirewallPolicy(policy.policyName)
            ? RollbackEnrollment::Supported
            : RollbackEnrollment::Unsupported;
    }
    if (policy.moduleName == "NET" && policy.submoduleName == "SshEdit") {
        // No default-positive enrollment for unknown SSH policies: the shared
        // main sshd_config must only be rolled back through the recorded
        // reverse delta of an integrated policy.
        return isSupportedSshPolicy(policy.policyName)
            ? RollbackEnrollment::Supported
            : RollbackEnrollment::Unsupported;
    }
    if (policy.moduleName == "DC" && policy.submoduleName == "DeviceControl") {
        return isDcCategoryFeature(policy.policyName)
            ? RollbackEnrollment::Supported
            : RollbackEnrollment::Unsupported;
    }
    return RollbackEnrollment::NotEnrolled;
}

namespace {

// Fail-safe provenance check for a supported policy without active journal
// records: the FIC-owned artifact must not contain the policy resource.
RollbackReport checkUnrecordedOwnership(
    const PolicyRef& policy,
    const std::string& resourceHint,
    const RollbackExecutorDeps& deps,
    const MutationJournal* journal) {
    RollbackReport report;
    report.status = RollbackStatus::NothingToDo;
    report.message = "Active mutation records отсутствуют; FIC не владеет "
                     "изменениями этой политики";

    if (policy.moduleName == "SYSCTL") {
        if (resourceHint.empty()) {
            return provenanceUnavailable(policy);
        }
        SysctlConfigurationOptions options = deps.sysctlOptions
            ? deps.sysctlOptions()
            : SysctlConfigurationOptions{};
        SysctlConfiguration configuration(options);
        std::string error;
        if (!configuration.load(error)) {
            report.status = RollbackStatus::Failed;
            report.message = "Не удалось проанализировать конфигурацию sysctl: " + error;
            return report;
        }
        // Legacy provenance check uses the FIC managed artifact content, not
        // the effective source: an entry shadowed by an external file is
        // still FIC-owned persistent state and must not be silently kept.
        const SysctlValueObservation managed =
            configuration.inspectManagedValue(resourceHint);
        if (managed.found) {
            return provenanceUnavailable(policy);
        }
        return report;
    }
    if (policy.moduleName == "DAC" && policy.submoduleName == "SudoEdit") {
        if (resourceHint.empty()) {
            return provenanceUnavailable(policy);
        }
        SudoersConfigurationOptions options = deps.sudoersOptions
            ? deps.sudoersOptions()
            : SudoersConfigurationOptions{};
        SudoersConfiguration configuration(options);
        std::string error;
        if (!configuration.load(error)) {
            report.status = RollbackStatus::Failed;
            report.message = "Не удалось проанализировать sudoers: " + error;
            return report;
        }
        // Legacy provenance check uses the FIC managed artifact content, not
        // the effective source: an entry shadowed by the main sudoers or
        // another include is still FIC-owned persistent state and must not
        // be silently kept.
        const SudoersValueObservation managed =
            configuration.inspectManagedGlobalDefault(resourceHint);
        if (managed.found) {
            return provenanceUnavailable(policy);
        }
        return report;
    }
    if (policy.moduleName == "NET" && policy.submoduleName == "SshEdit") {
        if (resourceHint.empty()) {
            return provenanceUnavailable(policy);
        }
        SshRollbackOptions options = deps.sshOptions
            ? deps.sshOptions()
            : SshRollbackOptions{};
        if (options.executables == nullptr || options.configPath.empty()) {
            RollbackReport report;
            report.status = RollbackStatus::Failed;
            report.message = "SSH rollback backend настроен неполно: путь к "
                             "sshd_config или resolver executables не задан";
            return report;
        }
        SshConfigFileHandler handler(options.configPath.string());
        if (!handler.loadConfig()) {
            RollbackReport report;
            report.status = RollbackStatus::Failed;
            report.message = "Не удалось проанализировать sshd_config: " +
                             options.configPath.string();
            return report;
        }
        // Only a successfully resolved historical record (RolledBack from a
        // previous disable, or Detached) proves that the current directive
        // state is the post-rollback state: FIC no longer owns anything
        // there. Any other status must fail closed instead of being treated
        // as proof of resolved ownership.
        if (journal != nullptr) {
            const std::string resource =
                "ssh:" + options.configPath.string() + ":" + resourceHint;
            for (const MutationRecord& record : journal->records()) {
                if (record.policy == policy &&
                    record.undo.backend == MutationBackend::Ssh &&
                    record.resource == resource) {
                    if (record.status == MutationStatus::RolledBack ||
                        record.status == MutationStatus::Detached) {
                        RollbackReport report;
                        report.status = RollbackStatus::NothingToDo;
                        report.message = "SSH-мутация политики уже была "
                                         "отозвана ранее; FIC не владеет "
                                         "текущим состоянием";
                        return report;
                    }
                    RollbackReport report;
                    report.status = RollbackStatus::Failed;
                    report.message =
                        "Историческая SSH-мутация политики имеет статус " +
                        mutationStatusToString(record.status) +
                        "; FIC-владение не может быть разрешено";
                    return report;
                }
            }
        }
        // Legacy provenance check (fail closed): the main sshd_config is a
        // shared file. A target directive present in the global section
        // cannot be attributed without journal provenance — even when its
        // value matches the policy. Absent directive: FIC owns nothing there.
        if (handler.isParameterExists(resourceHint)) {
            return provenanceUnavailable(policy);
        }
        RollbackReport report;
        report.status = RollbackStatus::NothingToDo;
        report.message = "Active mutation records отсутствуют; директива " +
                         resourceHint +
                         " в global section sshd_config отсутствует";
        return report;
    }
    // FIREWALL and DC: no cheap safe ownership check without the journal.
    return provenanceUnavailable(policy);
}

} // namespace

RollbackReport rollbackPolicyBeforeDisable(
    const PolicyRef& policy,
    const std::string& resourceHint,
    const RollbackExecutorDeps& deps) {
    const RollbackEnrollment enrollment = rollbackEnrollment(policy);
    if (enrollment == RollbackEnrollment::NotEnrolled) {
        RollbackReport report;
        report.status = RollbackStatus::Success;
        report.message = "Policy не участвует в системе rollback";
        return report;
    }
    if (enrollment == RollbackEnrollment::Unsupported) {
        RollbackReport report;
        report.status = RollbackStatus::Unsupported;
        report.message = "RollbackUnsupported: automatic rollback is not "
                         "supported for policy " + formatPolicyRef(policy) +
                         ". Disable is refused to avoid masking a live mutation.";
        return report;
    }

    std::string journalError;
    MutationJournal* journal =
        DaemonMutationJournal::instance().tryGet(journalError);
    if (journal == nullptr) {
        RollbackReport report;
        report.status = RollbackStatus::Failed;
        report.message = journalError.empty()
            ? "Mutation journal недоступен"
            : journalError;
        return report;
    }

    const std::vector<MutationRecord> active = journal->activeRecords(policy);
    if (active.empty()) {
        return checkUnrecordedOwnership(policy, resourceHint, deps, journal);
    }

    RollbackReport report;
    std::size_t succeeded = 0;
    std::size_t failed = 0;
    for (const MutationRecord& record : active) {
        MutationRollbackOutcome outcome = undoMutation(deps, record);
        report.outcomes.push_back(outcome);

        std::string journalUpdateError;
        if (outcome.status == RollbackStatus::Success ||
            outcome.status == RollbackStatus::NothingToDo) {
            ++succeeded;
            if (!journal->setStatus(
                    record.id, MutationStatus::RolledBack, journalUpdateError)) {
                // Fail closed: provenance must reflect the actual state.
                outcome.status = RollbackStatus::Failed;
                outcome.message += ". Ошибка обновления mutation journal: " +
                                   journalUpdateError;
                report.outcomes.back() = outcome;
                ++failed;
                --succeeded;
            }
        } else {
            ++failed;
            if (!journal->setStatusWithMessage(
                    record.id, MutationStatus::RollbackFailed,
                    outcome.message, journalUpdateError)) {
                outcome.message += ". Ошибка обновления mutation journal: " +
                                   journalUpdateError;
                report.outcomes.back() = outcome;
            }
        }
    }

    if (failed == 0) {
        const bool allNothingToDo =
            std::all_of(report.outcomes.begin(), report.outcomes.end(),
                        [](const MutationRollbackOutcome& outcome) {
                            return outcome.status == RollbackStatus::NothingToDo;
                        });
        if (allNothingToDo) {
            // Every active mutation turned out to be already resolved or owned
            // by a foreign source: report it explicitly instead of a fake
            // success, so callers can distinguish "no work" from real undo.
            report.status = RollbackStatus::NothingToDo;
            report.message =
                "Активные mutation не требуют отката: FIC не владеет текущим состоянием";
        } else {
            report.status = RollbackStatus::Success;
            report.message = "Rollback выполнен для " + std::to_string(succeeded) +
                             " mutation";
        }
    } else if (succeeded > 0) {
        report.status = RollbackStatus::Partial;
        report.message = "Rollback выполнен частично: успешно " +
                         std::to_string(succeeded) + ", с ошибками " +
                         std::to_string(failed);
    } else {
        const RollbackStatus firstStatus = report.outcomes.front().status;
        report.status = firstStatus == RollbackStatus::Conflict
            ? RollbackStatus::Conflict
            : (firstStatus == RollbackStatus::Unsupported
                   ? RollbackStatus::Unsupported
                   : RollbackStatus::Failed);
        report.message = report.outcomes.front().message;
    }
    return report;
}

RollbackExecutorDeps productionRollbackDeps(
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    std::function<bool(const std::string& feature, std::string& error)>
        disableDeviceFeature) {
    RollbackExecutorDeps deps;
    const fic::platform::SysctlPlatformConfig sysctlConfig = platform.sysctl;
    deps.sysctlOptions = [sysctlConfig]() {
        SysctlConfigurationOptions options;
        options.platform = sysctlConfig;
        return options;
    };

    const fic::platform::SudoPlatformConfig sudoConfig = platform.sudo;
    deps.sudoersOptions = [sudoConfig, &executables]() {
        SudoersConfigurationOptions options;
        options.mainPath = sudoConfig.mainConfigPath;
        options.managedPath = sudoConfig.managedConfigPath;
        std::filesystem::path validator;
        std::string error;
        if (executables.resolve(
                fic::platform::ExecutableId::Visudo, validator, error)) {
            options.validatorPath = validator.string();
        }
        return options;
    };

    const fic::platform::SshPlatformConfig sshConfig = platform.ssh;
    deps.sshOptions = [sshConfig, &executables]() {
        SshRollbackOptions options;
        options.configPath = sshConfig.configPath;
        options.includeBasePath = sshConfig.includeBasePath;
        options.serviceUnits = sshConfig.serviceUnits;
        options.executables = &executables;
        return options;
    };

    deps.undoFirewallPolicy =
        [&executables](const std::string& policyName, std::string& error) {
            ModuleConfigFileHandler config("FIREWALL");
            if (!config.loadConfig()) {
                error = "could not load FIREWALL.conf";
                return false;
            }
            std::map<std::string, bool> enabled;
            for (const std::string& policy :
                 {"block_rdp", "block_ftp", "custom_rules",
                  "exclusive_firewall_control"}) {
                enabled[policy] = policy != policyName &&
                    config.getPolicyStatus(policy) == "ENABLE";
            }
            const std::string customRules =
                config.hasConfiguredValue("custom_rules")
                    ? config.getPolicyValue("custom_rules") : "";
            fic::firewall::FirewallDesiredState desired;
            if (!fic::firewall::buildFirewallDesiredState(
                    enabled, customRules, desired, error)) {
                return false;
            }
            fic::firewall::FirewallBackend backend(executables);
            std::vector<fic::firewall::ForeignBaseChain> neutralized;
            return backend.reconcile(desired, neutralized, error);
        };

    deps.disableDeviceFeature = std::move(disableDeviceFeature);
    return deps;
}

} // namespace fic::rollback
