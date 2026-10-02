#include "modules/dac/mode_and_owner/ModeAndOwner.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <utility>

namespace {
std::string formatPermissions(mode_t permissions) {
    std::ostringstream output;
    output << std::setfill('0') << std::setw(4) << std::oct
           << static_cast<unsigned int>(permissions & 07777);
    return output.str();
}
} // namespace

ModeAndOwner::ModeAndOwner(PolicyPathResolution pathResolution)
    : DAC(),
      pathResolution_(pathResolution) {
    this->submoduleName = "Mode_and_Owner";
}


void ModeAndOwner::addExpectedRule(
    const std::filesystem::path& path,
    const fic::platform::DacPlatformConfig::PathContract& contract,
    fic::platform::DacPlatformConfig::PresenceRequirement presence) {
    expected.insert_or_assign(
        path.string(),
        ModeAndOwnerExpectation{
            FileStats(contract.metadata.owner, contract.metadata.group,
                      contract.metadata.permissions),
            contract.allowedFinalSymlinkTargets, contract.providerTargets,
            contract.objectType, presence,
            contract.remediation ==
                fic::platform::DacPlatformConfig::Remediation::ValidateOnly});
}


void ModeAndOwner::applyOpenedRule(
    const std::string& filename,
    const FileStats& expectedStats,
    FileStats currentStats,
    bool validateOnly,
    ApplyCounters& counters) {
    this->log("Проверка файла " + filename, logLevel::INFO);
    const std::string originalOwner = currentStats._owner;
    const std::string originalGroup = currentStats._group;
    const mode_t originalPermissions = currentStats._permissions;
    bool changed = false;
    bool ownershipRequirementMet = false;
    bool permissionRequirementMet = false;
    bool verificationSucceeded = true;
    bool currentStateReadable = true;
    bool ownershipChanged = false;
    std::vector<std::string> diagnostics;

    uid_t expectedOwnerId = 0;
    gid_t expectedGroupId = 0;
    const FileStatsOperationResult identityResult =
        FileStats::resolve_owner_group(
            expectedStats._owner,
            expectedStats._group,
            expectedOwnerId,
            expectedGroupId);
    if (!identityResult) {
        this->log(identityResult.message, logLevel::ERROR);
        this->log("ИТОГ: требования для " + filename + " не выполнены",
                  logLevel::ERROR);
        ++counters.failed;
        return;
    }
    const bool ownerInitiallyCorrect = identityResult &&
        currentStats.owner_id() == expectedOwnerId &&
        currentStats.group_id() == expectedGroupId;
    ownershipRequirementMet = ownerInitiallyCorrect;
    if (!ownerInitiallyCorrect && validateOnly) {
        diagnostics.push_back(
            "Provider-managed target has incorrect owner/group and is "
            "validate-only: " + currentStats.opened_policy_path().string() +
            " (expected " + expectedStats._owner + ":" + expectedStats._group +
            ", actual " + originalOwner + ":" + originalGroup +
            "); FIC did not modify the provider-owned target");
    } else if (!ownerInitiallyCorrect) {
        const FileStatsOperationResult changeResult =
            currentStats.change_owner_group(
                expectedOwnerId, expectedGroupId);
        if (changeResult) {
            ++counters.fixed;
            changed = true;
            ownershipChanged = true;
            this->log("Владелец/группа для " + filename +
                          " изменены [" + originalOwner + ":" +
                          originalGroup + " → " + expectedStats._owner +
                          ":" + expectedStats._group + "]",
                      logLevel::DEBUG);
        } else {
            ownershipRequirementMet = false;
            diagnostics.push_back(changeResult.message);
            // Do not apply a mode from a profile whose ownership could not
            // be established. That would leave a partially applied metadata
            // contract and can make the object less safe than either state.
            currentStateReadable = false;
        }
    }

    if (ownershipChanged) {
        const FileStatsOperationResult postChownRefresh =
            currentStats.refresh();
        if (!postChownRefresh) {
            currentStateReadable = false;
            diagnostics.push_back(postChownRefresh.message);
        }
    }

    const auto permissionRequirementSatisfied = [&]() {
        return currentStats.check_permission(expectedStats);
    };
    if (currentStateReadable && !permissionRequirementSatisfied() &&
        validateOnly) {
        diagnostics.push_back(
            "Provider-managed target has excessive permissions and is "
            "validate-only: " + currentStats.opened_policy_path().string() +
            " (expected exact mode " +
            formatPermissions(expectedStats._permissions) + ", actual " +
            formatPermissions(originalPermissions) +
            "); FIC did not modify the provider-owned target");
    } else if (currentStateReadable && !permissionRequirementSatisfied()) {
        const mode_t targetPermissions = expectedStats._permissions;
        const FileStatsOperationResult changeResult =
            currentStats.change_permissions(targetPermissions);
        if (changeResult) {
            ++counters.fixed;
            changed = true;
            this->log("Права для " + filename + " изменены [" +
                          formatPermissions(originalPermissions) +
                          " → " + formatPermissions(targetPermissions) + "]",
                      logLevel::DEBUG);
        } else {
            permissionRequirementMet = false;
            diagnostics.push_back(changeResult.message);
        }
    } else if (currentStateReadable) {
        permissionRequirementMet = true;
    }

    const FileStatsOperationResult refreshResult = currentStats.refresh();
    if (!refreshResult) {
        verificationSucceeded = false;
        ownershipRequirementMet = false;
        permissionRequirementMet = false;
        diagnostics.push_back(refreshResult.message);
    } else {
        ownershipRequirementMet =
            static_cast<bool>(identityResult) &&
            currentStats.owner_id() == expectedOwnerId &&
            currentStats.group_id() == expectedGroupId;
        permissionRequirementMet =
            permissionRequirementSatisfied();
        if (!ownershipRequirementMet) {
            diagnostics.push_back(
                "Контрольная проверка владельца/группы не пройдена для " +
                filename);
        }
        if (!permissionRequirementMet) {
            diagnostics.push_back(
                "Контрольная проверка прав не пройдена для " + filename);
        }
    }

    const bool fileSucceeded = verificationSucceeded &&
        ownershipRequirementMet && permissionRequirementMet;
    if (!fileSucceeded) {
        for (const std::string& diagnostic : diagnostics) {
            this->log(diagnostic, logLevel::ERROR);
        }
        this->log("ИТОГ: требования для " + filename + " не выполнены",
                  logLevel::ERROR);
        ++counters.failed;
    } else {
        this->log(changed
                      ? "ИТОГ: требования для " + filename + " исправлены"
                      : "ИТОГ: файл " + filename + " соответствует требованиям",
                  logLevel::INFO);
        ++counters.success;
    }
}

void ModeAndOwner::applyAdditionalRules(ApplyCounters&) {
}

bool ModeAndOwner::apply() {
    this->log("Запуск функции Mode_And_Owner::apply", logLevel::TRACE);
    ApplyCounters counters;
    this->lastApplyFixedCount_ = 0;

    for (const auto& [filename, expectation] : expected) {
        const FileStats& expectedStats = expectation.stats;
        ++counters.total;
        std::vector<std::filesystem::path> allowedTargets =
            expectation.allowedFinalSymlinkTargets;
        for (const auto& target :
             expectation.providerManagedFinalSymlinkTargets) {
            allowedTargets.push_back(target.path);
        }
        FileStats currentStats = FileStats::openPolicyPath(
            filename, allowedTargets, pathResolution_);

        if (currentStats.is_missing()) {
            if (expectation.presence ==
                fic::platform::DacPlatformConfig::PresenceRequirement::AllowMissing) {
                this->log("Файл " + filename + " отсутствует; правило пропущено",
                          logLevel::DEBUG);
                ++counters.success;
            } else {
                this->log("Обязательный файл отсутствует: " + filename,
                          logLevel::ERROR);
                ++counters.failed;
            }
            continue;
        }
        if (currentStats.has_error()) {
            this->log("Не удалось безопасно открыть файл " + filename + ": " +
                          currentStats.error_message(),
                      logLevel::ERROR);
            ++counters.failed;
            continue;
        }

        const auto providerTarget = std::find_if(
            expectation.providerManagedFinalSymlinkTargets.begin(),
            expectation.providerManagedFinalSymlinkTargets.end(),
            [&](const auto& target) {
                return target.path == currentStats.opened_policy_path();
            });
        if (providerTarget !=
                expectation.providerManagedFinalSymlinkTargets.end()) {
            // Provider-owned targets are validated against their own
            // target-specific platform contract and never remediated. A
            // matching target path alone is not compliance: owner/group and
            // mode of the provider-managed file may legally differ from the
            // static ModeAndOwnerVerifiedPath expectation.
            const FileStats providerExpectation(
                providerTarget->metadata.owner,
                providerTarget->metadata.group,
                providerTarget->metadata.permissions);
            if (!currentStats.is_regular_file()) {
                this->log(
                    "Provider-managed target " +
                        currentStats.opened_policy_path().string() +
                        " has an unexpected object type; expected a regular "
                        "file",
                    logLevel::ERROR);
                ++counters.failed;
                continue;
            }
            applyOpenedRule(
                filename, providerExpectation, std::move(currentStats),
                true, counters);
            continue;
        }

        const bool typeMatches =
            expectation.objectType ==
                    fic::platform::DacPlatformConfig::ObjectType::RegularFile
                ? currentStats.is_regular_file()
                : S_ISDIR(currentStats.file_type());
        // Static path: the platform contract is authoritative.
        // authoritative and remediation is allowed. The rule describes a
        // regular file: an unexpected object type (directory, device node,
        // ...) must fail closed before any metadata mutation.
        if (!typeMatches) {
            this->log(
                "Объект " + currentStats.opened_policy_path().string() +
                    " имеет неожиданный тип",
                logLevel::ERROR);
            ++counters.failed;
            continue;
        }
        applyOpenedRule(filename, expectedStats, std::move(currentStats),
                        expectation.validateOnly, counters);
    }

    applyAdditionalRules(counters);

    this->log("РЕЗУЛЬТАТ:", logLevel::DEBUG);
    this->log("Всего проверено файлов: " + std::to_string(counters.total),
              logLevel::DEBUG);
    this->log("Соответствуют требованиям: " + std::to_string(counters.success),
              logLevel::DEBUG);
    this->log("Исправлено параметров: " + std::to_string(counters.fixed),
              logLevel::DEBUG);
    this->log("Проблемных файлов: " + std::to_string(counters.failed),
              logLevel::DEBUG);

    if (counters.failed == 0) {
        this->lastApplyFixedCount_ = counters.fixed;
        if (counters.fixed != 0) {
            this->notify(
                "Были обнаружены отклонения от эталона при применении политики " +
                    this->policyName + ", однако они все были успешно исправлены",
                notifyLevel::WARN);
        }
        this->log(counters.fixed == 0 ? "Отклонений не обнаружено"
                             : "Все обнаруженные отклонения исправлены",
                  counters.fixed == 0 ? logLevel::INFO : logLevel::WARN);
        return true;
    }

    this->notify(
        "Были обнаружены отклонения от эталона при применении политики " +
            this->policyName + ", и некоторые (" +
            std::to_string(counters.failed) +
            ") исправлены не были",
        notifyLevel::ERROR);
    this->log("ВНИМАНИЕ: Не все отклонения удалось исправить (Проблемных файлов: " +
                  std::to_string(counters.failed) + ")",
              logLevel::ERROR);
    this->lastApplyFixedCount_ = counters.fixed;
    return false;
}
