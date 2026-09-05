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

const char* providerName(fic::platform::ManagedFileProvider provider) {
    switch (provider) {
    case fic::platform::ManagedFileProvider::SystemdResolved:
        return "systemd-resolved";
    case fic::platform::ManagedFileProvider::NetworkManager:
        return "NetworkManager";
    case fic::platform::ManagedFileProvider::Resolvconf:
        return "resolvconf";
    }
    return "unknown";
}
} // namespace

FileAccessRulesPolicyTypeValue::FileAccessRulesPolicyTypeValue(
    std::vector<fic::platform::FileAccessRule> rules,
    std::optional<fic::platform::TcbCredentialStorageConfig>
        tcbCredentialStorage)
    : FixedPolicyTypeValue(),
      rules_(std::move(rules)),
      tcbCredentialStorage_(std::move(tcbCredentialStorage)) {
}

std::string FileAccessRulesPolicyTypeValue::getPolicyRestrictionInfo() {
    std::ostringstream result;
    result << LocalizationManager::getLang(
        "[module:DAC][message:platform_access_rules]");
    for (const fic::platform::FileAccessRule& rule : rules_) {
        result << "\n" << rule.path.string() << " "
               << rule.owner << ":" << rule.group << " "
               << std::setfill('0') << std::setw(4) << std::oct
               << rule.permissions << std::dec;
        if (!rule.allowedFinalSymlinkTargets.empty()) {
            result << " (final symlink -> ";
            for (std::size_t index = 0;
                 index < rule.allowedFinalSymlinkTargets.size(); ++index) {
                if (index != 0) {
                    result << ", ";
                }
                result << rule.allowedFinalSymlinkTargets[index].string();
            }
            result << ")";
        }
        for (const auto& target :
             rule.providerManagedFinalSymlinkTargets) {
            result << " (provider-managed final symlink -> "
                   << target.path.string() << ", "
                   << providerName(target.provider) << ", validate only)";
        }
    }
    if (tcbCredentialStorage_) {
        const auto& tcb = *tcbCredentialStorage_;
        result << "\n" << tcb.rootPath.string() << " "
               << tcb.rootOwner << ":" << tcb.rootGroup << " "
               << std::setfill('0') << std::setw(4) << std::oct
               << tcb.rootPermissions << std::dec;
        result << "\n" << (tcb.rootPath / "<account>").string() << " "
               << "<account>:" << tcb.entryGroup << " "
               << std::setfill('0') << std::setw(4) << std::oct
               << tcb.entryDirectoryPermissions << std::dec;
        for (const auto& file : tcb.files) {
            result << "\n"
                   << (tcb.rootPath / "<account>" / file.name).string() << " "
                   << "<account>:" << tcb.entryGroup << " "
                   << std::setfill('0') << std::setw(4) << std::oct
                   << file.permissions << std::dec;
        }
    }
    return result.str();
}

ModeAndOwner::ModeAndOwner(MissingFilePolicy missingFilePolicy,
                           PolicyPathResolution pathResolution,
                           ModeEnforcement modeEnforcement)
    : DAC(),
      missingFilePolicy_(missingFilePolicy),
      pathResolution_(pathResolution),
      modeEnforcement_(modeEnforcement) {
    this->submoduleName = "Mode_and_Owner";
}

void ModeAndOwner::addExpectedRule(
    const std::filesystem::path& path,
    const std::string& owner,
    const std::string& group,
    mode_t permissions,
    std::vector<std::filesystem::path> allowedFinalSymlinkTargets,
    std::vector<fic::platform::ProviderManagedFileTarget>
        providerManagedFinalSymlinkTargets) {
    expected.insert_or_assign(
        path.string(),
        ModeAndOwnerExpectation{
            FileStats(owner, group, permissions),
            std::move(allowedFinalSymlinkTargets),
            std::move(providerManagedFinalSymlinkTargets)});
}

void ModeAndOwner::applyOpenedRule(
    const std::string& filename,
    const FileStats& expectedStats,
    FileStats currentStats,
    bool validateOnly,
    ApplyCounters& counters,
    mode_t requiredPermissions) {
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
    const bool ownerInitiallyCorrect = identityResult &&
        currentStats.owner_id() == expectedOwnerId &&
        currentStats.group_id() == expectedGroupId;
    ownershipRequirementMet = ownerInitiallyCorrect;
    if (!identityResult) {
        ownershipRequirementMet = false;
        diagnostics.push_back(identityResult.message);
    } else if (!ownerInitiallyCorrect && validateOnly) {
        diagnostics.push_back(
            "Provider-managed target has incorrect owner/group and is "
            "validate-only: " + currentStats.opened_policy_path().string());
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
        if (modeEnforcement_ == ModeEnforcement::Exact) {
            return currentStats.check_permission(expectedStats);
        }
        return (currentStats._permissions &
                static_cast<mode_t>(~expectedStats._permissions)) == 0 &&
            (currentStats._permissions & requiredPermissions) ==
                requiredPermissions;
    };
    if (currentStateReadable && !permissionRequirementSatisfied() &&
        validateOnly) {
        diagnostics.push_back(
            "Provider-managed target has excessive permissions and is "
            "validate-only: " + currentStats.opened_policy_path().string());
    } else if (currentStateReadable && !permissionRequirementSatisfied()) {
        const mode_t targetPermissions =
            modeEnforcement_ == ModeEnforcement::Exact
                ? expectedStats._permissions
                : (currentStats._permissions & expectedStats._permissions) |
                    requiredPermissions;
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
            if (missingFilePolicy_ == MissingFilePolicy::Ignore) {
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
        const bool providerManaged = providerTarget !=
            expectation.providerManagedFinalSymlinkTargets.end();
        applyOpenedRule(filename, expectedStats, std::move(currentStats),
                        providerManaged, counters);
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
    return false;
}
