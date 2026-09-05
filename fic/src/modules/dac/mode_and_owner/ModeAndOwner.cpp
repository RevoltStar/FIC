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
    std::vector<fic::platform::FileAccessRule> rules)
    : FixedPolicyTypeValue(),
      rules_(std::move(rules)) {
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

bool ModeAndOwner::apply() {
    this->log("Запуск функции Mode_And_Owner::apply", logLevel::TRACE);
    int total = 0;
    int success = 0;
    int failed = 0;
    int fixed = 0;

    for (const auto& [filename, expectation] : expected) {
        const FileStats& expectedStats = expectation.stats;
        ++total;
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
                ++success;
            } else {
                this->log("Обязательный файл отсутствует: " + filename,
                          logLevel::ERROR);
                ++failed;
            }
            continue;
        }
        if (currentStats.has_error()) {
            this->log("Не удалось безопасно открыть файл " + filename + ": " +
                          currentStats.error_message(),
                      logLevel::ERROR);
            ++failed;
            continue;
        }

        this->log("Проверка файла " + filename, logLevel::INFO);
        const auto providerTarget = std::find_if(
            expectation.providerManagedFinalSymlinkTargets.begin(),
            expectation.providerManagedFinalSymlinkTargets.end(),
            [&](const auto& target) {
                return target.path == currentStats.opened_policy_path();
            });
        const bool providerManaged = providerTarget !=
            expectation.providerManagedFinalSymlinkTargets.end();
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
        } else if (!ownerInitiallyCorrect && providerManaged) {
            diagnostics.push_back(
                "Provider-managed target has incorrect owner/group and is "
                "validate-only: " + currentStats.opened_policy_path().string());
        } else if (!ownerInitiallyCorrect) {
            const FileStatsOperationResult changeResult =
                currentStats.change_owner_group(
                    expectedOwnerId, expectedGroupId);
            if (changeResult) {
                ++fixed;
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
                    static_cast<mode_t>(~expectedStats._permissions)) == 0;
        };
        if (currentStateReadable && !permissionRequirementSatisfied() &&
            providerManaged) {
            diagnostics.push_back(
                "Provider-managed target has excessive permissions and is "
                "validate-only: " + currentStats.opened_policy_path().string());
        } else if (currentStateReadable && !permissionRequirementSatisfied()) {
            const mode_t targetPermissions =
                modeEnforcement_ == ModeEnforcement::Exact
                    ? expectedStats._permissions
                    : currentStats._permissions & expectedStats._permissions;
            const FileStatsOperationResult changeResult =
                currentStats.change_permissions(targetPermissions);
            if (changeResult) {
                ++fixed;
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
            ++failed;
        } else {
            this->log(changed
                          ? "ИТОГ: требования для " + filename + " исправлены"
                          : "ИТОГ: файл " + filename + " соответствует требованиям",
                      logLevel::INFO);
            ++success;
        }
    }

    this->log("РЕЗУЛЬТАТ:", logLevel::DEBUG);
    this->log("Всего проверено файлов: " + std::to_string(total), logLevel::DEBUG);
    this->log("Соответствуют требованиям: " + std::to_string(success),
              logLevel::DEBUG);
    this->log("Исправлено параметров: " + std::to_string(fixed), logLevel::DEBUG);
    this->log("Проблемных файлов: " + std::to_string(failed), logLevel::DEBUG);

    if (failed == 0) {
        if (fixed != 0) {
            this->notify(
                "Были обнаружены отклонения от эталона при применении политики " +
                    this->policyName + ", однако они все были успешно исправлены",
                notifyLevel::WARN);
        }
        this->log(fixed == 0 ? "Отклонений не обнаружено"
                             : "Все обнаруженные отклонения исправлены",
                  fixed == 0 ? logLevel::INFO : logLevel::WARN);
        return true;
    }

    this->notify(
        "Были обнаружены отклонения от эталона при применении политики " +
            this->policyName + ", и некоторые (" + std::to_string(failed) +
            ") исправлены не были",
        notifyLevel::ERROR);
    this->log("ВНИМАНИЕ: Не все отклонения удалось исправить (Проблемных файлов: " +
                  std::to_string(failed) + ")",
              logLevel::ERROR);
    return false;
}
