#ifndef FIC_ROLLBACK_ROLLBACK_EXECUTOR_H
#define FIC_ROLLBACK_ROLLBACK_EXECUTOR_H

#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/sysctl/SysctlConfiguration.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationRecord.h"

#include <functional>
#include <string>
#include <vector>

namespace fic::rollback {

enum class RollbackStatus {
    Success,
    NothingToDo,
    Conflict,
    Unsupported,
    Failed,
    Partial
};

std::string rollbackStatusToString(RollbackStatus status);

struct MutationRollbackOutcome {
    MutationId id = 0;
    std::string resource;
    RollbackStatus status = RollbackStatus::NothingToDo;
    std::string message;
};

struct RollbackReport {
    RollbackStatus status = RollbackStatus::NothingToDo;
    std::string message;
    std::vector<MutationRollbackOutcome> outcomes;

    bool rollbackCompleted() const {
        return status == RollbackStatus::Success ||
               status == RollbackStatus::NothingToDo;
    }
};

enum class RollbackEnrollment {
    Supported,   // journal-backed automatic rollback is implemented
    Unsupported, // enrolled module, but automatic rollback is not implemented
    NotEnrolled  // module is outside the rollback system; disable keeps legacy behavior
};

RollbackEnrollment rollbackEnrollment(const PolicyRef& policy);

struct RollbackExecutorDeps {
    // SYSCTL backend configuration (managed file layout etc.).
    std::function<SysctlConfigurationOptions()> sysctlOptions;
    // Runtime /proc/sys root override for tests; production default is used when empty.
    std::filesystem::path sysctlRuntimeRoot;
    // SUDO backend configuration (managed sudoers etc.).
    std::function<SudoersConfigurationOptions()> sudoersOptions;
    // SSH backend configuration: shared main sshd_config, service units and
    // the executable resolver used for sshd -T validation and service reload.
    std::function<SshRollbackOptions()> sshOptions;
    // FIREWALL undo: reconcile the nftables state without the given policy.
    std::function<bool(const std::string& policyName, std::string& error)> undoFirewallPolicy;
    // DC undo: disable one category feature via the device daemon.
    std::function<bool(const std::string& feature, std::string& error)> disableDeviceFeature;
};

// Production deps wiring for the daemon: uses the platform profile and the
// platform executable resolver.
RollbackExecutorDeps productionRollbackDeps(
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    std::function<bool(const std::string& feature, std::string& error)>
        disableDeviceFeature);

// Rolls back all active mutations of the given policy. Must be called while
// the policy is still ENABLE and before the policy status flips to DISABLE.
// resourceHint carries the policy's managed resource (sysctl key, sudoers
// Defaults key) when the caller can provide it; it is used only for the
// fail-safe provenance check when the journal holds no records.
RollbackReport rollbackPolicyBeforeDisable(
    const PolicyRef& policy,
    const std::string& resourceHint,
    const RollbackExecutorDeps& deps);

} // namespace fic::rollback

#endif // FIC_ROLLBACK_ROLLBACK_EXECUTOR_H
