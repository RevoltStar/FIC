#ifndef FIC_ROLLBACK_ROLLBACK_EXECUTOR_H
#define FIC_ROLLBACK_ROLLBACK_EXECUTOR_H

#include "modules/dac/mode_and_owner/DacBaselineRollback.h"
#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/identity_access/kerberos/KerberosRollback.h"
#include "modules/identity_access/pam/PamTopologyManager.h"
#include "modules/identity_access/sssd/SssdRollback.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/oss/grub/GrubRollback.h"
#include "modules/sysctl/SysctlConfiguration.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationRecord.h"

#include <functional>
#include <memory>
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

// Executes one UndoApplyDacPlatformBaseline mutation (implemented in
// modules/dac/mode_and_owner/DacBaselineRollback.cpp): transitions every
// managed object of the policy to its platform baseline. Path resolution,
// symlink allowlists, provider-target checks and object type validation are
// fail closed exactly as during apply; missing objects follow
// MissingFilePolicy::Ignore semantics and are never created. Partial success
// is reported as RollbackStatus::Partial.
MutationRollbackOutcome undoDacBaselineMutation(
    const DacBaselineRollbackOptions& options,
    const MutationRecord& record,
    const UndoApplyDacPlatformBaseline& undo);

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
    fic::platform::PamPlatformConfig pamPlatform;
    std::function<std::unique_ptr<fic::identity::pam::PamTopologyManager>(
        const fic::platform::PamCapabilityConfig&,
        const std::vector<std::string>&, std::string&)> pamManagerFactory;
    // SYSCTL backend configuration (managed file layout etc.).
    std::function<SysctlConfigurationOptions()> sysctlOptions;
    // Runtime /proc/sys root override for tests; production default is used when empty.
    std::filesystem::path sysctlRuntimeRoot;
    // SUDO backend configuration (managed sudoers etc.).
    std::function<SudoersConfigurationOptions()> sudoersOptions;
    // SSH backend configuration: shared main sshd_config, service units and
    // the executable resolver used for sshd -T validation and service reload.
    std::function<SshRollbackOptions()> sshOptions;
    // GRUB backend configuration: the platform profile GRUB topology is the
    // single source of truth for the managed artifact location.
    std::function<GrubRollbackOptions()> grubOptions;
    // SSSD backend configuration: the FIC-owned drop-in location and the
    // snippet topology come from the current SssdConfigurationOptions.
    std::function<SssdRollbackOptions()> sssdOptions;
    // Kerberos backend configuration: the root krb5.conf location comes from
    // the current KerberosConfigurationOptions.
    std::function<KerberosRollbackOptions()> kerberosOptions;
    // DAC platform-baseline backend configuration: the platform profile DAC
    // config is the single source of truth for the baseline metadata.
    std::function<DacBaselineRollbackOptions()> dacOptions;
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
