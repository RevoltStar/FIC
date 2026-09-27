#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_OPTION_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_OPTION_POLICY_H

#include "modules/identity_access/pam/PamOptionPolicy.h"
#include "modules/identity_access/pam/PamPasswordTopologyCoordinator.h"

#include <functional>
#include <memory>
#include <string>

// Shared apply strategy of the two managed pwhistory option policies
// (password_history_depth, password_history_enforce_for_root).
//
// Two physical configuration levels exist for the history capability and
// they are never mixed:
//
//   - PamCapabilityConfigurationMode::ModuleArguments (Debian 12): the
//     options are FIC-managed module arguments of the C2 history slots.
//     The joint coordinator (topology reconcile + in-place option
//     reconcile through the journal-bound slot writer) is the ONLY
//     writer; the classic stack-argument mutation path would corrupt the
//     canonical slot bodies and their journal ownership, so it is never
//     used here. The configuration intent (already persisted when the
//     policy apply runs) is the authoritative desired state — one joint
//     transition reads the Q/H request and the options from the SAME
//     configuration snapshot.
//
//   - every other mode (e.g. provider config file /etc/security/
//     pwhistory.conf): the classic PamOptionPolicy path is unchanged.
//
// Concurrency contract: the joint transition runs under the identity
// configuration mutex already held by PamPolicy::apply (same model as the
// activation policies).
class PamPasswordHistoryOptionPolicy : public PamOptionPolicy {
public:
    using PasswordCoordinatorFactory = std::function<
        std::unique_ptr<fic::identity::pam::PamPasswordTopologyCoordinator>()>;

    ~PamPasswordHistoryOptionPolicy() override = default;

protected:
    explicit PamPasswordHistoryOptionPolicy(
        fic::platform::PamPlatformConfig platformConfig,
        fic::platform::PamPolicyFeature feature,
        PasswordCoordinatorFactory passwordCoordinatorFactory = {});

    bool applyPam(const std::string& expectedValue) override;

private:
    // True when the platform governs the history capability through FIC
    // module arguments of the C2 joint topology (PamAuthUpdate topology +
    // ModuleArguments configuration mode).
    bool c2ManagedHistoryDomain() const;

    PasswordCoordinatorFactory passwordCoordinatorFactory_;
};

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_OPTION_POLICY_H