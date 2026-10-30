#pragma once
#include "service/VerifiedConfigLaunchContract.h"
#include "service/VerifiedConfigSystemd.h"
#include <functional>
namespace fic::service::detail {
// Internal proof extension, shared engine with public activate(). Callbacks
// published/ready callbacks validate only. The closed Ubuntu hook dispatches
// fixed activation actions; none can substitute snapshot/observation/cleanup.
// Exceptions fail the operation with ordinary cleanup. No policy-config writes.
struct ActivationProof {
    ActivationProfile profile = ActivationProfile::ActiveNotifyService;
    // Closed Ubuntu SSH profile only. Runs under the SAME published snapshot;
    // no permission to replace copy/mount/observation/cleanup machinery.
    std::function<void(std::chrono::steady_clock::time_point)> sshSocketActivation;
    // Closed ALT simple-service readiness; runs only inside the common bounded loop.
    std::function<bool(const ServiceState&, std::chrono::steady_clock::time_point)> altSshReadiness;
    // Mandatory for the closed SSSD profile; adapter supplies I1 native validation.
    std::function<void(const LaunchContract&)> sssdLaunchValidation;
    LaunchContract expectedConfiguration;
    std::map<std::string, Identity> sourceRoots;
    std::map<std::string, std::map<std::string, struct stat>> sourceAttributes;
    std::function<void(std::chrono::steady_clock::time_point)> published;
    std::function<void(const ServiceState&, std::chrono::steady_clock::time_point)> ready;
};
// Read-only preflight shared with callers that must reject known unsupported
// publication environments before making persistent configuration changes.
// Performs no mkdir/mount/restart and grants no later activation authority.
void validatePublicationEnvironment(const ActivationRequest&, std::vector<std::string>* residualPaths = nullptr);
ActivationResult activateWithProof(const ActivationRequest&, const ActivationProof&);
// Separate internal result/entrypoint; SUCCESS here proves validation under
// pinned CURRENT inputs and clean cleanup, never readiness or activation.
struct SnapshotValidationProof {
    ActivationProfile profile=ActivationProfile::ActiveNotifyService;
    LaunchContract expectedConfiguration;
    std::map<std::string,Identity> sourceRoots;
    std::map<std::string,std::map<std::string,struct stat>> sourceAttributes;
    std::function<void(std::chrono::steady_clock::time_point)> validate;
};
struct SnapshotValidationResult {
    ActivationResult snapshot;
    bool success() const {return snapshot.success()&&!snapshot.readinessConfirmed;}
};
SnapshotValidationResult validateSnapshotWithProof(const ActivationRequest&,const SnapshotValidationProof&);
#ifdef FIC_ACTIVATOR_TESTING
struct TestHooks;
ActivationResult activateWithProofForTests(const ActivationRequest&, const ActivationProof&, const TestHooks&);
SnapshotValidationResult validateSnapshotWithProofForTests(const ActivationRequest&,const SnapshotValidationProof&,const TestHooks&);
#endif
} // namespace fic::service::detail
