#pragma once
#include "service/VerifiedConfigLaunchContract.h"
#include "service/VerifiedConfigSystemd.h"
#include <functional>
namespace fic::service::detail {
// Internal proof extension, shared engine with public activate(). Callbacks
// cannot substitute snapshots, restart, observation or cleanup. Any exception
// fails the operation with ordinary cleanup. No persistent writes permitted.
struct ActivationProof {
    LaunchContract expectedConfiguration;
    std::map<std::string, Identity> sourceRoots;
    std::map<std::string, std::map<std::string, struct stat>> sourceAttributes;
    std::function<void(std::chrono::steady_clock::time_point)> published;
    std::function<void(const ServiceState&, std::chrono::steady_clock::time_point)> ready;
};
ActivationResult activateWithProof(const ActivationRequest&, const ActivationProof&);
#ifdef FIC_ACTIVATOR_TESTING
struct TestHooks;
ActivationResult activateWithProofForTests(const ActivationRequest&, const ActivationProof&, const TestHooks&);
#endif
} // namespace fic::service::detail
