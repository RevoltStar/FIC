#pragma once
#include "service/VerifiedConfigLaunchContract.h"
#ifdef FIC_SSSD_I1_TESTING
#include <functional>
#endif
namespace fic::service::sssd {
using Deadline = std::chrono::steady_clock::time_point;
// No activation authority, receipt or ownership. Exceptions use detail::Failure.
struct LaunchProfile {
    std::string platform, fragment, environment, user, group, pidFile;
    std::vector<std::vector<std::string>> preCommands;
    std::string unitSha256;
};
LaunchProfile launchProfile(const std::string& platform);
void validateLaunchProfile(const detail::LaunchContract&, const LaunchProfile&);
enum class AdmissionState { Candidate, Stopped, Failed, Transitioning, Unknown };
AdmissionState classifyService(const detail::LaunchContract&);
struct SssdLaunchReference {
    LaunchProfile profile;
    detail::LaunchContract contract;
    // Descriptor-rooted fingerprints, including executable bytes/metadata.
    std::map<std::string,std::string> executables;
    std::string processIdentity, environmentFingerprint, unitLookupFingerprint;
    bool genericActivationSupported = false; // I1 never authorizes I3.
    std::string activationLimit;
};
SssdLaunchReference admit(Deadline deadline);
void revalidate(const SssdLaunchReference&, Deadline deadline);
namespace detail_i5 {
// Same closed launch proof, additionally accepts inactive/dead MainPID=0.
// This alone is not offline proof: coordinator must exclude consumers/sockets
// and recheck before publication and finalization while holding the unit lease.
SssdLaunchReference admitForRelease(Deadline);
void revalidateRelease(const SssdLaunchReference&, Deadline);
}
namespace detail_i1 {
std::string environmentReference(const std::string& path);
void verifyExecutables(const SssdLaunchReference&);
#ifdef FIC_SSSD_I1_TESTING
// Operation-local checkpoint after initial launch/environment/lookup observations.
SssdLaunchReference admitForTests(Deadline, const std::function<void(const SssdLaunchReference&)>&);
#endif
}
} // namespace fic::service::sssd
