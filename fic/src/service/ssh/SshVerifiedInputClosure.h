#pragma once
#include "service/VerifiedConfigServiceActivator.h"
#include <set>
namespace fic::service::ssh {
enum class SshActivationIntent { SelectedPolicies, ConfigurationRelease };
}
namespace fic::service::ssh::detail {
// Bytes already checked against caller references. No filesystem enumeration,
// ownership enrollment or inferred reference digests in this classifier.
struct InputProfile {
    std::string unit, mainFile, base, fragments, environment, optionVariable;
    bool alt=false;
};
InputProfile inputProfile();
using InputBytes = std::map<std::string, std::string>;
struct Closure {
    std::vector<std::string> order;
    std::set<std::string> negativeSetDirectories;
    std::set<std::string> hostKeys;
};
Closure validateClosure(const ActivationRequest&, const InputBytes&, const std::map<std::string, std::string>& policies, const InputProfile& profile=inputProfile(), SshActivationIntent intent=SshActivationIntent::SelectedPolicies);
void validateCompatibleDropIn(const std::string& bytes);
void validateEmptyOptions(const std::string& bytes, const std::string& variable="SSHD_OPTS");
void validateLaunchProfile(const std::map<std::string, std::string>& launch, const InputProfile&, bool socketProfile);
std::set<std::string> discoverHostKeys(const ActivationRequest&, const InputBytes&,
    const std::map<std::string,std::string>& policies,SshActivationIntent intent=SshActivationIntent::SelectedPolicies);
void validatePolicies(const std::map<std::string, std::string>& policies,SshActivationIntent intent=SshActivationIntent::SelectedPolicies);
} // namespace fic::service::ssh::detail
