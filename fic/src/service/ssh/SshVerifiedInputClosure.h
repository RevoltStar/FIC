#pragma once
#include "service/VerifiedConfigServiceActivator.h"
#include <set>
namespace fic::service::ssh::detail {
// Bytes already checked against caller references. No filesystem enumeration,
// ownership enrollment or inferred reference digests in this classifier.
using InputBytes = std::map<std::string, std::string>;
struct Closure {
    std::vector<std::string> order;
    std::set<std::string> negativeSetDirectories;
    std::set<std::string> hostKeys;
};
Closure validateClosure(const ActivationRequest&, const InputBytes&, const std::map<std::string, std::string>& policies);
void validateCompatibleDropIn(const std::string& bytes);
void validateEmptyOptions(const std::string& bytes);
void validateLaunchProfile(const std::map<std::string, std::string>& launch);
std::set<std::string> discoverHostKeys(const ActivationRequest&, const InputBytes&,
    const std::map<std::string,std::string>& policies);
void validatePolicies(const std::map<std::string, std::string>& policies);
} // namespace fic::service::ssh::detail
