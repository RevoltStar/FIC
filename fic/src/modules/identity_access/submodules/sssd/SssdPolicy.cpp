#include "modules/identity_access/submodules/sssd/SssdPolicy.h"

#include <mutex>
#include <utility>

SssdPolicy::SssdPolicy(
    fic::identity::sssd::SssdConfigurationOptions options)
    : IdentityAccessPolicy("SSSD"),
      configuration_(std::move(options)) {
}

bool SssdPolicy::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(this->configurationMutex());
    return this->applySssd(configuration_, *value);
}
