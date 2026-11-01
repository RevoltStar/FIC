// Historical pre-I6 specimen, TEST ONLY; not a production policy path.
#include "LegacySssdPolicyBase.h"

#include <mutex>
#include <utility>

LegacySssdPolicyBase::LegacySssdPolicyBase(
    fic::identity::sssd::SssdConfigurationOptions options)
    : IdentityAccessPolicy("SSSD"),
      configurationOptions_(options),
      configuration_(std::move(options)) {
}

bool LegacySssdPolicyBase::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(this->configurationMutex());
    return this->applySssd(configuration_, *value);
}
