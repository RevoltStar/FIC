#include "modules/identity_access/submodules/sssd/SssdPolicy.h"

#include <mutex>

SssdPolicy::SssdPolicy()
    : IdentityAccessPolicy("SSSD") {
}

bool SssdPolicy::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(this->configurationMutex());
    return this->applySssd(*value);
}
