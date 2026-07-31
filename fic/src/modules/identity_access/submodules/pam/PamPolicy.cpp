#include "modules/identity_access/submodules/pam/PamPolicy.h"

#include <mutex>

PamPolicy::PamPolicy()
    : IdentityAccessPolicy("PAM") {
}

bool PamPolicy::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(this->configurationMutex());
    return this->applyPam(*value);
}
