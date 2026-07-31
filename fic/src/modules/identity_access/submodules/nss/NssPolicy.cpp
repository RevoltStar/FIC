#include "modules/identity_access/submodules/nss/NssPolicy.h"

#include <mutex>

NssPolicy::NssPolicy()
    : IdentityAccessPolicy("NSS") {
}

bool NssPolicy::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(this->configurationMutex());
    return this->applyNss(*value);
}
