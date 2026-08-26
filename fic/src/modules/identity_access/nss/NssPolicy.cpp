#include "modules/identity_access/nss/NssPolicy.h"

#include <mutex>
#include <utility>

NssPolicy::NssPolicy(fic::identity::nss::NssConfigurationOptions options)
    : IdentityAccessPolicy("NSS"),
      configuration_(std::move(options)) {
}

bool NssPolicy::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(this->configurationMutex());
    return this->applyNss(configuration_, *value);
}
