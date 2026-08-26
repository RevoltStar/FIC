#include "modules/identity_access/kerberos/KerberosPolicy.h"

#include <mutex>
#include <utility>

KerberosPolicy::KerberosPolicy(
    fic::identity::kerberos::KerberosConfigurationOptions options)
    : IdentityAccessPolicy("KERBEROS"),
      configuration_(std::move(options)) {
}

bool KerberosPolicy::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(this->configurationMutex());
    return this->applyKerberos(configuration_, *value);
}
