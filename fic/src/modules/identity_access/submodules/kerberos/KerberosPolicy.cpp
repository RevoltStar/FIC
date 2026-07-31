#include "modules/identity_access/submodules/kerberos/KerberosPolicy.h"

#include <mutex>

KerberosPolicy::KerberosPolicy()
    : IdentityAccessPolicy("KERBEROS") {
}

bool KerberosPolicy::apply() {
    const auto value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    const std::lock_guard<std::mutex> lock(this->configurationMutex());
    return this->applyKerberos(*value);
}
