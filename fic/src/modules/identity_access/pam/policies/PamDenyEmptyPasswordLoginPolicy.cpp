#include "modules/identity_access/pam/policies/PamDenyEmptyPasswordLoginPolicy.h"

#include "modules/identity_access/pam/PamEmptyPasswordLogin.h"
#include "rollback/DaemonMutationJournal.h"

#include <fic/policy/PolicyTypeValue.h>

PamDenyEmptyPasswordLoginPolicy::PamDenyEmptyPasswordLoginPolicy(
    fic::platform::PamPlatformConfig platform)
    : platform_(std::move(platform)) {
    policyName = fic::identity::pam::emptyPasswordPolicy;
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
}

bool PamDenyEmptyPasswordLoginPolicy::applyPam(const std::string& expectedValue) {
    std::string error;
    if (expectedValue != "ENABLE") {
        log("empty-password login policy requires ENABLE", logLevel::ERROR);
        return false;
    }
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if (!journal || !fic::identity::pam::applyEmptyPasswordLogin(platform_, *journal, error)) {
        log(error, logLevel::ERROR);
        return false;
    }
    return true;
}
