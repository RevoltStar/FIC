#include "modules/identity_access/pam/policies/PamDisableNopasswdloginPolicy.h"
#include "modules/identity_access/pam/PamNopasswdloginTransaction.h"
#include "rollback/DaemonMutationJournal.h"
#include "modules/identity_access/pam/PamNopasswdloginPackageProof.h"

PamDisableNopasswdloginPolicy::PamDisableNopasswdloginPolicy(
    fic::platform::PamPlatformConfig platform)
    : platform_(std::move(platform)) {
    policyName = "disable_nopasswdlogin";
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
}

bool PamDisableNopasswdloginPolicy::applyPam(const std::string&) {
    std::string error;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if (!journal || platform_.passwordlessLoginTargets.empty()) {
        log("PAM suppression journal or platform unavailable: " + error, logLevel::ERROR);
        return false;
    }
    auto options = fic::identity::pam::productionNopasswdloginOptions(platform_);
    fic::identity::pam::PamNopasswdloginTransaction transaction(std::move(options), *journal);
    if (!transaction.apply(error)) {
        log("Could not suppress nopasswdlogin: " + error, logLevel::ERROR);
        return false;
    }
    return true;
}
