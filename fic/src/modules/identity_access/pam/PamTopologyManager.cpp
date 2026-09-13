#include "modules/identity_access/pam/PamTopologyManager.h"

namespace fic::identity::pam {

bool PamTopologyManager::canEnableStrategy(
    fic::platform::PamFaillockStrategy,
    std::string& error) const {
    error = "this PAM topology manager does not support pam_faillock "
        "integration strategies";
    return false;
}

bool PamTopologyManager::enableStrategy(
    fic::platform::PamFaillockStrategy,
    std::string& error) {
    error = "this PAM topology manager does not support pam_faillock "
        "integration strategies";
    return false;
}

} // namespace fic::identity::pam