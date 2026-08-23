#ifndef FIC_IDENTITY_ACCESS_PAM_REQUIRED_PROVIDERS_H
#define FIC_IDENTITY_ACCESS_PAM_REQUIRED_PROVIDERS_H

#include "modules/identity_access/submodules/pam/PamProviderInspector.h"

#include <string>
#include <vector>

namespace fic::identity::pam {

bool parseRequiredPamProviders(const std::string& value,
                               std::vector<PamProviderKind>& providers,
                               std::string& normalized,
                               std::string& error);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_REQUIRED_PROVIDERS_H
