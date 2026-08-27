#ifndef FIC_IDENTITY_ACCESS_PAM_REQUIRED_PROVIDERS_H
#define FIC_IDENTITY_ACCESS_PAM_REQUIRED_PROVIDERS_H

#include "modules/identity_access/pam/PamProviderInspector.h"

#include <string>
#include <vector>

namespace fic::identity::pam {

const std::vector<std::string>& requiredPamProviderNames();

bool parseRequiredPamProviders(const std::string& value,
                               std::vector<PamProviderKind>& providers,
                               std::string& normalized,
                               std::string& error);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_REQUIRED_PROVIDERS_H
