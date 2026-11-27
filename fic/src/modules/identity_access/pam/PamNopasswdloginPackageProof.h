#ifndef FIC_PAM_NOPASSWDLOGIN_PACKAGE_PROOF_H
#define FIC_PAM_NOPASSWDLOGIN_PACKAGE_PROOF_H

#include "modules/identity_access/pam/PamNopasswdloginTransaction.h"
#include <fic/core/process/ProcessExecutor.h>

namespace fic::identity::pam {

using PamPackageQuery = std::function<ProcessResult(const std::vector<std::string>&)>;

// The query is the trusted platform package-query executable, not a shell.
// Hash the captured bytes, then let the transaction reprove their current inode.
bool provePackagedPamContent(
    const fic::platform::PamPlatformConfig::PasswordlessLoginTarget& target,
    fic::platform::PackageManagerKind kind, const std::string& content,
    const PamPackageQuery& query, std::string& error);

PamNopasswdloginOptions productionNopasswdloginOptions(
    const fic::platform::PamPlatformConfig& platform);

} // namespace fic::identity::pam
#endif
