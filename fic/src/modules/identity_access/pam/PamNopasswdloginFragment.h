#ifndef FIC_PAM_NOPASSWDLOGIN_FRAGMENT_H
#define FIC_PAM_NOPASSWDLOGIN_FRAGMENT_H

#include "modules/identity_access/pam/PamConfiguration.h"
#include "rollback/MutationRecord.h"

namespace fic::identity::pam {

// Diagnose unsupported variants too, including pam_succeed_if group lists.
// This predicate never authorizes suppression; planning requires the exact rule.
bool referencesNopasswdlogin(const PamRule& rule);

// Pure fragment operations. File trust, projected effective-graph proof,
// journal admission and CAS belong to the transaction coordinator.
bool planNopasswdloginSuppression(
    const std::filesystem::path& source, const std::string& service,
    const std::string& content, std::optional<fic::rollback::UndoRestorePamSuppression>& plan,
    PamRule& target, std::string& error);

std::string nopasswdloginWrapper(
    fic::rollback::MutationId id, const fic::rollback::UndoRestorePamSuppression& proof);

bool restoreNopasswdloginFragment(
    const std::filesystem::path& source, const std::string& content,
    fic::rollback::MutationId id, const fic::rollback::UndoRestorePamSuppression& proof,
    std::string& restored, PamRule& target, std::string& error);

bool suppressNopasswdloginFragment(
    const std::filesystem::path& source, const std::string& content,
    fic::rollback::MutationId id, const fic::rollback::UndoRestorePamSuppression& proof,
    std::string& suppressed, std::string& error);

} // namespace fic::identity::pam
#endif
