#ifndef FIC_PAM_MFA_TOPOLOGY_H
#define FIC_PAM_MFA_TOPOLOGY_H

#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"

#include <string>
#include <map>
#include <vector>

namespace fic::identity::pam {

inline constexpr char mfaSlotName[] = "fic-mfa";
inline constexpr char mfaNeutralSlot[] = "auth optional pam_deny.so\n";
inline constexpr char mfaIdentityGuard[] =
    "auth [success=ignore ignore=ignore default=die] pam_succeed_if.so user !~ */* quiet\n";
inline constexpr char mfaGoogleOptions[] =
    "pam_google_authenticator.so user=root secret=/etc/security/fic-mfa/totp-${USER} noskewadj";
inline const std::string mfaRequiredSlot =
    std::string(mfaIdentityGuard) + "auth [success=ok default=die] " + mfaGoogleOptions + "\n";
inline constexpr char mfaSshService[] = "fic-sshd-mfa";

// Bind parsed graph entries to the exact slot language. Reused by D13-1 so
// the independent blank-password proof can traverse a future MFA substack.
inline bool matchesMfaSlotRules(const std::vector<PamStackEntry>& entries,
                                const std::filesystem::path& path,
                                const std::string& content) {
    std::vector<PamRule> rules;
    std::string error;
    if (!PamConfiguration::parseRulesContent(path, content, rules, error) ||
        rules.size() != entries.size()) return false;
    for (std::size_t i = 0; i < rules.size(); ++i) {
        const auto& expected = rules[i];
        const auto& actual = entries[i].rule;
        if (actual.source != path || actual.includeKind != PamIncludeKind::None ||
            actual.group != expected.group || actual.module != expected.module ||
            actual.control != expected.control || actual.arguments != expected.arguments)
            return false;
    }
    return true;
}

enum class PamMfaFactor { GoogleTotp };
enum class PamMfaProofTarget { Candidate, Installed };

struct PamMfaTopology {
    std::string profile;
    std::string neutralSlot;
    std::string requiredSlot;
    std::string slotName;
    std::string attachment;
};

// Text only. The caller owns publication and must establish provenance.
bool buildDebian13MfaTopology(const std::vector<PamMfaFactor>& factors,
                             PamMfaTopology& topology, std::string& error);

bool buildDebian13MfaTopology(PamMfaForm form, bool hasSssdPasswordRoute,
                             PamMfaTopology& topology, std::string& error,
                             bool sshFaillock = false);

// StructuralEffective proof of a declared Debian 13 PAM service at the
// configuration snapshot. Candidate substitutes the canonical neutral slot
// in memory; Installed checks the exact effective provider rules on disk.
// Neither mode starts a service, authenticates users, or writes any files.
bool verifyDebian13Mfa(const fic::platform::PlatformProfile& platform,
                      const std::string& service, PamMfaProofTarget target,
                      std::string& error);

// The staged SSH proof is conditional on selector input. SSH attachment,
// effective AuthenticationMethods and runtime activation belong to D13-3B.
bool verifyDebian13Mfa(const fic::platform::PlatformProfile& platform,
                      const std::string& service, PamMfaProofTarget target,
                      PamMfaForm form, bool hasSssdPasswordRoute, std::string& error,
                      std::optional<fic::platform::PamFaillockStrategy> sshFaillock = {});

// Pinned input paths must be covered by the caller-authorized activation
// snapshot. This function checks necessary coverage and effective PAM graphs.
bool verifyDebian13SshMfaInputs(const fic::platform::PlatformProfile& platform, bool sssd,
                               std::optional<fic::platform::PamFaillockStrategy> faillock,
                               const std::map<std::string, std::string>& inputs,
                               std::string& error);

} // namespace fic::identity::pam
#endif
