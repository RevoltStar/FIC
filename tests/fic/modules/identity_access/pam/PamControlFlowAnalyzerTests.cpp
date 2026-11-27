#include "modules/identity_access/pam/PamNopasswdloginPackageProof.h"
#include "modules/identity_access/pam/PamNopasswdloginTransaction.h"
#include "modules/identity_access/pam/PamNopasswdloginFragment.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "../../../platform/SddmTestProfiles.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>

#include <unistd.h>

namespace fs = std::filesystem;

using fic::identity::pam::PamConfiguration;
using fic::identity::pam::PamControlFlowAnalysis;
using fic::identity::pam::PamControlFlowAnalyzer;
using fic::identity::pam::PamEffectiveStack;
using fic::identity::pam::PamFlowViolation;
using fic::identity::pam::PamFlowViolationKind;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const fs::path& path, const std::string& content) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not write " + path.string());
    output << content;
}

fic::platform::PamPlatformConfig makePlatform(const fs::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "security"};
    platform.scopes = {
        {fic::platform::PamScope::EffectiveAuthenticationStack, {"login"}},
        {fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
    platform.capabilities = {
        {fic::platform::PamCapability::AuthenticationLockout,
         fic::platform::PamProviderKind::PamFaillock,
         fic::platform::PamScope::EffectiveAuthenticationStack,
         root / "security/faillock.conf",
         fic::platform::PamTopologyStrategyKind::StaticVerifyOnly}};
    return platform;
}

fic::platform::PamPlatformConfig makeSddmPlatform(const fs::path& root) {
    auto platform = makePlatform(root);
    platform.scopes.front().services = {"sddm"};
    platform.trustedAuthenticationExclusions = {
        {"sddm", "pam_succeed_if.so",
         fic::platform::PamTrustedAuthenticationExclusionReason::
             ExplicitSubjectExclusion,
         "root", "required", {"user", "!=", "root", "quiet_success"},
         root / "pam.d/sddm", "common-auth", "requisite"}};
    return platform;
}

PamControlFlowAnalysis analyzeService(
    const fic::platform::PamPlatformConfig& platform,
    const std::string& service) {
    PamConfiguration configuration(platform);
    PamControlFlowAnalysis analysis;
    std::string error;
    require(PamControlFlowAnalyzer::analyze(
                configuration, platform, service,
                fic::platform::PamCapability::AuthenticationLockout,
                fic::platform::PamProviderKind::PamFaillock, analysis, error),
            error);
    return analysis;
}

std::optional<fic::platform::PamFaillockStrategy> detectStrategy(
    const fic::platform::PamPlatformConfig& platform,
    const std::string& service,
    std::string& error) {
    PamConfiguration configuration(platform);
    PamEffectiveStack stack;
    if (!configuration.buildEffectiveStack(
            service, fic::identity::pam::PamManagementGroup::Auth, stack,
            error)) {
        return std::nullopt;
    }
    return fic::identity::pam::detectPamFaillockStrategy(stack, error);
}

bool hasViolation(const PamControlFlowAnalysis& analysis,
                  PamFlowViolationKind kind) {
    return std::any_of(analysis.violations.begin(), analysis.violations.end(),
                       [kind](const PamFlowViolation& violation) {
                           return violation.kind == kind;
                       });
}

const std::string kDebianRequisite =
    "#%PAM-1.0\n"
    "auth requisite pam_faillock.so preauth\n"
    "auth [success=2 default=ignore] pam_unix.so nullok\n"
    "auth [default=die] pam_faillock.so authfail\n"
    "auth requisite pam_deny.so\n"
    "auth required pam_permit.so\n"
    "auth optional pam_cap.so\n";

const std::string kDebianRequired =
    "#%PAM-1.0\n"
    "auth required pam_faillock.so preauth\n"
    "auth [success=2 default=ignore] pam_unix.so nullok\n"
    "auth [default=die] pam_faillock.so authfail\n"
    "auth requisite pam_deny.so\n"
    "auth required pam_permit.so\n"
    "auth optional pam_cap.so\n";

const std::string kDebianAuthsucc =
    "#%PAM-1.0\n"
    "auth [success=2 default=ignore] pam_unix.so nullok\n"
    "auth [default=die] pam_faillock.so authfail\n"
    "auth requisite pam_deny.so\n"
    "auth required pam_permit.so\n"
    "auth required pam_faillock.so authsucc\n"
    "auth optional pam_cap.so\n";

const std::string kDebianRequisiteAccount =
    "account required pam_faillock.so\n"
    "account required pam_unix.so\n";

// PAM services on Debian/Ubuntu include the generated common-* files; the
// analyzer proves both the auth and the account stacks of the service.
void writeLoginWrapper(const fs::path& root) {
    writeFile(root / "pam.d/login",
              "auth include common-auth\n"
              "account include common-account\n");
}

void writeDebianFixture(const fs::path& root,
                        const std::string& authContent,
                        bool withAccountEnforcement) {
    writeLoginWrapper(root);
    writeFile(root / "pam.d/common-auth", authContent);
    writeFile(root / "pam.d/common-account",
              withAccountEnforcement ? kDebianRequisiteAccount
                                     : "account required pam_unix.so\n");
}

void testDetectPamFaillockStrategy(const fs::path& root) {
    std::string error;

    writeDebianFixture(root, kDebianRequisite, true);
    auto platform = makePlatform(root);
    auto strategy = detectStrategy(platform, "common-auth", error);
    require(strategy ==
                fic::platform::PamFaillockStrategy::PreauthRequisite,
            error);

    writeDebianFixture(root, kDebianRequired, true);
    strategy = detectStrategy(platform, "common-auth", error);
    require(strategy ==
                fic::platform::PamFaillockStrategy::PreauthRequired,
            error);

    writeDebianFixture(root, kDebianAuthsucc, false);
    strategy = detectStrategy(platform, "common-auth", error);
    require(strategy == fic::platform::PamFaillockStrategy::Authsucc,
            error);

    // Ambiguous: preauth and authsucc combined must fail closed.
    writeDebianFixture(root,
                       "auth requisite pam_faillock.so preauth\n"
                       "auth [default=die] pam_faillock.so authfail\n"
                       "auth required pam_faillock.so authsucc\n",
                       true);
    strategy = detectStrategy(platform, "common-auth", error);
    require(!strategy.has_value() && !error.empty(),
            "combined preauth and authsucc topology was not rejected");

    // Duplicated preauth rules must fail closed.
    writeDebianFixture(root,
                       "auth requisite pam_faillock.so preauth\n"
                       "auth required pam_faillock.so preauth\n"
                       "auth [default=die] pam_faillock.so authfail\n",
                       true);
    strategy = detectStrategy(platform, "common-auth", error);
    require(!strategy.has_value(),
            "duplicated preauth rules were not rejected");

    // Unsupported preauth control must fail closed.
    writeDebianFixture(root,
                       "auth [default=1] pam_faillock.so preauth\n"
                       "auth [default=die] pam_faillock.so authfail\n",
                       true);
    strategy = detectStrategy(platform, "common-auth", error);
    require(!strategy.has_value(),
            "unsupported preauth control was not rejected");

    // A topology without authfail accounting must fail closed.
    writeDebianFixture(root,
                       "auth requisite pam_faillock.so preauth\n",
                       true);
    strategy = detectStrategy(platform, "common-auth", error);
    require(!strategy.has_value(),
            "topology without authfail was not rejected");

    // No faillock at all must fail closed.
    writeDebianFixture(root, "auth required pam_unix.so nullok\n", false);
    strategy = detectStrategy(platform, "common-auth", error);
    require(!strategy.has_value(),
            "topology without pam_faillock was not rejected");
}

// The stacks pam-auth-update actually generates on Debian/Ubuntu for each
// strategy must be proven effective, including locked-user paths:
// preauth_requisite denies before the credential backend, preauth_required
// defers the denial to the account phase, and authsucc denies a locked user
// after the credential provider succeeded.
void testDebianGeneratedTopologiesAreEffective(const fs::path& root) {
    writeDebianFixture(root, kDebianRequisite, true);
    auto platform = makePlatform(root);
    auto analysis = analyzeService(platform, "login");
    require(analysis.effective,
            "Debian preauth_requisite stack was not proven effective: " +
                (analysis.violations.empty()
                    ? std::string()
                    : analysis.violations.front().message));

    writeDebianFixture(root, kDebianRequired, true);
    analysis = analyzeService(platform, "login");
    require(analysis.effective,
            "Debian preauth_required stack was not proven effective: " +
                (analysis.violations.empty()
                    ? std::string()
                    : analysis.violations.front().message));

    writeDebianFixture(root, kDebianAuthsucc, false);
    analysis = analyzeService(platform, "login");
    require(analysis.effective,
            "Debian authsucc stack was not proven effective: " +
                (analysis.violations.empty()
                    ? std::string()
                    : analysis.violations.front().message));
}

void testRecoverableFailureAccounting(const fs::path& root) {
    // provider FAILURE -> authfail -> provider SUCCESS -> overall SUCCESS:
    // a recoverable failure was already accounted.
    writeLoginWrapper(root);
    writeDebianFixture(root,
                       "auth [success=3 default=ignore] pam_unix.so nullok\n"
                       "auth [success=ok default=ignore] pam_faillock.so authfail\n"
                       "auth sufficient pam_sss.so use_first_pass\n"
                       "auth requisite pam_deny.so\n"
                       "auth required pam_permit.so\n"
                       "auth required pam_faillock.so authsucc\n",
                       false);
    auto platform = makePlatform(root);
    auto analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::RecoverableFailureAccounting),
            "recoverable failure accounting through a numeric-jump provider "
            "was not detected");

    // The same recovery reached through an included file.
    writeLoginWrapper(root);
    writeFile(root / "pam.d/common-auth",
              "auth [success=2 default=ignore] pam_unix.so nullok\n"
              "auth [success=ok default=ignore] pam_faillock.so authfail\n"
              "auth include common-auth-extras\n"
              "auth requisite pam_deny.so\n"
              "auth required pam_permit.so\n"
              "auth required pam_faillock.so authsucc\n");
    writeFile(root / "pam.d/common-auth-extras",
              "auth sufficient pam_sss.so use_first_pass\n");
    analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::RecoverableFailureAccounting),
            "recoverable failure accounting through an include was not "
            "detected");
}

void testPrematureSuccessAccounting(const fs::path& root) {
    // provider SUCCESS -> authsucc SUCCESS -> later gate FAILURE -> overall
    // FAILURE: success accounting (tally reset) happened prematurely.
    writeDebianFixture(root,
                       "auth [success=2 default=ignore] pam_unix.so nullok\n"
                       "auth [default=bad] pam_faillock.so authfail\n"
                       "auth requisite pam_deny.so\n"
                       "auth required pam_permit.so\n"
                       "auth required pam_faillock.so authsucc\n"
                       "auth required pam_access.so\n",
                       false);
    auto platform = makePlatform(root);
    auto analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::PrematureSuccessAccounting),
            "premature authsucc success accounting was not detected");

    // Same shape behind a substack boundary.
    writeFile(root / "pam.d/common-auth",
              "auth [success=2 default=ignore] pam_unix.so nullok\n"
              "auth [default=bad] pam_faillock.so authfail\n"
              "auth requisite pam_deny.so\n"
              "auth required pam_permit.so\n"
              "auth required pam_faillock.so authsucc\n"
              "auth substack common-auth-gate\n");
    writeFile(root / "pam.d/common-auth-gate",
              "auth required pam_access.so\n");
    analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::PrematureSuccessAccounting),
            "premature authsucc accounting behind a substack was not "
            "detected");
}

void testAltSshAuthsuccBeforeOuterNologinIsPremature(const fs::path& root) {
    // ALT's sshd stack obtains the password before entering the native
    // use_first_pass substack. An authsucc call inside system-auth therefore
    // clears the tally before control returns to the outer pam_nologin gate.
    writeFile(root / "pam.d/sshd",
              "#%PAM-1.0\n"
              "auth required pam_userpass.so\n"
              "auth include common-login-use_first_pass\n");
    writeFile(root / "pam.d/common-login-use_first_pass",
              "#%PAM-1.0\n"
              "auth substack system-auth-use_first_pass\n"
              "auth required pam_nologin.so\n");
    writeFile(root / "pam.d/system-auth-use_first_pass",
              "#%PAM-1.0\n"
              "auth include system-auth-use_first_pass-local-only\n");
    writeFile(root / "pam.d/system-auth-use_first_pass-local-only",
              "#%PAM-1.0\n"
              "auth [success=1 default=bad] pam_tcb.so shadow fork nullok "
              "use_first_pass\n"
              "auth [default=die] pam_faillock.so authfail\n"
              "auth [success=ok default=bad] pam_faillock.so authsucc\n");

    auto platform = makePlatform(root);
    platform.scopes.front().services = {"sshd"};
    const auto analysis = analyzeService(platform, "sshd");
    require(hasViolation(analysis,
                         PamFlowViolationKind::PrematureSuccessAccounting),
            "ALT sshd authsucc topology was accepted even though outer "
            "pam_nologin can fail after the tally reset");
}

void writeAltSssRouter(const fs::path& root, bool withLocalFaillock) {
    writeFile(root / "pam.d/system-auth",
              "auth include system-check-localuser\n"
              "auth substack system-auth-local-only\n"
              "auth [default=1] pam_permit.so\n"
              "auth substack system-auth-sss-only\n"
              "auth substack system-auth-common\n"
              "account include system-check-localuser\n"
              "account substack system-auth-local-only\n"
              "account [default=1] pam_permit.so\n"
              "account substack system-auth-sss-only\n"
              "account substack system-auth-common\n");
    writeFile(root / "pam.d/system-check-localuser",
              "auth [success=1 perm_denied=ignore default=die] "
              "pam_localuser.so\n"
              "auth [success=2 auth_err=ignore default=bad] "
              "pam_succeed_if.so uid >= 65536 quiet\n"
              "account [success=1 perm_denied=ignore default=die] "
              "pam_localuser.so\n"
              "account [success=2 auth_err=ignore default=bad] "
              "pam_succeed_if.so uid >= 65536 quiet\n");
    writeFile(root / "pam.d/system-auth-local-only",
              withLocalFaillock
                  ? "auth required pam_faillock.so preauth\n"
                    "auth [success=1 default=bad] pam_tcb.so shadow fork "
                    "nullok\n"
                    "auth [default=die] pam_faillock.so authfail\n"
                    "account required pam_faillock.so\n"
                    "account required pam_tcb.so shadow fork\n"
                  : "auth required pam_tcb.so shadow fork nullok\n"
                    "account required pam_tcb.so shadow fork\n");
    writeFile(root / "pam.d/system-auth-sss-only",
              "auth required pam_sss.so forward_pass\n"
              "account required pam_sss.so\n");
    writeFile(root / "pam.d/system-auth-common", "# empty\n");
}

void testAltLocalOnlyFaillockAcrossSssRouter(const fs::path& root) {
    auto platform = makePlatform(root);
    platform.scopes.front().services = {"system-auth"};
    platform.capabilities.front().topology =
        fic::platform::PamTopologyStrategyKind::AltTcbManaged;
    platform.capabilities.front().subjectScope =
        fic::platform::PamIdentitySubjectScope::LocalUsersOnly;

    writeAltSssRouter(root, true);
    auto analysis = analyzeService(platform, "system-auth");
    require(analysis.effective,
            "ALT SSS router required local pam_faillock on the remote "
            "pam_sss branch");

    writeAltSssRouter(root, false);
    analysis = analyzeService(platform, "system-auth");
    require(hasViolation(analysis,
                         PamFlowViolationKind::AuthenticationBypass),
            "ALT SSS router accepted a local branch without pam_faillock");
}

void testSddmRootExclusionWithAuthsucc(const fs::path& root) {
    fs::remove(root / "security/faillock.conf");
    writeFile(root / "pam.d/sddm",
              "#%PAM-1.0\n"
              "auth requisite pam_nologin.so\n"
              "auth required pam_succeed_if.so user != root quiet_success\n"
              "@include common-auth\n"
              "-auth optional pam_gnome_keyring.so\n"
              "-auth optional pam_kwallet5.so\n"
              "@include common-account\n");
    writeFile(root / "pam.d/common-auth", kDebianAuthsucc);
    writeFile(root / "pam.d/common-account",
              "account required pam_unix.so\n");

    auto platform = makeSddmPlatform(root);
    auto analysis = analyzeService(platform, "sddm");
    require(analysis.effective,
            "trusted SDDM root exclusion rejected authsucc with root "
            "lockout disabled: " +
                (analysis.violations.empty()
                     ? std::string()
                     : analysis.violations.front().message));
    require(!analysis.acceptedTrustedAuthenticationExclusions.empty() &&
                analysis.acceptedTrustedAuthenticationExclusions.front().
                    excludedUser == "root",
            "trusted SDDM root exclusion was not recorded in evidence");

    writeFile(root / "security/faillock.conf", "even_deny_root\n");
    analysis = analyzeService(platform, "sddm");
    require(hasViolation(analysis,
                         PamFlowViolationKind::PrematureSuccessAccounting),
            "authsucc reset of an excluded root tally was accepted while "
            "even_deny_root is enabled");

    // The hardening policy upgrades the narrowing gate to requisite. Root is
    // then rejected before common-auth, so authsucc cannot reset root's tally
    // even when even_deny_root is enabled.
    writeFile(root / "pam.d/sddm",
              "auth requisite pam_nologin.so\n"
              "auth requisite pam_succeed_if.so user != root quiet_success\n"
              "@include common-auth\n"
              "@include common-account\n");
    analysis = analyzeService(platform, "sddm");
    require(analysis.effective,
            "requisite SDDM root exclusion rejected safe authsucc topology");

    writeFile(root / "security/faillock.conf", "# even_deny_root\n");
    writeFile(root / "pam.d/sddm",
              "auth requisite pam_nologin.so\n"
              "auth required pam_succeed_if.so user != root quiet\n"
              "@include common-auth\n"
              "@include common-account\n");
    analysis = analyzeService(platform, "sddm");
    require(hasViolation(analysis,
                         PamFlowViolationKind::PrematureSuccessAccounting),
            "non-exact SDDM pam_succeed_if rule was trusted");
}

void testNativeSddmProfiles(const fs::path& root) {
    writeFile(root/"pam.d/common-session","session required pam_unix.so\n");
    writeFile(root/"pam.d/common-password","password required pam_unix.so\n");
    writeFile(root/"pam.d/common-auth",kDebianAuthsucc);
    writeFile(root/"pam.d/common-account","account required pam_unix.so\n");
    writeFile(root/"security/faillock.conf","even_deny_root\n");
    for(auto profile:sddmTestProfiles()) {
        auto platform=makeSddmPlatform(root);
        platform.trustedAuthenticationExclusions=profile.pam.trustedAuthenticationExclusions;
        require(platform.trustedAuthenticationExclusions.size()==1,profile.id+": missing exclusion");
        platform.trustedAuthenticationExclusions.front().source=root/"pam.d/sddm";
        auto content=nativeSddmFixture();writeFile(root/"pam.d/sddm",content);
        auto analysis=analyzeService(platform,"sddm");
        std::string detail;for(const auto& violation:analysis.violations)detail+=formatPamFlowViolation(violation)+"; ";
        require(!analysis.effective&&hasViolation(analysis,PamFlowViolationKind::PrematureSuccessAccounting),
            profile.id+": required gate hid premature success accounting: "+detail);
        const auto offset=content.find("required        pam_succeed_if.so");
        require(offset!=std::string::npos,"missing native gate");content.replace(offset,8,"requisite");
        writeFile(root/"pam.d/sddm",content);analysis=analyzeService(platform,"sddm");
        require(analysis.effective,profile.id+": requisite gate failed structural proof");
    }
    std::cout<<"Native Debian12/13 Ubuntu24.04/26.04 required/requisite CFG PASS\n";
}

void testAuthsuccDenialBypassDetected(const fs::path& root) {
    auto platform = makePlatform(root);

    // sufficient provider turns a denied authsucc into overall success. The
    // authsucc denial must be deliberately non-poisoning in this negative
    // fixture; with default=bad the required failure would correctly keep the
    // stack failed and there would be no bypass to detect.
    writeDebianFixture(root,
                       "auth [success=2 default=ignore] pam_unix.so nullok\n"
                       "auth [default=bad] pam_faillock.so authfail\n"
                       "auth requisite pam_deny.so\n"
                       "auth required pam_permit.so\n"
                       "auth [success=ok auth_err=ignore default=bad] pam_faillock.so "
                       "authsucc\n"
                       "auth sufficient pam_sss.so use_first_pass\n",
                       false);
    auto analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::AuthenticationBypass),
            "sufficient bypass of the authsucc denial was not detected");

    // done extended control terminates a denied path with success.
    writeDebianFixture(root,
                       "auth [success=2 default=ignore] pam_unix.so nullok\n"
                       "auth [default=bad] pam_faillock.so authfail\n"
                       "auth requisite pam_deny.so\n"
                       "auth required pam_permit.so\n"
                       "auth [success=ok auth_err=ignore default=bad] pam_faillock.so "
                       "authsucc\n"
                       "auth [success=done default=bad] pam_sss.so "
                       "use_first_pass\n",
                       false);
    analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::AuthenticationBypass),
            "done bypass of the authsucc denial was not detected");

    // reset extended control rolls the denial back.
    writeDebianFixture(root,
                       "auth [success=2 default=ignore] pam_unix.so nullok\n"
                       "auth [default=bad] pam_faillock.so authfail\n"
                       "auth requisite pam_deny.so\n"
                       "auth required pam_permit.so\n"
                       "auth [success=ok auth_err=reset] pam_faillock.so "
                       "authsucc\n"
                       "auth optional pam_cap.so\n",
                       false);
    analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::AuthenticationBypass),
            "reset bypass of the authsucc denial was not detected");

    // numeric jump skips the modules that would enforce the denial.
    writeDebianFixture(root,
                       "auth [success=2 default=ignore] pam_unix.so nullok\n"
                       "auth [default=bad] pam_faillock.so authfail\n"
                       "auth requisite pam_deny.so\n"
                       "auth required pam_permit.so\n"
                       "auth [success=ok auth_err=2] pam_faillock.so "
                       "authsucc\n"
                       "auth required pam_access.so\n"
                       "auth optional pam_cap.so\n",
                       false);
    analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::AuthenticationBypass),
            "numeric-jump bypass of the authsucc denial was not detected");

    // include pulling in a sufficient provider after the denial.
    writeFile(root / "pam.d/common-auth",
              "auth [success=2 default=ignore] pam_unix.so nullok\n"
              "auth [default=bad] pam_faillock.so authfail\n"
              "auth requisite pam_deny.so\n"
              "auth required pam_permit.so\n"
              "auth [success=ok auth_err=ignore default=bad] pam_faillock.so authsucc\n"
              "auth include common-auth-extras\n");
    writeFile(root / "pam.d/common-auth-extras",
              "auth sufficient pam_sss.so use_first_pass\n");
    analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::AuthenticationBypass),
            "include bypass of the authsucc denial was not detected");

    // substack with a sufficient provider after the denial.
    writeFile(root / "pam.d/common-auth",
              "auth [success=2 default=ignore] pam_unix.so nullok\n"
              "auth [default=bad] pam_faillock.so authfail\n"
              "auth requisite pam_deny.so\n"
              "auth required pam_permit.so\n"
              "auth [success=ok auth_err=ignore default=bad] pam_faillock.so authsucc\n"
              "auth substack common-auth-extras\n");
    writeFile(root / "pam.d/common-auth-extras",
              "auth sufficient pam_sss.so use_first_pass\n");
    analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::AuthenticationBypass),
            "substack bypass of the authsucc denial was not detected");
}

void testProviderUnreachableAfterAuthfail(const fs::path& root) {
    // A credential provider after the authfail accounting rule can never be
    // reached: failure would be accounted even though it is recoverable by
    // that provider.
    writeDebianFixture(root,
                       "auth [success=2 default=ignore] pam_unix.so nullok\n"
                       "auth [default=die] pam_faillock.so authfail\n"
                       "auth sufficient pam_sss.so use_first_pass\n"
                       "auth requisite pam_deny.so\n"
                       "auth required pam_permit.so\n"
                       "auth required pam_faillock.so authsucc\n",
                       false);
    auto platform = makePlatform(root);
    auto analysis = analyzeService(platform, "login");
    require(hasViolation(analysis,
                         PamFlowViolationKind::ProviderUnreachable),
            "credential provider after authfail was not detected as "
            "unreachable");
}

// ---------------------------------------------------------------------------
// Rule G password-flow tests (P1-2 hardening): symbolic control-flow proofs
// for quality/history enforcement. Every fixture keeps quality textually
// BEFORE history where relevant — the tests prove that verdicts come from
// the control flow, not from textual index ordering.
// ---------------------------------------------------------------------------

void writePasswordFlowFixture(const fs::path& root,
                              const std::string& stackContent) {
    writeFile(root / "pam.d/passwd", stackContent);
    writeFile(root / "security/pam_unix.so", "fixture\n");
    writeFile(root / "security/pam_pwquality.so", "fixture\n");
    writeFile(root / "security/pam_pwhistory.so", "fixture\n");
}

fic::platform::PamPlatformConfig makePasswordFlowPlatform(
    const fs::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "security"};
    platform.scopes = {
        {fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
    return platform;
}

fic::identity::pam::PamPasswordFlowAnalysis analyzePasswordFlowFixture(
    const fs::path& root, const std::string& stackContent,
    fic::identity::pam::PamPasswordFlowRequirements requirements = {true, true}) {
    writePasswordFlowFixture(root, stackContent);
    auto platform = makePasswordFlowPlatform(root);
    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamEffectiveStack stack;
    std::string error;
    require(configuration.buildEffectiveStack(
                "passwd",
                fic::identity::pam::PamManagementGroup::Password,
                stack, error),
            error);
    fic::identity::pam::PamPasswordFlowAnalysis analysis;
    require(fic::identity::pam::analyzePasswordFlow(
                stack, platform, requirements, analysis, error),
            error);
    return analysis;
}

void testConditionalPasswordRequirements(const fs::path& root) {
    const std::string qualityOnly =
        "password requisite pam_pwquality.so retry=3\n"
        "password required pam_unix.so\n";
    auto analysis = analyzePasswordFlowFixture(root, qualityOnly, {true, false});
    require(analysis.qualityNonBypassable && !analysis.historyNonBypassable &&
                analysis.violations.empty(), "quality-only incorrectly requires history");
    analysis = analyzePasswordFlowFixture(root, qualityOnly, {true, true});
    require(!analysis.violations.empty(), "required history absence accepted");
    analysis = analyzePasswordFlowFixture(root,
        "password requisite pam_pwhistory.so use_authtok\n"
        "password required pam_unix.so\n", {false, true});
    require(!analysis.historyAlwaysHasTokenProducer && !analysis.violations.empty(),
            "history requires a prior producer even when quality is not required");
    analysis = analyzePasswordFlowFixture(root,
        "password requisite pam_pwquality.so\n"
        "password requisite pam_pwhistory.so\n"
        "password required pam_unix.so\n", {true, true});
    require(!analysis.historyNonBypassable && !analysis.violations.empty(),
            "history without use_authtok counted as enforcement");
    analysis = analyzePasswordFlowFixture(root,
        "password optional pam_pwquality.so\n"
        "password required pam_unix.so\n", {true, false});
    require(!analysis.qualityNonBypassable && !analysis.violations.empty(),
            "quality-only bypass accepted");
    analysis = analyzePasswordFlowFixture(root,
        "password required pam_unix.so\n", {false, false});
    require(analysis.violations.empty(), "unrequired properties created violations");
}

// G1 positive: producer proven, history non-bypassable, token produced on
// every successful path before the history rule.
void testPasswordFlowPositive(const fs::path& root) {
    const auto analysis = analyzePasswordFlowFixture(
        root,
        "password requisite pam_pwquality.so retry=3\n"
        "password requisite pam_pwhistory.so use_authtok\n"
        "password required pam_unix.so use_authtok\n");
    require(analysis.violations.empty(),
            "G1 positive flow reported violations");
    require(analysis.qualityNonBypassable,
            "G1: quality bypassability not disproven");
    require(analysis.historyNonBypassable,
            "G1: history bypassability not disproven");
    require(analysis.historyAlwaysHasTokenProducer,
            "G1: token producer invariant not proven");
}

// G2 producer bypass: quality textually before history, but an earlier
// success jump skips the quality rule — a successful path exists without
// the quality/token producer. This proves the implementation is no longer
// index-based.
void testPasswordFlowProducerBypass(const fs::path& root) {
    const auto analysis = analyzePasswordFlowFixture(
        root,
        "password [success=1 default=ignore] pam_permit.so\n"
        "password requisite pam_pwquality.so retry=3\n"
        "password requisite pam_pwhistory.so use_authtok\n"
        "password required pam_unix.so use_authtok\n");
    require(!analysis.qualityNonBypassable,
            "G2: producer bypass not detected");
    require(!analysis.violations.empty(),
            "G2: bypass flow must report a violation");
}

// G2b history bypass: quality runs, but its success action jumps over the
// history rule — history enforcement is bypassed while textual order stays
// "correct" (quality before history).
void testPasswordFlowHistoryBypass(const fs::path& root) {
    const auto analysis = analyzePasswordFlowFixture(
        root,
        "password [success=1 default=ignore] pam_pwquality.so retry=3\n"
        "password requisite pam_pwhistory.so use_authtok\n"
        "password required pam_unix.so use_authtok\n");
    require(!analysis.historyNonBypassable,
            "G2b: history bypass (jump over pwhistory) not detected");
    require(!analysis.violations.empty(),
            "G2b: bypass flow must report a violation");
}

// G2c token-state: a successful path reaches the history rule while the
// quality producer did not succeed on that same path.
void testPasswordFlowTokenProducerBypass(const fs::path& root) {
    const auto analysis = analyzePasswordFlowFixture(
        root,
        "password [success=1 default=ignore] pam_permit.so\n"
        "password requisite pam_pwquality.so retry=3\n"
        "password requisite pam_pwhistory.so use_authtok\n"
        "password required pam_unix.so use_authtok\n");
    require(!analysis.historyAlwaysHasTokenProducer,
            "G2c: token producer bypass not detected");
}

// G4 normal ordering reversed: history before quality — the history rule
// runs (successfully: use_authtok only sets the new token) BEFORE any
// producer success exists, so the token invariant cannot hold; the flow is
// rejected.
void testPasswordFlowHistoryBeforeProducer(const fs::path& root) {
    const auto analysis = analyzePasswordFlowFixture(
        root,
        "password requisite pam_pwhistory.so use_authtok\n"
        "password requisite pam_pwquality.so retry=3\n"
        "password required pam_unix.so use_authtok\n");
    // The history rule succeeds on the happy path BEFORE the quality
    // producer runs; the token-state proof must reject this topology.
    require(!analysis.historyAlwaysHasTokenProducer,
            "G4: history-before-producer topology not rejected");
}

// G5 unknown/unrepresentable control syntax: fail closed. The analyzer's
// control parser rejects the unknown result token during the symbolic
// execution (after stack construction): analyzePasswordFlow reports the
// error and no security verdict is produced (never a safe one).
void testPasswordFlowUnknownControl(const fs::path& root) {
    writePasswordFlowFixture(
        root,
        "password requisite pam_pwquality.so retry=3\n"
        "password requisite pam_pwhistory.so use_authtok\n"
        "password [bogus=1] pam_unix.so use_authtok\n");
    auto platform = makePasswordFlowPlatform(root);
    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamEffectiveStack stack;
    std::string error;
    require(configuration.buildEffectiveStack(
                "passwd", fic::identity::pam::PamManagementGroup::Password,
                stack, error),
            error);
    fic::identity::pam::PamPasswordFlowAnalysis analysis;
    std::string flowError;
    require(!fic::identity::pam::analyzePasswordFlow(
                stack, platform, {true, true}, analysis, flowError),
            "unknown control syntax must not produce a verdict");
    require(!flowError.empty(),
            "unknown control syntax must report an error");
}

// G6 no successful path provable at all: fail closed.
void testPasswordFlowNoSuccessfulPath(const fs::path& root) {
    const auto analysis = analyzePasswordFlowFixture(
        root,
        "password requisite pam_deny.so\n"
        "password required pam_permit.so\n");
    require(!analysis.violations.empty(),
            "G6: flow without a provable successful path must fail closed");
}

// G7 substack boundaries: a history rule inside its own substack scope is
// still proven non-bypassable on the successful path.
void testPasswordFlowSubstackJump(const fs::path& root) {
    writePasswordFlowFixture(
        root,
        "password requisite pam_pwquality.so retry=3\n"
        "password substack secret-branch\n"
        "password required pam_unix.so use_authtok\n");
    writeFile(root / "pam.d/secret-branch",
              "password requisite pam_pwhistory.so use_authtok\n"
              "password required pam_permit.so\n");
    auto platform = makePasswordFlowPlatform(root);
    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamEffectiveStack stack;
    std::string error;
    require(configuration.buildEffectiveStack(
                "passwd", fic::identity::pam::PamManagementGroup::Password,
                stack, error),
            error);
    fic::identity::pam::PamPasswordFlowAnalysis analysis;
    require(fic::identity::pam::analyzePasswordFlow(
                stack, platform, {true, true}, analysis, error),
            error);
    require(analysis.violations.empty(),
            "G7: substack-scoped history rule was misjudged: " +
                (analysis.violations.empty()
                     ? std::string()
                     : analysis.violations.front().message));
    require(analysis.historyNonBypassable,
            "G7: history inside a substack must still be enforced");
    require(analysis.historyAlwaysHasTokenProducer,
            "G7: token producer invariant must hold across substacks");
}

void testEmptyUnixPasswordPaths() {
    using namespace fic::identity::pam;
    const auto check = [](const std::string& primary,
                          const std::vector<std::string>& tail, bool expected) {
        PamEffectiveStack stack;
        stack.service = "login";
        std::string error;
        const auto append = [&](const std::string& line) {
            std::vector<PamRule> parsed;
            require(PamConfiguration::parseRulesContent("login", line, parsed, error), error);
            stack.entries.push_back({parsed.front(), {}});
        };
        append(primary);
        for (const auto& rule : tail) append(rule);
        bool safe = false;
        require(proveNoEmptyUnixPasswordPath(stack, {}, safe, error), error);
        require(safe == expected, "unexpected blank-password verdict: " + primary);
    };
    check("auth required pam_unix.so\n", {}, true);
    for (const std::string option : {"nullok", "nullok_secure", "nullresetok"}) {
        const auto unixPrimary = "auth [success=1 default=ignore] pam_unix.so " + option + "\n";
        const std::string deny = "auth requisite pam_deny.so\n";
        const std::string permit = "auth required pam_permit.so\n";
        const std::string strict = "auth [success=ok default=die] pam_unix.so use_first_pass\n";
        check(unixPrimary, {deny, permit}, false);
        check(unixPrimary, {deny, permit, strict}, true);
        check("auth sufficient pam_unix.so " + option + "\n", {strict}, false);
        check("auth [success=2 default=ignore] pam_unix.so " + option + "\n",
              {deny, strict, permit}, false);
    }
}

void testMfaAuthenticationPaths() {
    using namespace fic::identity::pam;
    const auto check = [](const std::string& before, const std::string& otp,
                          const std::string& after, bool expected) {
        const auto parse = [](const fs::path& file, const std::string& text,
                              std::vector<PamStackEntry>& entries) {
            std::vector<PamRule> rules;
            std::string error;
            require(PamConfiguration::parseRulesContent(file, text, rules, error), error);
            for (auto& rule : rules) entries.push_back({std::move(rule), {}});
        };
        PamEffectiveStack stack;
        stack.service = "login";
        parse("common-auth", before, stack.entries);
        parse("common-auth", "auth substack fic-mfa\n", stack.entries);
        parse("fic-mfa", otp, stack.entries.back().substack);
        parse("common-auth", after, stack.entries);
        std::string error;
        require(proveMfaAuthenticationPaths(stack, {}, "common-auth", "fic-mfa", false, error)
                    == expected,
                "unexpected MFA path verdict: " + error);
    };
    const std::string strict = "auth required pam_unix.so\n";
    const std::string mfa = "auth [success=ok default=die] pam_google_authenticator.so\n";
    check(strict, mfa, "", true);
    check("auth required pam_unix.so nullok\n", mfa, "", false);
    check("auth sufficient pam_unix.so\n", mfa, "", false);
    check("auth optional pam_unix.so\n", mfa, "", false);
    check(strict, "auth [success=ok ignore=ignore default=die] pam_google_authenticator.so\n", "", false);
    check(strict, mfa, "auth [success=reset default=ignore] pam_permit.so\n", false);
}

void testRuleSuppressionProof(const fs::path& root) {
    using namespace fic::identity::pam;
    const auto platform = makePlatform(root / "suppression");
    const auto path = platform.configDirectories.front() / "login";
    const std::string prefix = "auth required pam_shells.so\n";
    const std::string bypass =
        "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\n";
    const std::string suffix = "auth required pam_unix.so\n";
    auto stack = [&](const std::string& content) {
        PamConfiguration configuration(platform);
        std::string error;
        require(configuration.projectService("login", content, error), error);
        PamEffectiveStack result;
        require(configuration.buildEffectiveStack("login", PamManagementGroup::Auth,
                                                  result, error), error);
        return result;
    };
    auto original = stack(prefix + bypass + suffix);
    const auto target = original.entries.at(1).rule;
    auto suppressed = stack(prefix + "# owned suppression\n" + suffix);
    std::string error;
    require(provePamRuleSuppression(original, suppressed, target, error), error);
    auto changed = stack(prefix + "auth optional pam_unix.so\n");
    require(!provePamRuleSuppression(original, changed, target, error),
            "changing adjacent enforcement must fail");
    auto inserted = stack(prefix + "auth sufficient pam_permit.so\n" + suffix);
    require(!provePamRuleSuppression(original, inserted, target, error),
            "inserting another bypass must fail");
    require(!provePamRuleSuppression(original, original, target, error),
            "unchanged graph must not prove suppression");
    auto jumped = stack("auth [success=1 default=ignore] pam_permit.so\n" + bypass + suffix);
    auto jumpedSuppressed = stack("auth [success=1 default=ignore] pam_permit.so\n" + suffix);
    require(!provePamRuleSuppression(jumped, jumpedSuppressed,
                                     jumped.entries.at(1).rule, error),
            "numeric jump target changes must fail");
    auto laterJump = stack(prefix + bypass +
        "auth [success=1 default=ignore] pam_unix.so\nauth requisite pam_deny.so\n"
        "auth required pam_permit.so\n");
    auto laterJumpSuppressed = stack(prefix +
        "auth [success=1 default=ignore] pam_unix.so\nauth requisite pam_deny.so\n"
        "auth required pam_permit.so\n");
    require(provePamRuleSuppression(laterJump, laterJumpSuppressed,
                                    laterJump.entries.at(1).rule, error),
            "jumps after suppression preserve their targets: " + error);
    auto terminal = stack(prefix + bypass);
    require(!provePamRuleSuppression(terminal, stack(prefix),
                                     terminal.entries.back().rule, error),
            "terminal bypass without fallback must fail");
    writeFile(path.parent_path() / "nested",
              "auth [success=1 default=ignore] pam_unix.so\n"
              "auth requisite pam_deny.so\nauth required pam_permit.so\n");
    const std::string nested = "auth substack nested\n";
    original = stack(prefix + bypass + nested);
    suppressed = stack(prefix + nested);
    require(provePamRuleSuppression(original, suppressed,
                                    original.entries.at(1).rule, error),
            "jumps inside an unchanged substack must remain supported: " + error);
    const auto saved = original.entries.at(1);
    original.entries.push_back(saved);
    require(!provePamRuleSuppression(original, suppressed, saved.rule, error),
            "repeated included target must fail");
}

void testNopasswdloginFragment() {
    using namespace fic::identity::pam;
    const fs::path source = "/etc/pam.d/lightdm";
    const std::string prefix = "# administrator\nauth required pam_shells.so\n";
    const std::string raw =
        "auth\t sufficient\t pam_succeed_if.so user ingroup nopasswdlogin # kept\n";
    const std::string suffix = "# separator\nauth include common-auth\naccount required pam_permit.so\n";
    const auto original = prefix + raw + suffix;
    std::optional<fic::rollback::UndoRestorePamSuppression> proof;
    PamRule target;
    std::string error, suppressed, restored;
    require(planNopasswdloginSuppression(source, "lightdm", original, proof, target, error), error);
    require(proof && proof->original == raw, "original formatting must survive planning");
    const std::string continued =
        std::string("auth sufficient pam_succeed_if.so user ") + char(92) +
        "\n ingroup nopasswdlogin\n";
    std::optional<fic::rollback::UndoRestorePamSuppression> multiline;
    require(planNopasswdloginSuppression(source, "lightdm", prefix + continued + suffix,
                                        multiline, target, error), error);
    require(multiline && multiline->original == continued && target.endLine == target.line + 1,
            "parser must expose the whole logical rule");
    require(suppressNopasswdloginFragment(source, prefix + continued + suffix, 19,
                                          *multiline, suppressed, error), error);
    std::vector<PamRule> active;
    require(PamConfiguration::parseRulesContent(source, suppressed, active, error), error);
    require(std::none_of(active.begin(), active.end(), [](const PamRule& rule) {
        return std::find(rule.arguments.begin(), rule.arguments.end(), "nopasswdlogin") !=
            rule.arguments.end();
    }), "all continued physical lines must be suppressed");
    require(restoreNopasswdloginFragment(source, suppressed, 19, *multiline,
                                         restored, target, error), error);
    require(restored == prefix + continued + suffix, "continued rule must round trip exactly");
    const auto saved = *proof;
    require(suppressNopasswdloginFragment(source, original, 17, saved, suppressed, error), error);
    require(restoreNopasswdloginFragment(source, suppressed, 17, saved, restored, target, error), error);
    require(restored == original, "suppression round trip must preserve all bytes");
    auto adjacent = "# another administrator comment\n" + suppressed;
    require(restoreNopasswdloginFragment(source, adjacent, 17, saved, restored, target, error), error);
    require(restored == "# another administrator comment\n" + original, "release must retain adjacent changes");
    require(!restoreNopasswdloginFragment(source, suppressed, 18, saved, restored, target, error),
            "wrong mutation id must fail");
    require(!restoreNopasswdloginFragment(source, suppressed + nopasswdloginWrapper(17, saved),
                                         17, saved, restored, target, error), "duplicate marker must fail");
    auto damaged = suppressed;
    damaged.replace(damaged.find("# kept"), 6, "# changed");
    require(!restoreNopasswdloginFragment(source, damaged, 17, saved, restored, target, error),
            "modified suppressed bytes must fail");
    auto moved = prefix + suffix + nopasswdloginWrapper(17, saved);
    require(!restoreNopasswdloginFragment(source, moved, 17, saved, restored, target, error),
            "moved wrapper must fail");
    const auto duplicateAnchors = prefix + suffix;
    require(!planNopasswdloginSuppression(source, "lightdm", original + duplicateAnchors,
                                         proof, target, error),
            "ambiguous anchor pair must refuse initial ownership");
    require(!restoreNopasswdloginFragment(source, suppressed + duplicateAnchors,
                                         17, saved, restored, target, error),
            "new duplicate anchor pair must refuse ambiguous release");
    require(!restoreNopasswdloginFragment(source, prefix + suffix + prefix +
                                         nopasswdloginWrapper(17, saved) + suffix,
                                         17, saved, restored, target, error),
            "moving a wrapper to an identical anchor pair must fail");
    require(!suppressNopasswdloginFragment(source, original, 0, saved, suppressed, error),
            "zero mutation id must fail");
    require(planNopasswdloginSuppression(source, "lightdm", prefix + "# " + raw + suffix,
                                        proof, target, error) && !proof,
            "administrator-commented rule must be a no-op");
    require(!planNopasswdloginSuppression(source, "lightdm",
                                         prefix + raw + raw + suffix, proof, target, error),
            "duplicate active bypass must fail");
    require(!planNopasswdloginSuppression(source, "lightdm",
                                         prefix + "auth optional pam_succeed_if.so user ingroup nopasswdlogin\n" + suffix,
                                         proof, target, error),
            "unsupported control must fail");
    require(!planNopasswdloginSuppression(source, "lightdm", prefix +
                "auth sufficient pam_succeed_if.so user ingroup wheel:nopasswdlogin\n" + suffix,
                proof, target, error), "unsupported group list must fail");
    require(planNopasswdloginSuppression(source, "lightdm", prefix +
                "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin-other\n" + suffix,
                proof, target, error) && !proof, "different group name must remain outside the contract");
}

void testNopasswdloginTransaction(const fs::path& root) {
    using namespace fic::identity::pam;
    using namespace fic::rollback;
    const auto directory = root / "transaction";
    auto platform = makePlatform(directory);
    const auto service = platform.configDirectories.front() / "lightdm";
    const std::string bypass = "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\n";
    const std::string original = "auth required pam_shells.so\n" + bypass +
        "auth required pam_unix.so\n";
    writeFile(service, original);
    MutationJournal journal(directory / "journal");
    std::string error;
    require(journal.load(error), error);
    PamNopasswdloginOptions options;
    options.platform = platform;
    options.services = {"lightdm", "sddm"};
    PamNopasswdloginTransaction transaction(options, journal);
    require(transaction.apply(error), error);
    const auto bytes = [&] {
        std::ifstream file(service);
        return std::string(std::istreambuf_iterator<char>(file), {});
    };
    auto suppressed = bytes();
    require(suppressed.find("# FIC_PAM_NOPASSWDLOGIN BEGIN") != std::string::npos, "wrapper missing");
    require(journal.records().size() == 1 && journal.records()[0].status == MutationStatus::Applied,
            "apply must commit one record");
    require(transaction.apply(error), error);
    require(bytes() == suppressed && journal.records().size() == 1, "reapply must be a no-op");
    auto differentDomain = options;
    differentDomain.services = {"sddm"};
    PamNopasswdloginTransaction wrongPlatform(differentDomain, journal);
    require(!wrongPlatform.apply(error), "an active resource outside the platform domain must fail");
    require(bytes() == suppressed, "wrong platform must retain physical ownership");

    writeFile(service, "# administrator\n" + suppressed);
    require(transaction.release(journal.records()[0], error), error);
    require(bytes() == "# administrator\n" + original, "release must preserve administrator bytes");
    require(transaction.apply(error), error);
    auto owned = journal.records().back();
    // Simulate restart between durable Prepared and physical publication.
    require(transaction.release(owned, error), error);
    require(transaction.apply(error), error);
    owned = journal.records().back();
    require(journal.setStatus(owned.id, MutationStatus::Prepared, error), error);
    require(transaction.apply(error), error);
    require(journal.records().back().status == MutationStatus::Applied, "published Prepared must recover");
    require(transaction.release(journal.records().back(), error), error);
    const auto beforeFailure = bytes();
    options.writer = [](const std::string& path, const std::string& content,
                        const AtomicWriteOptions& opts, std::string* message) {
        if (!AtomicFileWriter::write(path, content, opts, message)) return false;
        *message = "injected post-publication error";
        return false;
    };
    PamNopasswdloginTransaction failed(options, journal);
    require(!failed.apply(error), "post-publication failure must be reported");
    // Failed compensation also publishes its restored bytes. Recovery resolves
    // its durable releasing record on the next ordinary apply.
    options.writer = AtomicFileWriter::write;
    PamNopasswdloginTransaction recovered(options, journal);
    require(recovered.apply(error), error);
    require(recovered.release(journal.records().back(), error), error);
    require(bytes() == beforeFailure, "recovery must restore the original fragment");
    // Refuse external replacement without stock proof.
    require(recovered.apply(error), error);
    owned = journal.records().back();
    writeFile(service, original);
    require(!recovered.release(owned, error), "unknown replacement must retain conflict");
    options.proveStock = [&](const fs::path& path, const std::string& content, std::string&) {
        return path == service && content == original;
    };
    PamNopasswdloginTransaction stock(options, journal);
    require(stock.release(owned, error), error);
    require(bytes() == original, "stock release must not write historical data");
    // Unsupported included rule must be diagnosed without adopting the include.
    writeFile(service, "auth include nested\n");
    writeFile(service.parent_path() / "nested", bypass + "auth required pam_unix.so\n");
    require(!stock.apply(error), "included foreign bypass must fail");
    writeFile(service.parent_path() / "nested",
              "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin:wheel\n"
              "auth required pam_unix.so\n");
    require(!stock.apply(error), "included unsupported group list must fail");
    writeFile(service, original);
    writeFile(service.parent_path() / "sddm",
              "auth optional pam_succeed_if.so user ingroup nopasswdlogin\n"
              "auth required pam_unix.so\n");
    const auto initialRecords = journal.records().size();
    require(!stock.apply(error), "second service failure must be reported");
    require(bytes() == original, "second service failure must compensate new first-service effect");
    require(journal.records().size() == initialRecords + 1 &&
            journal.records().back().status == MutationStatus::RolledBack,
            "compensated effect must close its journal cycle");
    fs::remove(service.parent_path() / "sddm");
    // A third-party edit after publication prevents whole-call compensation.
    options.writer = [&](const std::string& path, const std::string& content,
                         const AtomicWriteOptions& opts, std::string* message) {
        if (!AtomicFileWriter::write(path, content, opts, message)) return false;
        writeFile(path, "# concurrent administrator\n" + content);
        *message = "injected concurrent writer";
        return false;
    };
    PamNopasswdloginTransaction concurrent(options, journal);
    require(!concurrent.apply(error), "concurrent publication must report failure");
    require(bytes().find("# concurrent administrator\n") == 0,
            "compensation must preserve third-party writes");
    require(journal.records().back().isActive(), "uncertain effect must retain provenance");
    options.writer = AtomicFileWriter::write;
    PamNopasswdloginTransaction retried(options, journal);
    require(retried.apply(error), error);
    require(retried.release(journal.records().back(), error), error);
    require(bytes() == "# concurrent administrator\n" + original,
            "scoped release must preserve concurrent administrator changes");
    require(retried.release(journal.records().back(), error), "release must be idempotent");
    // Recover a Prepared intent that never published its physical marker.
    std::optional<UndoRestorePamSuppression> planned;
    PamRule plannedTarget;
    require(planNopasswdloginSuppression(service, "lightdm", bytes(), planned, plannedTarget, error), error);
    MutationRecord intent;
    intent.policy = {"IDENTITY_ACCESS", "PAM", "disable_nopasswdlogin"};
    intent.resource = "lightdm";
    intent.undo.backend = MutationBackend::PamSuppression;
    intent.undo.payload = *planned;
    MutationId intentId = 0;
    require(journal.prepareMutation(intent, intentId, error), error);
    require(retried.apply(error), error);
    require(journal.records().back().id != intentId,
            "unpublished intent must close before a fresh ownership cycle");
    require(retried.release(journal.records().back(), error), error);

    fs::remove(service);
    const auto vendor = directory / "vendor";
    fs::create_directories(vendor);
    writeFile(directory / "foreign", original);
    fs::create_symlink(directory / "foreign", vendor / "lightdm");
    options.platform.configDirectories.push_back(vendor);
    PamNopasswdloginTransaction unsafeFallback(options, journal);
    require(!unsafeFallback.apply(error), "untrusted fallback must not be treated as a missing service");
    require(!fs::exists(service), "fallback refusal must not create a primary file");
    fs::remove(vendor / "lightdm");
    writeFile(vendor / "lightdm", "# FIC_PAM_NOPASSWDLOGIN orphan\nauth required pam_unix.so\n");
    require(!unsafeFallback.apply(error), "fallback suppression witness must not be silently ignored");
    fs::remove(vendor / "lightdm");

    const auto readFile = [](const fs::path& path) {
        std::ifstream input(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(input), {});
    };
    const auto other = service.parent_path() / "other";
    require(unsafeFallback.apply(error), "missing service without other must be allowed");
    writeFile(other, "auth required pam_deny.so\n");
    const auto safeOther = readFile(other);
    require(unsafeFallback.apply(error), error);
    require(readFile(other) == safeOther, "safe fallback changed");
    writeFile(other, original);
    require(!unsafeFallback.apply(error), "other bypass must refuse missing service");
    require(readFile(other) == original && !fs::exists(service),
            "other bypass refusal must not write either file");
    writeFile(other, "# FIC_PAM_NOPASSWDLOGIN orphan\nauth required pam_deny.so\n");
    const auto orphanOther = readFile(other);
    require(!unsafeFallback.apply(error), "other orphan witness must fail closed");
    require(readFile(other) == orphanOther, "other orphan changed");
    fs::remove(other);

    const auto stage = service.parent_path() / "stage";
    writeFile(service, bypass + "auth include stage\n");
    writeFile(stage, "auth required pam_unix.so\n");
    options.writer = [&](const std::string& path, const std::string& content,
                         const AtomicWriteOptions& settings, std::string* message) {
        if (!AtomicFileWriter::write(path, content, settings, message)) return false;
        writeFile(stage, bypass + "auth required pam_unix.so\n");
        return true;
    };
    PamNopasswdloginTransaction changedInclude(options, journal);
    require(!changedInclude.apply(error), "post-publication include drift must fail postcondition");
    require(journal.records().back().isActive(), "unresolved graph drift must retain ownership");
    require(bytes().find("FIC_PAM_NOPASSWDLOGIN") != std::string::npos,
            "failed graph compensation must leave its physical proof");
    writeFile(stage, "auth required pam_unix.so\n");
    options.writer = AtomicFileWriter::write;
    PamNopasswdloginTransaction repairedInclude(options, journal);
    require(repairedInclude.apply(error), error);
    require(repairedInclude.release(journal.records().back(), error), error);


}

void testPackagedPamProof() {
    using namespace fic::identity::pam;
    using fic::platform::PackageManagerKind;
    fic::platform::PamPlatformConfig::PasswordlessLoginTarget target{
        "lightdm", "/etc/pam.d/lightdm", {"lightdm"}};
    std::string error;
    std::string owner = "lightdm:amd64: /etc/pam.d/lightdm\n";
    std::string metadata = "installed\n /etc/pam.d/lightdm 900150983cd24fb0d6963f7d28e17f72\n";
    std::string rpm = "lightdm\n/etc/pam.d/lightdm\t900150983cd24fb0d6963f7d28e17f72\n";
    bool failed = false;
    const auto query = [&](const std::vector<std::string>& arguments) {
        ProcessResult result;
        result.started = true;
        result.exitCode = failed ? 1 : 0;
        if (arguments.front() == "-S") {
            require(arguments.back() == target.source, "owner query must use the exact managed source");
            result.standardOutput = owner;
        } else if (arguments.front() == "-W") {
            require(arguments.back() == "lightdm:amd64", "metadata must use the identified binary owner");
            result.standardOutput = metadata;
        } else {
            require(arguments.front() == "-qf" && arguments.back() == target.source,
                    "RPM must query exact file ownership");
            result.standardOutput = rpm;
        }
        return result;
    };
    require(provePackagedPamContent(target, PackageManagerKind::Dpkg, "abc", query, error), error);
    require(provePackagedPamContent(target, PackageManagerKind::Rpm, "abc", query, error), error);
    require(!provePackagedPamContent(target, PackageManagerKind::Dpkg, "changed", query, error),
            "DEB ownership alone must not prove package bytes");
    require(!provePackagedPamContent(target, PackageManagerKind::Rpm, "changed", query, error),
            "RPM ownership alone must not prove package bytes");
    owner += "other: /etc/pam.d/lightdm\n";
    require(!provePackagedPamContent(target, PackageManagerKind::Dpkg, "abc", query, error),
            "ambiguous DEB owner must fail");
    owner = "lightdm:amd64: /etc/pam.d/lightdm\n";
    metadata = "config-files\n /etc/pam.d/lightdm 900150983cd24fb0d6963f7d28e17f72\n";
    require(!provePackagedPamContent(target, PackageManagerKind::Dpkg, "abc", query, error),
            "removed DEB package metadata must fail");
    metadata = "installed\n /etc/pam.d/lightdm 900150983cd24fb0d6963f7d28e17f72 obsolete\n";
    require(!provePackagedPamContent(target, PackageManagerKind::Dpkg, "abc", query, error),
            "obsolete conffile metadata must fail");
    rpm += "/etc/pam.d/lightdm\t900150983cd24fb0d6963f7d28e17f72\n";
    require(!provePackagedPamContent(target, PackageManagerKind::Rpm, "abc", query, error),
            "duplicate RPM digest must fail");
    rpm = "other\n/etc/pam.d/lightdm\t900150983cd24fb0d6963f7d28e17f72\n";
    require(!provePackagedPamContent(target, PackageManagerKind::Rpm, "abc", query, error),
            "unexpected package must fail");
    failed = true;
    require(!provePackagedPamContent(target, PackageManagerKind::Rpm, "abc", query, error),
            "failed query must fail closed");
}

} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() /
        ("fic-pam-analyzer-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    try {
        testPackagedPamProof();
        testNopasswdloginTransaction(root);
        testNopasswdloginFragment();
        testRuleSuppressionProof(root);
        testMfaAuthenticationPaths();
        testEmptyUnixPasswordPaths();
        testDetectPamFaillockStrategy(root);
        testDebianGeneratedTopologiesAreEffective(root);
        testRecoverableFailureAccounting(root);
        testPrematureSuccessAccounting(root);
        testAltSshAuthsuccBeforeOuterNologinIsPremature(root);
        testAltLocalOnlyFaillockAcrossSssRouter(root);
        testSddmRootExclusionWithAuthsucc(root);
        testNativeSddmProfiles(root);
        testAuthsuccDenialBypassDetected(root);
        testProviderUnreachableAfterAuthfail(root);
        testConditionalPasswordRequirements(root);
        testPasswordFlowPositive(root);
        testPasswordFlowProducerBypass(root);
        testPasswordFlowHistoryBypass(root);
        testPasswordFlowTokenProducerBypass(root);
        testPasswordFlowHistoryBeforeProducer(root);
        testPasswordFlowUnknownControl(root);
        testPasswordFlowNoSuccessfulPath(root);
        testPasswordFlowSubstackJump(root);
    } catch (const std::exception& exception) {
        std::cerr << "PamControlFlowAnalyzerTests failed: "
                  << exception.what() << '\n';
        fs::remove_all(root);
        return EXIT_FAILURE;
    }
    fs::remove_all(root);
    std::cout << "PamControlFlowAnalyzerTests passed\n";
    return EXIT_SUCCESS;
}
