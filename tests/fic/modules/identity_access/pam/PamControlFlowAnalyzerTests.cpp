#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"
#include "modules/identity_access/pam/PamConfiguration.h"

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

} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() /
        ("fic-pam-analyzer-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    try {
        testDetectPamFaillockStrategy(root);
        testDebianGeneratedTopologiesAreEffective(root);
        testRecoverableFailureAccounting(root);
        testPrematureSuccessAccounting(root);
        testAltSshAuthsuccBeforeOuterNologinIsPremature(root);
        testAltLocalOnlyFaillockAcrossSssRouter(root);
        testSddmRootExclusionWithAuthsucc(root);
        testAuthsuccDenialBypassDetected(root);
        testProviderUnreachableAfterAuthfail(root);
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
