#include "modules/identity_access/submodules/pam/PamConfiguration.h"
#include "modules/identity_access/submodules/pam/PamOptionFile.h"
#include "modules/identity_access/submodules/pam/PamProviderInspector.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace {

class TempDirectory {
public:
    TempDirectory() {
        char pattern[] = "/tmp/fic-pam-tests-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = created;
    }

    ~TempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path& path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const std::filesystem::path& path,
               const std::string& content,
               mode_t mode = 0644) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        throw std::runtime_error("could not write " + path.string());
    }
    output << content;
    output.close();
    if (::chmod(path.c_str(), mode) != 0) {
        throw std::runtime_error("could not chmod " + path.string());
    }
}

fic::platform::PamPlatformConfig makePlatform(const TempDirectory& temp) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {temp.path() / "pam.d"};
    platform.moduleDirectories = {temp.path() / "security"};
    platform.authenticationServices = {"login", "sshd"};
    platform.passwordServices = {"passwd"};
    platform.faillockConfigPath = temp.path() / "security-config/faillock.conf";
    platform.passwordQualityConfigPath =
        temp.path() / "security-config/pwquality.conf";
    platform.passwordHistoryConfigPath =
        temp.path() / "security-config/pwhistory.conf";
    return platform;
}

void createFaillockGraph(const TempDirectory& temp,
                         const std::string& authExtra = "") {
    writeFile(
        temp.path() / "pam.d/login",
        "auth include common-auth\n"
        "account include common-account\n");
    writeFile(
        temp.path() / "pam.d/sshd",
        "@include common-auth\n"
        "@include common-account\n");
    writeFile(
        temp.path() / "pam.d/common-auth",
        "auth required pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail " + authExtra + "\n"
        "auth sufficient pam_faillock.so authsucc\n");
    writeFile(
        temp.path() / "pam.d/common-account",
        "account required pam_unix.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
}

void testIncludeGraphAndProviderInspection() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    createFaillockGraph(temp);

    fic::identity::pam::PamConfiguration configuration(platform);
    std::vector<fic::identity::pam::PamRule> rules;
    std::string error;
    require(
        configuration.collectRules(
            "login", fic::identity::pam::PamManagementGroup::Auth, rules, error),
        error);
    require(rules.size() == 4, "login auth graph must contain four rules");
    require(
        rules.front().source.filename() == "common-auth",
        "include source location was not preserved");

    fic::identity::pam::PamProviderInspection inspection;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.authenticationServices,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            inspection,
            error),
        error);
    require(inspection.services.size() == 2, "both services must be inspected");
    require(
        fic::identity::pam::PamProviderInspector::verifyProviderFiles(
            inspection, platform.moduleDirectories, error),
        error);
    require(
        fic::identity::pam::PamProviderInspector::verifyConfigurationFiles(
            inspection, error),
        error);
}

void testIncludeCycleFailsClosed() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    writeFile(temp.path() / "pam.d/login", "auth include first\n");
    writeFile(temp.path() / "pam.d/first", "auth substack second\n");
    writeFile(temp.path() / "pam.d/second", "auth include first\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    std::vector<fic::identity::pam::PamRule> rules;
    std::string error;
    require(
        !configuration.collectRules(
            "login", fic::identity::pam::PamManagementGroup::Auth, rules, error),
        "include cycle must fail");
    require(
        error.find("cycle") != std::string::npos,
        "include cycle diagnostic is missing");
}

void testNonRegularHigherPriorityServiceFails() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.configDirectories.push_back(temp.path() / "vendor-pam.d");
    std::filesystem::create_directories(temp.path() / "pam.d/login");
    writeFile(
        temp.path() / "vendor-pam.d/login",
        "auth required pam_faillock.so preauth\n"
        "auth required pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        !fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            {"login"},
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            inspection,
            error),
        "a non-regular higher-priority PAM service must fail");
    require(
        error.find("not a regular file") != std::string::npos,
        "non-regular PAM service diagnostic is missing");
}

void testConflictingLockoutProvidersFail() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    createFaillockGraph(temp);
    writeFile(
        temp.path() / "pam.d/common-auth",
        "auth required pam_faillock.so preauth\n"
        "auth required pam_tally2.so deny=5\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        !fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.authenticationServices,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            inspection,
            error),
        "pam_faillock plus pam_tally2 must be rejected");
    require(
        error.find("conflicting") != std::string::npos,
        "provider conflict diagnostic is missing");
}

void testIncompleteFaillockFails() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    createFaillockGraph(temp);
    writeFile(
        temp.path() / "pam.d/common-auth",
        "auth required pam_faillock.so preauth\n"
        "auth required pam_unix.so\n"
        "auth required pam_faillock.so authfail\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        !fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.authenticationServices,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            inspection,
            error),
        "incomplete pam_faillock topology must fail");
    require(
        error.find("incomplete") != std::string::npos,
        "incomplete topology diagnostic is missing");
}

void testDuplicatePasswordProviderFails() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password requisite pam_pwquality.so\n"
        "password required pam_pwquality.so\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        !fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.passwordServices,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPwquality,
            inspection,
            error),
        "duplicate pam_pwquality calls must fail");
    require(
        error.find("ambiguous") != std::string::npos,
        "duplicate provider diagnostic is missing");
}

void testPamArgumentOverrideFails() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    createFaillockGraph(temp, "deny=3");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.authenticationServices,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            inspection,
            error),
        error);
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            inspection,
            platform.faillockConfigPath.string(),
            "deny",
            "5",
            error),
        "conflicting PAM argument must fail");
    require(
        error.find("overrides") != std::string::npos,
        "override diagnostic is missing");
}

void testFailIntervalArgumentOverride() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    createFaillockGraph(temp, "fail_interval=600");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.authenticationServices,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            inspection,
            error),
        error);
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            inspection,
            platform.faillockConfigPath.string(),
            "fail_interval",
            "900",
            error),
        "conflicting fail_interval PAM argument must fail");
    require(
        error.find("fail_interval=600") != std::string::npos,
        "fail_interval override diagnostic is missing");

    error.clear();
    require(
        fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            inspection,
            platform.faillockConfigPath.string(),
            "fail_interval",
            "600",
            error),
        error);
}

void testPasswordHistoryFlagOverride() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so enforce_for_root\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.passwordServices,
            fic::identity::pam::PamCapability::PasswordHistory,
            fic::identity::pam::PamProviderKind::PamPwhistory,
            inspection,
            error),
        error);
    require(
        fic::identity::pam::PamProviderInspector::verifyFlagOverrides(
            inspection,
            platform.passwordHistoryConfigPath.string(),
            "enforce_for_root",
            true,
            error),
        error);
    require(
        !fic::identity::pam::PamProviderInspector::verifyFlagOverrides(
            inspection,
            platform.passwordHistoryConfigPath.string(),
            "enforce_for_root",
            false,
            error),
        "PAM flag argument must override the requested disabled state");
    require(
        error.find("overrides") != std::string::npos,
        "PAM flag override diagnostic is missing");
}

void testPasswordHistoryFlagAssignmentFails() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so enforce_for_root=yes\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.passwordServices,
            fic::identity::pam::PamCapability::PasswordHistory,
            fic::identity::pam::PamProviderKind::PamPwhistory,
            inspection,
            error),
        error);
    require(
        !fic::identity::pam::PamProviderInspector::verifyFlagOverrides(
            inspection,
            platform.passwordHistoryConfigPath.string(),
            "enforce_for_root",
            true,
            error),
        "valued PAM flag argument must fail");
    require(
        error.find("must not have a value") != std::string::npos,
        "valued PAM flag diagnostic is missing");

    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=/other/pwhistory.conf\n");
    fic::identity::pam::PamConfiguration pathConfiguration(platform);
    fic::identity::pam::PamProviderInspection pathInspection;
    error.clear();
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            pathConfiguration,
            platform.passwordServices,
            fic::identity::pam::PamCapability::PasswordHistory,
            fic::identity::pam::PamProviderKind::PamPwhistory,
            pathInspection,
            error),
        error);
    require(
        !fic::identity::pam::PamProviderInspector::verifyFlagOverrides(
            pathInspection,
            platform.passwordHistoryConfigPath.string(),
            "enforce_for_root",
            true,
            error),
        "alternate configuration path must fail for a PAM flag policy");
    require(
        error.find("another configuration file") != std::string::npos,
        "PAM flag configuration-path diagnostic is missing");
}

void testWritableProviderFileFails() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    createFaillockGraph(temp);
    require(
        ::chmod(
            (temp.path() / "security/pam_faillock.so").c_str(), 0775) == 0,
        "could not make test provider writable");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.authenticationServices,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            inspection,
            error),
        error);
    require(
        !fic::identity::pam::PamProviderInspector::verifyProviderFiles(
            inspection, platform.moduleDirectories, error),
        "group-writable provider file must fail");
    require(
        error.find("writable") != std::string::npos,
        "provider permission diagnostic is missing");
}

void testWritableConfigurationFileFails() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    createFaillockGraph(temp);

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.authenticationServices,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            inspection,
            error),
        error);
    require(
        ::chmod((temp.path() / "pam.d/common-auth").c_str(), 0664) == 0,
        "could not make test PAM configuration writable");
    require(
        !fic::identity::pam::PamProviderInspector::verifyConfigurationFiles(
            inspection, error),
        "group-writable PAM configuration must fail");
    require(
        error.find("writable") != std::string::npos,
        "PAM configuration permission diagnostic is missing");
}

void testOptionFileUpdatesAllDefinitions() {
    TempDirectory temp;
    const auto path = temp.path() / "security/faillock.conf";
    writeFile(
        path,
        "# administrator comment\n"
        "deny = 3\n"
        "fail_interval=300\n"
        "unlock_time=300\n"
        "fail_interval = 600 # duplicate interval\n"
        "deny=4 # duplicate\n");

    std::string error;
    require(
        fic::identity::pam::PamOptionFile::setValue(path, "deny", "5", error),
        error);
    require(
        fic::identity::pam::PamOptionFile::hasOnlyValue(path, "deny", "5", error),
        error);
    require(
        fic::identity::pam::PamOptionFile::setValue(
            path, "fail_interval", "900", error),
        error);
    require(
        fic::identity::pam::PamOptionFile::hasOnlyValue(
            path, "fail_interval", "900", error),
        error);
    require(
        fic::identity::pam::PamOptionFile::setValue(
            path, "unlock_time", "600", error),
        error);
    require(
        fic::identity::pam::PamOptionFile::hasOnlyValue(
            path, "unlock_time", "600", error),
        error);

    std::ifstream input(path);
    const std::string content(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    require(
        content.find("# administrator comment") != std::string::npos,
        "comments must be preserved");
    require(
        content.find("deny = 5") != std::string::npos,
        "deny value was not preserved after later updates");
    require(
        content.find("fail_interval = 900") != std::string::npos,
        "fail_interval value was not updated");
    require(
        content.find("unlock_time = 600") != std::string::npos,
        "unlock_time value was not updated");
    require(
        content.find("# duplicate interval") != std::string::npos &&
            content.find("# duplicate") != std::string::npos,
        "inline comments must be preserved across related updates");
}

void testOptionFileSymlinkFails() {
    TempDirectory temp;
    const auto target = temp.path() / "security/real.conf";
    const auto link = temp.path() / "security/faillock.conf";
    writeFile(target, "deny = 3\n");
    require(
        ::symlink(target.c_str(), link.c_str()) == 0,
        "could not create option-file symlink");

    std::string error;
    require(
        !fic::identity::pam::PamOptionFile::setValue(link, "deny", "5", error),
        "PAM option-file symlink must fail");
    require(
        error.find("symbolic link") != std::string::npos,
        "option-file symlink diagnostic is missing");
}

void testOptionFileFlagEnableDisable() {
    TempDirectory temp;
    const auto path = temp.path() / "security/pwhistory.conf";
    writeFile(
        path,
        "# administrator header\n"
        "remember = 5\n"
        "enforce_for_root # keep root history\n"
        "enforce_for_root\n"
        "retry = 2\n");

    std::string error;
    require(
        fic::identity::pam::PamOptionFile::hasFlag(
            path, "enforce_for_root", true, error),
        error);
    require(
        fic::identity::pam::PamOptionFile::setFlag(
            path, "enforce_for_root", false, error),
        error);
    require(
        fic::identity::pam::PamOptionFile::hasFlag(
            path, "enforce_for_root", false, error),
        error);

    std::ifstream disabledInput(path);
    const std::string disabledContent(
        (std::istreambuf_iterator<char>(disabledInput)),
        std::istreambuf_iterator<char>());
    require(
        disabledContent.find("# administrator header") != std::string::npos &&
            disabledContent.find("# keep root history") != std::string::npos,
        "disabling a PAM flag must preserve comments");
    require(
        disabledContent.find("remember = 5") != std::string::npos &&
            disabledContent.find("retry = 2") != std::string::npos,
        "disabling a PAM flag must preserve assignments");

    require(
        fic::identity::pam::PamOptionFile::setFlag(
            path, "enforce_for_root", true, error),
        error);
    require(
        fic::identity::pam::PamOptionFile::hasFlag(
            path, "enforce_for_root", true, error),
        error);
}

void testMalformedOptionFileFlagFailsWithoutWrite() {
    TempDirectory temp;
    const auto path = temp.path() / "security/pwhistory.conf";
    const std::string original =
        "remember = 5\n"
        "enforce_for_root=yes\n";
    writeFile(path, original);

    std::string error;
    require(
        !fic::identity::pam::PamOptionFile::setFlag(
            path, "enforce_for_root", false, error),
        "malformed PAM flag assignment must fail");
    require(
        error.find("malformed") != std::string::npos,
        "malformed PAM flag diagnostic is missing");
    std::ifstream input(path);
    const std::string content(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    require(content == original, "malformed PAM flag failure modified the file");

    const auto missing = temp.path() / "security/missing.conf";
    error.clear();
    require(
        fic::identity::pam::PamOptionFile::setFlag(
            missing, "enforce_for_root", false, error),
        error);
    require(
        !std::filesystem::exists(missing),
        "disabling an absent PAM flag must not create a file");
}

void testPasswordHistoryAlternativeIsDetected() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_unix.so remember=5\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        !fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.passwordServices,
            fic::identity::pam::PamCapability::PasswordHistory,
            fic::identity::pam::PamProviderKind::PamPwhistory,
            inspection,
            error),
        "pam_unix remember must not be treated as pam_pwhistory");
    require(
        error.find("pam_unix remember") != std::string::npos,
        "alternative history provider diagnostic is missing");
}

} // namespace

int main() {
    try {
        testIncludeGraphAndProviderInspection();
        testIncludeCycleFailsClosed();
        testNonRegularHigherPriorityServiceFails();
        testConflictingLockoutProvidersFail();
        testIncompleteFaillockFails();
        testDuplicatePasswordProviderFails();
        testPamArgumentOverrideFails();
        testFailIntervalArgumentOverride();
        testPasswordHistoryFlagOverride();
        testPasswordHistoryFlagAssignmentFails();
        testWritableProviderFileFails();
        testWritableConfigurationFileFails();
        testOptionFileUpdatesAllDefinitions();
        testOptionFileSymlinkFails();
        testOptionFileFlagEnableDisable();
        testMalformedOptionFileFlagFailsWithoutWrite();
        testPasswordHistoryAlternativeIsDetected();
    } catch (const std::exception& error) {
        std::cerr << "PamConfigurationTests failed: " << error.what() << '\n';
        return 1;
    }
    std::cout << "PamConfigurationTests passed\n";
    return 0;
}
