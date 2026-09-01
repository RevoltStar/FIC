#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamOptionFile.h"
#include "modules/identity_access/pam/PamOptionValueCodec.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamProviderInspector.h"
#include "modules/identity_access/pam/PamPwhistoryArguments.h"
#include "modules/identity_access/pam/PamProviderSemanticVerifier.h"
#include "modules/identity_access/pam/PamRequiredProviders.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

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

struct TestPamPlatformConfig : fic::platform::PamPlatformConfig {
    std::vector<std::string>& authenticationServices;
    std::vector<std::string>& passwordServices;
    std::filesystem::path& faillockConfigPath;
    std::filesystem::path& passwordQualityConfigPath;
    std::filesystem::path& passwordHistoryConfigPath;

    TestPamPlatformConfig()
        : fic::platform::PamPlatformConfig(initial()),
          authenticationServices(scopes[0].services),
          passwordServices(scopes[1].services),
          faillockConfigPath(capabilities[0].configPath),
          passwordQualityConfigPath(capabilities[1].configPath),
          passwordHistoryConfigPath(capabilities[2].configPath) {}

    TestPamPlatformConfig(const TestPamPlatformConfig& other)
        : fic::platform::PamPlatformConfig(other),
          authenticationServices(scopes[0].services),
          passwordServices(scopes[1].services),
          faillockConfigPath(capabilities[0].configPath),
          passwordQualityConfigPath(capabilities[1].configPath),
          passwordHistoryConfigPath(capabilities[2].configPath) {}

private:
    static fic::platform::PamPlatformConfig initial() {
        fic::platform::PamPlatformConfig result;
        result.scopes = {
            {fic::platform::PamScope::EffectiveAuthenticationStack, {}},
            {fic::platform::PamScope::EffectivePasswordStack, {}}
        };
        result.capabilities = {
            {fic::platform::PamCapability::AuthenticationLockout,
             fic::platform::PamProviderKind::PamFaillock,
             fic::platform::PamScope::EffectiveAuthenticationStack, {},
             fic::platform::PamTopologyStrategyKind::StaticReadOnly, {}},
            {fic::platform::PamCapability::PasswordQuality,
             fic::platform::PamProviderKind::PamPwquality,
             fic::platform::PamScope::EffectivePasswordStack, {},
             fic::platform::PamTopologyStrategyKind::StaticReadOnly, {}},
            {fic::platform::PamCapability::PasswordHistory,
             fic::platform::PamProviderKind::PamPwhistory,
             fic::platform::PamScope::EffectivePasswordStack, {},
             fic::platform::PamTopologyStrategyKind::StaticReadOnly, {}}
        };
        return result;
    }
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

TestPamPlatformConfig makePlatform(const TempDirectory& temp) {
    TestPamPlatformConfig platform;
    platform.configDirectories = {temp.path() / "pam.d"};
    platform.moduleDirectories = {temp.path() / "security"};
    platform.authenticationServices = {"login", "sshd"};
    platform.passwordServices = {"passwd"};
    platform.faillockConfigPath = temp.path() / "security-config/faillock.conf";
    platform.passwordQualityConfigPath =
        temp.path() / "security-config/pwquality.conf";
    platform.passwordHistoryConfigPath =
        temp.path() / "security-config/pwhistory.conf";
    auto qualityTopology = fic::identity::pam::pamProviderDescriptor(
        fic::platform::PamProviderKind::PamPwquality).defaultConfigTopology;
    qualityTopology.primaryPath = platform.passwordQualityConfigPath;
    qualityTopology.dropInDirectories = {
        std::filesystem::path(
            platform.passwordQualityConfigPath.string() + ".d")};
    platform.capabilities[1].configTopology = std::move(qualityTopology);
    return platform;
}

void createFaillockGraph(const TempDirectory& temp,
                         const std::string& authExtra = "") {
    const std::string configArgument =
        " conf=" +
        (temp.path() / "security-config/faillock.conf").string();
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
        "auth required pam_faillock.so preauth" + configArgument + "\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail" + configArgument +
            " " + authExtra + "\n"
        "auth sufficient pam_faillock.so authsucc" + configArgument + "\n"
        "auth required pam_deny.so\n");
    writeFile(
        temp.path() / "pam.d/common-account",
        "account required pam_unix.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
}

fic::identity::pam::PamCapabilityVerification verifyCapability(
    const fic::platform::PamPlatformConfig& platform,
    fic::identity::pam::PamCapability capability,
    fic::identity::pam::PamProviderKind provider,
    const std::vector<std::string>& services,
    fic::identity::pam::PamCapabilityVerificationMode mode =
        fic::identity::pam::PamCapabilityVerificationMode::SecurityEffective) {
    const auto& descriptor =
        fic::identity::pam::pamProviderDescriptor(provider);
    const auto capabilityConfig = std::find_if(
        platform.capabilities.begin(), platform.capabilities.end(),
        [capability](const auto& candidate) {
            return candidate.capability == capability;
        });
    if (provider == fic::identity::pam::PamProviderKind::PamPwquality &&
        capabilityConfig != platform.capabilities.end() &&
        !std::filesystem::exists(capabilityConfig->configPath)) {
        writeFile(capabilityConfig->configPath, "");
    }
    if (descriptor.externalConfigMode ==
            fic::identity::pam::PamExternalConfigMode::Optional &&
        capabilityConfig != platform.capabilities.end() &&
        descriptor.defaultConfigTopology.primaryPath.has_value() &&
        capabilityConfig->configPath !=
            *descriptor.defaultConfigTopology.primaryPath) {
        const std::string assignment =
            " " + std::string(descriptor.externalConfigArgument) + "=" +
            capabilityConfig->configPath.string();
        for (const auto& directory : platform.configDirectories) {
            std::error_code iterationError;
            std::filesystem::directory_iterator entries(
                directory, iterationError);
            if (iterationError) {
                continue;
            }
            for (const auto& entry : entries) {
                if (!entry.is_regular_file()) {
                    continue;
                }
                std::ifstream input(entry.path(), std::ios::binary);
                std::string content{
                    std::istreambuf_iterator<char>(input),
                    std::istreambuf_iterator<char>()};
                std::istringstream lines(content);
                std::string line;
                std::string rewritten;
                bool changed = false;
                while (std::getline(lines, line)) {
                    if (line.find(descriptor.moduleName) != std::string::npos &&
                        line.find(
                            std::string(descriptor.externalConfigArgument) +
                            "=") == std::string::npos) {
                        line += assignment;
                        changed = true;
                    }
                    rewritten += line + "\n";
                }
                if (changed) {
                    writeFile(entry.path(), rewritten);
                }
            }
        }
    }
    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamCapabilityVerification verification;
    fic::identity::pam::PamCapabilityVerifier::verify(
        configuration,
        platform,
        services,
        capability,
        provider,
        verification,
        mode);
    return verification;
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
    require(rules.size() == 5, "login auth graph must contain five rules");
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
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Conflicting,
        "multiple lockout providers must be reported as conflicting");
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
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() +
            " enforce_for_root\n");

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
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() +
            " enforce_for_root=yes\n");

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

void testOptionalExternalConfigRequiresNativeDefaultPath() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so\n");

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
        !fic::identity::pam::PamProviderInspector::verifyExternalConfigContract(
            inspection, platform.passwordHistoryConfigPath.string(), error),
        "optional PAM config accepted a non-default managed path without conf=");
    require(
        error.find("native default configuration path") != std::string::npos,
        "optional PAM default-path diagnostic is missing: " + error);
    require(
        fic::identity::pam::PamProviderInspector::verifyExternalConfigContract(
            inspection, "/etc/security/pwhistory.conf", error),
        "native pam_pwhistory default path was rejected: " + error);

    inspection.providerRules.front().arguments = {
        "conf=" + platform.passwordHistoryConfigPath.string()};
    require(
        fic::identity::pam::PamProviderInspector::verifyExternalConfigContract(
            inspection, platform.passwordHistoryConfigPath.string(), error),
        "explicit optional PAM config path was rejected: " + error);
}

void testFlagConflictingOptionFails() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    createFaillockGraph(temp, "root_unlock_time=60");

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
        !fic::identity::pam::PamProviderInspector::verifyFlagOverrides(
            inspection,
            platform.faillockConfigPath.string(),
            "even_deny_root",
            false,
            error,
            {"root_unlock_time"}),
        "root_unlock_time PAM argument must prevent disabling root lockout");
    require(
        error.find("root_unlock_time") != std::string::npos,
        "conflicting PAM argument diagnostic is missing");

    const auto configPath = platform.faillockConfigPath;
    writeFile(
        configPath,
        "deny = 5\n"
        "root_unlock_time = 60\n");
    error.clear();
    require(
        !fic::identity::pam::PamOptionFile::verifyNoActiveDirectives(
            configPath, {"root_unlock_time"}, error),
        "root_unlock_time config directive must be detected");
    require(
        error.find("root_unlock_time") != std::string::npos,
        "conflicting config directive diagnostic is missing");

    writeFile(configPath, "deny = 5\n# root_unlock_time = 60\n");
    error.clear();
    require(
        fic::identity::pam::PamOptionFile::verifyNoActiveDirectives(
            configPath, {"root_unlock_time"}, error),
        error);
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

void createPwqualityGraph(
    const TempDirectory& temp,
    const TestPamPlatformConfig& platform,
    const std::string& service,
    const std::string& arguments = "") {
    writeFile(
        temp.path() / "pam.d" / service,
        "password requisite pam_pwquality.so" + arguments + "\n"
        "password required pam_unix.so use_authtok\n");
    const auto module = temp.path() / "security/pam_pwquality.so";
    if (!std::filesystem::exists(module)) {
        writeFile(module, "test", 0555);
    }
}

fic::identity::pam::PamProviderInspection inspectPwquality(
    const TestPamPlatformConfig& platform) {
    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration,
            platform.passwordServices,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPwquality,
            inspection,
            error),
        error);
    return inspection;
}

void testPwqualityEnforcingStateAndServices() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.passwordServices = {"passwd"};
    createPwqualityGraph(temp, platform, "passwd");
    writeFile(
        platform.passwordQualityConfigPath,
        "minlen = 20\n"
        "enforcing = 1\n");

    auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Effective,
        fic::identity::pam::formatPamCapabilityVerification(verification));

    writeFile(
        platform.passwordQualityConfigPath,
        "minlen = 20\n"
        "enforcing = 1\n"
        "local_users_only\n");
    verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Ineffective,
        "pam_pwquality local_users_only was reported effective for all PAM "
        "subjects");
    verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices,
        fic::identity::pam::PamCapabilityVerificationMode::Structural);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Effective,
        "structurally valid pwquality local_users_only was reported broken");
    platform.capabilities[1].subjectScope =
        fic::platform::PamIdentitySubjectScope::LocalUsersOnly;
    verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Effective,
        "pwquality local_users_only did not satisfy explicit local-only scope");
    platform.capabilities[1].subjectScope =
        fic::platform::PamIdentitySubjectScope::AllPamSubjects;

    writeFile(
        platform.passwordQualityConfigPath,
        "minlen = 20\n"
        "enforcing = 0\n");
    verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Ineffective,
        "pam_pwquality enforcing=0 was reported as security-effective");
    verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices,
        fic::identity::pam::PamCapabilityVerificationMode::Structural);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Effective,
        "structurally valid pwquality enforcing=0 was reported broken");

    writeFile(platform.passwordQualityConfigPath, "enforcing = 1\n");
    platform.passwordServices = {"passwd", "chpasswd"};
    createPwqualityGraph(temp, platform, "passwd");
    createPwqualityGraph(temp, platform, "chpasswd", " enforcing=0");
    verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Ineffective,
        "one non-enforcing pwquality service was hidden by another service");
}

void testPwqualityEffectiveTopologyAndArguments() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.passwordServices = {"passwd"};
    createPwqualityGraph(temp, platform, "passwd");
    writeFile(
        platform.passwordQualityConfigPath.parent_path() /
            "pwquality.conf.d/10-base.conf",
        "MINLEN = 8\n"
        "enforce_for_root\n");
    writeFile(
        platform.passwordQualityConfigPath.parent_path() /
            "pwquality.conf.d/20-later.conf",
        "minlen = 12\n");
    writeFile(
        platform.passwordQualityConfigPath,
        "minlen = 18\n"
        "minlen = 20\n"
        "enforcing = 1\n");

    auto inspection = inspectPwquality(platform);
    std::string error;
    require(
        fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspection, platform.capabilities[1],
            "minlen", "20", error),
        "pwquality main file did not override sorted drop-ins: " + error);
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspection, platform.capabilities[1],
            "minlen", "12", error),
        "pwquality verification ignored main-file precedence");
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::verifyFlag(
            inspection, platform.capabilities[1], "enforce_for_root", false,
            {}, error),
        "pwquality SET flag from a drop-in was hidden by its absence in main");

    createPwqualityGraph(temp, platform, "passwd", " MiNlEn=9");
    inspection = inspectPwquality(platform);
    require(
        fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspection, platform.capabilities[1],
            "minlen", "9", error),
        "pwquality PAM argv did not override config topology: " + error);
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspection, platform.capabilities[1],
            "minlen", "20", error),
        "pwquality config value hid a later PAM argv override");

    createPwqualityGraph(temp, platform, "passwd");
    writeFile(
        platform.passwordQualityConfigPath,
        "minclass = 8\n"
        "lcredit = -2\n");
    inspection = inspectPwquality(platform);
    require(
        fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspection, platform.capabilities[1], "minclass", "4", error) &&
            fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
                inspection, platform.capabilities[1], "lcredit", "-2", error),
        "pwquality typed cross-option state was not canonicalized: " + error);
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspection, platform.capabilities[1], "minclass", "8", error),
        "pwquality native minclass clamp was ignored");

    writeFile(
        platform.passwordQualityConfigPath,
        "minlen = 20\n"
        "dcredit = 1\n");
    inspection = inspectPwquality(platform);
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspection, platform.capabilities[1], "minlen", "20", error) &&
            error.find("credits") != std::string::npos,
        "positive pwquality credit hid a shorter effective minimum length: " +
            error);

    std::filesystem::remove(
        platform.passwordQualityConfigPath.parent_path() /
        "pwquality.conf.d/10-base.conf");
    std::filesystem::remove(
        platform.passwordQualityConfigPath.parent_path() /
        "pwquality.conf.d/20-later.conf");
    createPwqualityGraph(
        temp, platform, "passwd", " enforce_for_root=0");
    inspection = inspectPwquality(platform);
    require(
        fic::identity::pam::PamProviderSemanticVerifier::verifyFlag(
            inspection, platform.capabilities[1], "enforce_for_root", true,
            {}, error),
        "pwquality SET-style PAM argument value was treated as a disable: " +
            error);
}

void testPwqualityLineLengthBoundary() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.passwordServices = {"passwd"};
    createPwqualityGraph(temp, platform, "passwd");

    const auto paddedDirective = [](std::size_t length) {
        const std::string prefix = "minlen = 20 #";
        require(length >= prefix.size(), "invalid boundary test length");
        return prefix + std::string(length - prefix.size(), 'x');
    };
    const auto requireState = [&](fic::identity::pam::PamEnforcementState state,
                                  const std::string& message) {
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPwquality,
            platform.passwordServices);
        require(
            verification.state == state,
            message + ": " +
                fic::identity::pam::formatPamCapabilityVerification(
                    verification));
    };

    // libpwquality 1.4.5 uses char[1024] with fgets(): 1022 bytes plus the
    // terminating newline fit, while 1023 bytes leave no room for that newline.
    writeFile(platform.passwordQualityConfigPath,
              paddedDirective(1022) + "\n");
    requireState(
        fic::identity::pam::PamEnforcementState::Effective,
        "1022-byte newline-terminated pwquality line was rejected");

    writeFile(platform.passwordQualityConfigPath,
              paddedDirective(1023) + "\n");
    requireState(
        fic::identity::pam::PamEnforcementState::Broken,
        "1023-byte newline-terminated pwquality line was accepted");

    writeFile(platform.passwordQualityConfigPath, paddedDirective(1023));
    requireState(
        fic::identity::pam::PamEnforcementState::Broken,
        "1023-byte final pwquality line without newline was accepted");

    writeFile(platform.passwordQualityConfigPath, "minlen = 20");
    requireState(
        fic::identity::pam::PamEnforcementState::Effective,
        "short final pwquality line without newline was rejected");
}

void testPwqualityInvalidInputsAreBroken() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.passwordServices = {"passwd"};
    createPwqualityGraph(temp, platform, "passwd");
    writeFile(platform.passwordQualityConfigPath, "minlen = 20\n");
    const auto dropIn = platform.passwordQualityConfigPath.parent_path() /
        "pwquality.conf.d/00-broken.conf";

    const auto requireBroken = [&](const std::string& message) {
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPwquality,
            platform.passwordServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Broken,
            message + ": " +
                fic::identity::pam::formatPamCapabilityVerification(
                    verification));
    };

    writeFile(dropIn, "vendor_bad_option = 1\n");
    requireBroken("unknown pwquality drop-in option was accepted");
    writeFile(dropIn, "minlen = garbage\n");
    requireBroken("malformed pwquality drop-in integer was accepted");
    writeFile(dropIn, "minlen == 20\n");
    requireBroken("malformed pwquality drop-in assignment was accepted");
    writeFile(dropIn, "# valid again\n");
    writeFile(platform.passwordQualityConfigPath, "enforcing = maybe\n");
    requireBroken("invalid known pwquality main option was accepted");

    writeFile(platform.passwordQualityConfigPath, "minlen = 20\n", 0000);
    requireBroken("unreadable pwquality main config was accepted");
    require(::chmod(platform.passwordQualityConfigPath.c_str(), 0644) == 0,
            "could not restore pwquality test config mode");

    writeFile(platform.passwordQualityConfigPath, "minlen = 20\n");
    createPwqualityGraph(temp, platform, "passwd", " minlen=garbage");
    requireBroken("invalid pwquality PAM argv was accepted");

    createPwqualityGraph(temp, platform, "passwd", " vendor_unknown=1");
    requireBroken("unknown pwquality PAM argv was accepted");

    createPwqualityGraph(
        temp, platform, "passwd",
        " conf=" + platform.passwordQualityConfigPath.string());
    requireBroken(
        "unsupported pam_pwquality 1.4.5 conf= argument was accepted");
}

void testGenericFallbackFailsClosed() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.passwordServices = {"passwd"};
    const auto fallback = temp.path() / "vendor/pwhistory.conf";
    auto topology = fic::identity::pam::pamProviderDescriptor(
        fic::platform::PamProviderKind::PamPwhistory).defaultConfigTopology;
    topology.primaryPath = platform.passwordHistoryConfigPath;
    topology.fallbackPaths = {fallback};
    platform.capabilities[2].configTopology = topology;
    writeFile(
        temp.path() / "pam.d/passwd",
        "password requisite pam_pwhistory.so\n"
        "password required pam_unix.so use_authtok\n");
    writeFile(temp.path() / "security/pam_pwhistory.so", "test", 0555);
    writeFile(fallback, "enforce_for_root\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration, platform.passwordServices,
            fic::platform::PamCapability::PasswordHistory,
            fic::platform::PamProviderKind::PamPwhistory,
            inspection, error),
        error);
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::verifyFlag(
            inspection, platform.capabilities[2], "enforce_for_root", false,
            {}, error) && error.find("fallback") != std::string::npos,
        "missing managed file hid an active provider fallback: " + error);
    const auto verifyRequiredCapability = [&] {
        fic::identity::pam::PamConfiguration currentConfiguration(platform);
        fic::identity::pam::PamCapabilityVerification result;
        fic::identity::pam::PamCapabilityVerifier::verify(
            currentConfiguration, platform, platform.passwordServices,
            fic::identity::pam::PamCapability::PasswordHistory,
            fic::identity::pam::PamProviderKind::PamPwhistory, result);
        return result;
    };
    auto verification = verifyRequiredCapability();
    require(
        verification.state == fic::identity::pam::PamEnforcementState::Broken,
        "generic required-PAM capability ignored an active fallback: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));

    writeFile(platform.passwordHistoryConfigPath, "# managed primary\n");
    require(
        fic::identity::pam::PamProviderSemanticVerifier::verifyFlag(
            inspection, platform.capabilities[2], "enforce_for_root", false,
            {}, error),
        "managed primary did not shadow the provider fallback: " + error);

    const auto dropIn = temp.path() / "vendor/pwhistory.conf.d";
    topology.dropInDirectories = {dropIn};
    platform.capabilities[2].configTopology = topology;
    writeFile(dropIn / "10-vendor.conf", "remember = 99\n");
    verification = verifyRequiredCapability();
    require(
        verification.state == fic::identity::pam::PamEnforcementState::Broken,
        "generic required-PAM capability ignored unmanaged drop-ins");

    writeFile(
        temp.path() / "pam.d/passwd",
        "password requisite pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() + "\n"
        "password required pam_unix.so use_authtok\n");
    verification = verifyRequiredCapability();
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Effective,
        "explicit pwhistory config did not replace inactive native topology: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testEffectiveKnownProviders() {
    {
        TempDirectory temp;
        const auto platform = makePlatform(temp);
        createFaillockGraph(temp);
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            platform.authenticationServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Effective,
            fic::identity::pam::formatPamCapabilityVerification(verification));
    }
    {
        TempDirectory temp;
        const auto platform = makePlatform(temp);
        writeFile(
            temp.path() / "pam.d/passwd",
            "password requisite pam_pwquality.so\n"
            "password required pam_unix.so\n");
        writeFile(temp.path() / "security/pam_pwquality.so", "test", 0555);
        writeFile(platform.passwordQualityConfigPath, "");
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPwquality,
            platform.passwordServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Effective,
            fic::identity::pam::formatPamCapabilityVerification(verification));
    }
    {
        TempDirectory temp;
        auto platform = makePlatform(temp);
        platform.capabilities[1].provider =
            fic::platform::PamProviderKind::PamPasswdqc;
        platform.passwordQualityConfigPath = temp.path() / "passwdqc.conf";
        writeFile(platform.passwordQualityConfigPath, "enforce=everyone\n");
        writeFile(
            temp.path() / "pam.d/passwd",
            "password required pam_passwdqc.so config=" +
                platform.passwordQualityConfigPath.string() + "\n"
            "password required pam_tcb.so use_authtok\n");
        writeFile(temp.path() / "security/pam_passwdqc.so", "test", 0555);
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPasswdqc,
            platform.passwordServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Effective,
            "native ALT pam_passwdqc provider was not detected: " +
                fic::identity::pam::formatPamCapabilityVerification(
                    verification));
    }
    {
        TempDirectory temp;
        const auto platform = makePlatform(temp);
        writeFile(
            temp.path() / "pam.d/passwd",
            "password include common-password\n");
        writeFile(
            temp.path() / "pam.d/common-password",
            "password required pam_pwhistory.so conf=" +
                platform.passwordHistoryConfigPath.string() + "\n"
            "password required pam_unix.so\n");
        writeFile(temp.path() / "security/pam_pwhistory.so", "test", 0555);
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordHistory,
            fic::identity::pam::PamProviderKind::PamPwhistory,
            platform.passwordServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Effective,
            fic::identity::pam::formatPamCapabilityVerification(verification));
    }
}

void testDebianPamAuthUpdateGeneratedStackIsEffective() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"login"};
    platform.passwordServices = {"passwd"};

    writeFile(
        temp.path() / "pam.d/login",
        "auth include common-auth\n"
        "account include common-account\n");
    writeFile(
        temp.path() / "pam.d/passwd",
        "password include common-password\n");
    writeFile(
        temp.path() / "pam.d/common-auth",
        "auth requisite pam_faillock.so preauth conf=" +
            platform.faillockConfigPath.string() + "\n"
        "auth sufficient pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail conf=" +
            platform.faillockConfigPath.string() + "\n"
        "auth requisite pam_deny.so\n");
    writeFile(
        temp.path() / "pam.d/common-account",
        "account required pam_faillock.so conf=" +
            platform.faillockConfigPath.string() + "\n"
        "account required pam_unix.so\n");
    writeFile(
        temp.path() / "pam.d/common-password",
        "password requisite pam_pwquality.so\n"
        "password requisite pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() + " use_authtok\n"
        "password required pam_unix.so\n");
    for (const auto* module : {
             "pam_faillock.so",
             "pam_pwquality.so",
             "pam_pwhistory.so"}) {
        writeFile(temp.path() / "security" / module, "test", 0555);
    }
    writeFile(platform.passwordQualityConfigPath, "");

    for (const auto& expectation : {
             std::pair{fic::identity::pam::PamCapability::AuthenticationLockout,
                       fic::identity::pam::PamProviderKind::PamFaillock},
             std::pair{fic::identity::pam::PamCapability::PasswordQuality,
                       fic::identity::pam::PamProviderKind::PamPwquality},
             std::pair{fic::identity::pam::PamCapability::PasswordHistory,
                       fic::identity::pam::PamProviderKind::PamPwhistory}}) {
        const auto& services =
            expectation.first ==
                    fic::identity::pam::PamCapability::AuthenticationLockout
                ? platform.authenticationServices
                : platform.passwordServices;
        const auto verification = verifyCapability(
            platform, expectation.first, expectation.second, services);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Effective,
            "expected pam-auth-update stack was rejected: " +
                fic::identity::pam::formatPamCapabilityVerification(
                    verification));
    }
}

void testSubstackBoundaryIsEffective() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password substack common-password\n"
        "password required pam_unix.so\n");
    writeFile(
        temp.path() / "pam.d/common-password",
        "password requisite pam_pwquality.so\n");
    writeFile(temp.path() / "security/pam_pwquality.so", "test", 0555);
    writeFile(platform.passwordQualityConfigPath, "");
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices);
    require(
        verification.state == fic::identity::pam::PamEnforcementState::Effective,
        fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testFaillockAccountTopologyIsEffective() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"login"};
    writeFile(
        temp.path() / "pam.d/login",
        "auth required pam_faillock.so preauth conf=" +
            platform.faillockConfigPath.string() + "\n"
        "auth sufficient pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail conf=" +
            platform.faillockConfigPath.string() + "\n"
        "auth required pam_deny.so\n"
        "account required pam_faillock.so conf=" +
            platform.faillockConfigPath.string() + "\n"
        "account required pam_unix.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state == fic::identity::pam::PamEnforcementState::Effective,
        "supported pam_faillock account topology was rejected: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testMissingInactiveAndBrokenStates() {
    {
        TempDirectory temp;
        const auto platform = makePlatform(temp);
        writeFile(temp.path() / "pam.d/passwd",
                  "password required pam_unix.so\n");
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPwquality,
            platform.passwordServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Missing,
            "absent provider module must be reported as missing");
    }
    {
        TempDirectory temp;
        const auto platform = makePlatform(temp);
        writeFile(temp.path() / "pam.d/passwd",
                  "password required pam_unix.so\n");
        writeFile(temp.path() / "security/pam_pwquality.so", "test", 0555);
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPwquality,
            platform.passwordServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Inactive,
            "installed but unreachable provider must be reported as inactive");
    }
    {
        TempDirectory temp;
        const auto platform = makePlatform(temp);
        writeFile(temp.path() / "pam.d/passwd",
                  "password required pam_pwquality.so\n");
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPwquality,
            platform.passwordServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Broken,
            "active rule with a missing module must be reported as broken");
    }
}

void testAuthenticationEarlySuccessBypass() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"login"};
    writeFile(
        temp.path() / "pam.d/login",
        "auth sufficient pam_permit.so\n"
        "auth required pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Ineffective,
        "early sufficient pam_permit must be rejected");
    require(
        verification.detail.find("authentication_bypass") !=
            std::string::npos &&
            verification.detail.find("pam_permit.so") != std::string::npos,
        "authentication bypass diagnostic must contain the concrete path");
}

void testTrustedSuRootokPathIsAccepted() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"su", "su-l"};
    platform.trustedAuthenticationBypasses = {
        {"su", "pam_rootok.so",
         fic::platform::PamTrustedAuthenticationBypassReason::
             AlreadyPrivilegedCaller},
        {"su-l", "pam_rootok.so",
         fic::platform::PamTrustedAuthenticationBypassReason::
             AlreadyPrivilegedCaller}
    };
    writeFile(
        temp.path() / "pam.d/su",
        "auth sufficient pam_rootok.so\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    writeFile(
        temp.path() / "pam.d/su-l",
        "auth include su\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);

    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state == fic::identity::pam::PamEnforcementState::Effective,
        "standard su pam_rootok path was rejected: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamControlFlowAnalysis analysis;
    std::string error;
    require(
        fic::identity::pam::PamControlFlowAnalyzer::analyze(
            configuration,
            platform,
            "su",
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            analysis,
            error),
        error);
    require(analysis.effective,
            "trusted su analysis must remain effective");
    require(
        analysis.acceptedTrustedAuthenticationBypasses.size() == 1,
        "trusted su path must be retained in analysis diagnostics");
    const auto& accepted =
        analysis.acceptedTrustedAuthenticationBypasses.front();
    require(
        accepted.service == "su" && accepted.module == "pam_rootok.so" &&
            accepted.line == 1 && !accepted.path.empty(),
        "trusted su path context is incomplete");

    TempDirectory brokenTemp;
    auto brokenPlatform = makePlatform(brokenTemp);
    brokenPlatform.authenticationServices = {"su"};
    brokenPlatform.trustedAuthenticationBypasses = {
        platform.trustedAuthenticationBypasses.front()
    };
    writeFile(
        brokenTemp.path() / "pam.d/su",
        "auth sufficient pam_rootok.so\n"
        "auth required pam_faillock.so preauth\n"
        "auth required pam_unix.so\n"
        "auth [success=1 default=ignore] pam_env.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    writeFile(
        brokenTemp.path() / "security/pam_faillock.so", "test", 0555);
    const auto broken = verifyCapability(
        brokenPlatform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        brokenPlatform.authenticationServices);
    require(
        broken.state == fic::identity::pam::PamEnforcementState::Ineffective &&
            broken.detail.find("failure_accounting_bypass") !=
                std::string::npos,
        "trusted root path must not hide a broken non-root su failure path: " +
            fic::identity::pam::formatPamCapabilityVerification(broken));
}

void testRootokOutsideTrustedServiceIsRejected() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"sshd", "su"};
    platform.trustedAuthenticationBypasses = {
        {"su", "pam_rootok.so",
         fic::platform::PamTrustedAuthenticationBypassReason::
             AlreadyPrivilegedCaller}
    };
    writeFile(
        temp.path() / "pam.d/sshd",
        "auth sufficient pam_rootok.so\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        {"sshd"});
    require(
        verification.state ==
                fic::identity::pam::PamEnforcementState::Ineffective &&
            verification.detail.find("authentication_bypass") !=
                std::string::npos &&
            verification.detail.find("pam_rootok.so") != std::string::npos,
        "pam_rootok outside an explicit trusted service must be rejected: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testSddmSucceedIfGateIsEffective() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"sddm"};
    writeFile(
        temp.path() / "pam.d/sddm",
        "auth required pam_succeed_if.so user != root quiet_success\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state == fic::identity::pam::PamEnforcementState::Effective,
        "required pam_succeed_if gate broke a valid SDDM stack: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testSucceedIfSufficientBypassIsRejected() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"login"};
    writeFile(
        temp.path() / "pam.d/login",
        "auth sufficient pam_succeed_if.so user ingroup admins\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state ==
                fic::identity::pam::PamEnforcementState::Ineffective &&
            verification.detail.find("authentication_bypass") !=
                std::string::npos,
        "sufficient pam_succeed_if before faillock must remain a bypass");
}

void testGateSuccessDoesNotMaskCredentialFailure() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"login"};
    writeFile(
        temp.path() / "pam.d/login",
        "auth required pam_succeed_if.so user != root quiet_success\n"
        "auth required pam_faillock.so preauth\n"
        "auth required pam_unix.so\n"
        "auth [success=1 default=ignore] pam_env.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state ==
                fic::identity::pam::PamEnforcementState::Ineffective &&
            verification.detail.find("failure_accounting_bypass") !=
                std::string::npos,
        "pam_succeed_if success masked a credential authentication failure: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testGateFailureIsNotCredentialFailure() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"login"};
    writeFile(
        temp.path() / "pam.d/login",
        "auth required pam_succeed_if.so user != root quiet_success\n"
        "auth required pam_faillock.so preauth\n"
        "auth [success=1 default=ignore] pam_env.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state == fic::identity::pam::PamEnforcementState::Effective,
        "required gate failure was misclassified as credential failure: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testPasswordEarlySuccessBypass() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password sufficient pam_unix.so\n"
        "password requisite pam_pwquality.so\n");
    writeFile(temp.path() / "security/pam_pwquality.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Ineffective,
        "successful password path bypassing pam_pwquality must be rejected");
}

void testExtendedControlBypasses() {
    const auto verifyStack = [](const std::string& stack) {
        TempDirectory temp;
        const auto platform = makePlatform(temp);
        writeFile(temp.path() / "pam.d/passwd", stack);
        writeFile(temp.path() / "security/pam_pwquality.so", "test", 0555);
        return verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPwquality,
            platform.passwordServices);
    };

    const auto jump = verifyStack(
        "password [success=1 default=ignore] pam_unknown_vendor.so\n"
        "password requisite pam_pwquality.so\n"
        "password sufficient pam_permit.so\n");
    require(
        jump.state == fic::identity::pam::PamEnforcementState::Ineffective,
        "numeric jump over password enforcement must be rejected");

    const auto done = verifyStack(
        "password [success=done default=bad] pam_unknown_vendor.so\n"
        "password requisite pam_pwquality.so\n");
    require(
        done.state == fic::identity::pam::PamEnforcementState::Ineffective,
        "success=done before password enforcement must be rejected");
}

void testResetAndOptionalControlAreModeled() {
    TempDirectory temp;
    const auto platform = makePlatform(temp);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password optional pam_unknown_vendor.so\n"
        "password [success=reset default=bad] pam_permit.so\n"
        "password required pam_pwquality.so\n"
        "password sufficient pam_permit.so\n");
    writeFile(temp.path() / "security/pam_pwquality.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPwquality,
        platform.passwordServices);
    require(
        verification.state == fic::identity::pam::PamEnforcementState::Effective,
        "optional/reset control flow was modeled incorrectly: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testBypassThroughIncludeAndSubstack() {
    {
        TempDirectory temp;
        const auto platform = makePlatform(temp);
        writeFile(temp.path() / "pam.d/passwd",
                  "password include common-password\n");
        writeFile(
            temp.path() / "pam.d/common-password",
            "password sufficient pam_permit.so\n"
            "password requisite pam_pwhistory.so\n");
        writeFile(temp.path() / "security/pam_pwhistory.so", "test", 0555);
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordHistory,
            fic::identity::pam::PamProviderKind::PamPwhistory,
            platform.passwordServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Ineffective,
            "bypass through include must be rejected");
    }
    {
        TempDirectory temp;
        const auto platform = makePlatform(temp);
        writeFile(
            temp.path() / "pam.d/passwd",
            "password substack common-password\n"
            "password required pam_unix.so\n");
        writeFile(
            temp.path() / "pam.d/common-password",
            "password sufficient pam_unknown_vendor.so\n"
            "password requisite pam_pwhistory.so\n");
        writeFile(temp.path() / "security/pam_pwhistory.so", "test", 0555);
        const auto verification = verifyCapability(
            platform,
            fic::identity::pam::PamCapability::PasswordHistory,
            fic::identity::pam::PamProviderKind::PamPwhistory,
            platform.passwordServices);
        require(
            verification.state ==
                fic::identity::pam::PamEnforcementState::Ineffective,
            "done inside substack must not hide a provider bypass");
    }
}

void testUnknownAuthModuleCannotProveEnforcement() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"login"};
    writeFile(
        temp.path() / "pam.d/login",
        "auth sufficient pam_unknown_vendor.so\n"
        "auth required pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Ineffective,
        "unknown sufficient auth module must fail closed");
}

void testFailureAccountingBypass() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"login"};
    writeFile(
        temp.path() / "pam.d/login",
        "auth required pam_faillock.so preauth\n"
        "auth required pam_unix.so\n"
        "auth [success=1 default=ignore] pam_env.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Ineffective,
        "failed authentication path skipping authfail must be rejected");
    require(
        verification.detail.find("failure_accounting_bypass") !=
            std::string::npos,
        "failure-accounting diagnostic is missing: " + verification.detail);
}

void testCredentialFailureBeforeFaillockRemainsABypass() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"sshd"};
    writeFile(
        temp.path() / "pam.d/sshd",
        "auth requisite pam_userpass.so\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state ==
                fic::identity::pam::PamEnforcementState::Ineffective &&
            verification.detail.find("failure_accounting_bypass") !=
                std::string::npos,
        "credential failure before pam_faillock must remain a bypass: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testRequiredProviderListParsing() {
    std::vector<fic::identity::pam::PamProviderKind> providers;
    std::string normalized;
    std::string error;
    require(
        fic::identity::pam::parseRequiredPamProviders(
            " pam_faillock, pam_pwquality,pam_faillock ",
            providers,
            normalized,
            error),
        error);
    require(
        providers.size() == 2 &&
            normalized == "pam_faillock,pam_pwquality",
        "required PAM list must trim and deduplicate providers");
    require(
        fic::identity::pam::parseRequiredPamProviders(
            " pam_faillock , pam_passwdqc ",
            providers,
            normalized,
            error),
        error);
    require(
        providers == std::vector<fic::identity::pam::PamProviderKind>{
                         fic::identity::pam::PamProviderKind::PamFaillock,
                         fic::identity::pam::PamProviderKind::PamPasswdqc} &&
            normalized == "pam_faillock,pam_passwdqc",
        "pam_passwdqc must be normalized as a required PAM provider");
    require(
        fic::identity::pam::parseRequiredPamProviders(
            "pam_pwquality,pam_pwhistory,pam_passwdqc",
            providers,
            normalized,
            error),
        "all supported non-default providers must remain valid: " + error);
    require(
        fic::identity::pam::requiredPamProviderNames() ==
            std::vector<std::string>{
                "pam_faillock", "pam_pwquality", "pam_passwdqc",
                "pam_pwhistory"},
        "required PAM provider metadata is incomplete");
    require(
        !fic::identity::pam::parseRequiredPamProviders(
            "pam_faillock,,pam_pwquality",
            providers,
            normalized,
            error) && error.find("empty item") != std::string::npos,
        "empty required PAM list item must be rejected");
    require(
        !fic::identity::pam::parseRequiredPamProviders(
            "pam_vendor",
            providers,
            normalized,
            error) && error.find("unsupported") != std::string::npos,
        "unknown required PAM provider must be rejected");
}

void testPamOptionValueCodec() {
    using fic::identity::pam::PamOptionValueCodec;
    using fic::identity::pam::PamOptionValueEncoding;

    std::string encoded;
    std::string decoded;
    std::string error;
    require(
        PamOptionValueCodec::encode(
            PamOptionValueEncoding::YesNoInteger,
            "yes", encoded, error) && encoded == "1",
        error);
    require(
        PamOptionValueCodec::decode(
            PamOptionValueEncoding::YesNoInteger,
            "0", decoded, error) && decoded == "no",
        error);
    require(
        PamOptionValueCodec::encode(
            PamOptionValueEncoding::MinimumCredit,
            "2", encoded, error) && encoded == "-2",
        error);
    require(
        PamOptionValueCodec::decode(
            PamOptionValueEncoding::MinimumCredit,
            "-2", decoded, error) && decoded == "2",
        error);
    require(
        PamOptionValueCodec::encode(
            PamOptionValueEncoding::MinimumCredit,
            "0", encoded, error) && encoded == "0",
        error);
    require(
        PamOptionValueCodec::decode(
            PamOptionValueEncoding::MinimumCredit,
            "0", decoded, error) && decoded == "0",
        error);
    require(
        !PamOptionValueCodec::decode(
            PamOptionValueEncoding::MinimumCredit,
            "2", decoded, error),
        "positive native credit must not be interpreted as a minimum");
    require(
        !PamOptionValueCodec::encode(
            PamOptionValueEncoding::MinimumCredit,
            "-1", encoded, error),
        "negative logical minimum must be rejected");
}

void testTrustedPamServiceAliasSecurityContract() {
    const auto collect = [](
                             const fic::platform::PamPlatformConfig& platform,
                             const std::string& service,
                             std::vector<fic::identity::pam::PamRule>& rules,
                             std::set<std::filesystem::path>& sources,
                             std::string& error) {
        fic::identity::pam::PamConfiguration configuration(platform);
        return configuration.collectRules(
            service, fic::identity::pam::PamManagementGroup::Auth,
            rules, error, &sources);
    };
    const auto platformFor = [](const TempDirectory& temp, bool allow) {
        auto platform = makePlatform(temp);
        platform.authenticationServices = {"system-auth"};
        if (allow) {
            platform.trustedServiceAliases = {
                {temp.path() / "pam.d/system-auth",
                 {temp.path() / "pam.d/system-auth-local"}}
            };
        }
        return platform;
    };

    {
        TempDirectory temp;
        const auto platform = platformFor(temp, true);
        writeFile(temp.path() / "pam.d/system-auth-local",
                  "auth required pam_permit.so\n");
        std::filesystem::create_symlink(
            "system-auth-local", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(collect(platform, "system-auth", rules, sources, error), error);
        require(rules.size() == 1 &&
                    rules.front().source ==
                        temp.path() / "pam.d/system-auth-local" &&
                    sources.count(temp.path() / "pam.d/system-auth-local") == 1,
                "trusted alias did not expose its authoritative regular source");
    }
    {
        TempDirectory temp;
        const auto platform = platformFor(temp, false);
        writeFile(temp.path() / "pam.d/system-auth-local",
                  "auth required pam_permit.so\n");
        std::filesystem::create_symlink(
            "system-auth-local", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error) &&
                    error.find("symbolic link") != std::string::npos,
                "undeclared PAM service alias was accepted");
    }
    {
        TempDirectory temp;
        const auto platform = platformFor(temp, true);
        writeFile(temp.path() / "evil", "auth required pam_permit.so\n");
        std::filesystem::create_directories(temp.path() / "pam.d");
        std::filesystem::create_symlink(
            "../evil", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error) &&
                    error.find("escapes") != std::string::npos,
                "trusted alias ../ escape was accepted");
    }
    {
        TempDirectory temp;
        const auto platform = platformFor(temp, true);
        writeFile(temp.path() / "evil", "auth required pam_permit.so\n");
        std::filesystem::create_directories(temp.path() / "pam.d");
        std::filesystem::create_symlink(
            temp.path() / "evil", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error) &&
                    error.find("escapes") != std::string::npos,
                "trusted alias absolute directory escape was accepted");
    }
    {
        TempDirectory temp;
        const auto platform = platformFor(temp, true);
        writeFile(temp.path() / "pam.d/system-auth-vendor",
                  "auth required pam_permit.so\n");
        std::filesystem::create_symlink(
            "system-auth-vendor", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error) &&
                    error.find("unapproved target") != std::string::npos,
                "same-directory target outside exact allowlist was accepted");
    }
    {
        TempDirectory temp;
        const auto platform = platformFor(temp, true);
        writeFile(temp.path() / "pam.d/real",
                  "auth required pam_permit.so\n");
        std::filesystem::create_symlink(
            "real", temp.path() / "pam.d/system-auth-local");
        std::filesystem::create_symlink(
            "system-auth-local", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error),
                "trusted alias symlink chain was accepted");
    }
    for (const mode_t mode : {0664, 0646}) {
        TempDirectory temp;
        const auto platform = platformFor(temp, true);
        writeFile(temp.path() / "pam.d/system-auth-local",
                  "auth required pam_permit.so\n", mode);
        std::filesystem::create_symlink(
            "system-auth-local", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error),
                "writable trusted alias target was accepted");
    }
    {
        TempDirectory temp;
        const auto platform = platformFor(temp, true);
        std::filesystem::create_directories(
            temp.path() / "pam.d/system-auth-local");
        std::filesystem::create_symlink(
            "system-auth-local", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error),
                "non-regular trusted alias target was accepted");
    }
    {
        TempDirectory temp;
        auto platform = platformFor(temp, true);
        platform.trustedServiceAliases.front().allowedTargets = {
            temp.path() / "pam.d/system-auth"};
        std::filesystem::create_directories(temp.path() / "pam.d");
        std::filesystem::create_symlink(
            "system-auth", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error),
                "trusted alias cycle was accepted");
    }
    {
        TempDirectory temp;
        const auto platform = platformFor(temp, true);
        writeFile(temp.path() / "pam.d/system-auth-local",
                  "auth include system-auth\n");
        std::filesystem::create_symlink(
            "system-auth-local", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error) &&
                    error.find("cycle") != std::string::npos,
                "include cycle through trusted alias was accepted");
    }
    {
        TempDirectory temp;
        const auto platform = platformFor(temp, true);
        writeFile(temp.path() / "pam.d/system-auth-local", "auth [ broken\n");
        std::filesystem::create_symlink(
            "system-auth-local", temp.path() / "pam.d/system-auth");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-auth", rules, sources, error),
                "malformed trusted alias target was accepted");
    }
    {
        TempDirectory temp;
        auto platform = platformFor(temp, true);
        platform.authenticationServices = {"passwd"};
        writeFile(temp.path() / "evil", "auth required pam_permit.so\n");
        std::filesystem::create_directories(temp.path() / "pam.d");
        std::filesystem::create_symlink(
            temp.path() / "evil", temp.path() / "pam.d/passwd");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "passwd", rules, sources, error) &&
                    error.find("symbolic link") != std::string::npos,
                "arbitrary top-level symlink was accepted beside trusted alias");

        std::filesystem::remove(temp.path() / "pam.d/passwd");
        writeFile(temp.path() / "pam.d/passwd", "auth include included\n");
        std::filesystem::create_symlink(
            temp.path() / "evil", temp.path() / "pam.d/included");
        rules.clear();
        sources.clear();
        require(!collect(platform, "passwd", rules, sources, error) &&
                    error.find("symbolic link") != std::string::npos,
                "arbitrary included symlink was accepted beside trusted alias");
    }
}

void testLegacyPwhistoryNativeRememberSemantics() {
    using fic::identity::pam::PamPwhistoryArgumentState;
    using fic::identity::pam::PamPwhistoryArguments;

    const auto evaluate = [](const std::vector<std::string>& arguments,
                             PamPwhistoryArgumentState& state,
                             std::string& error) {
        fic::identity::pam::PamRule rule;
        rule.source = "/etc/pam.d/passwd";
        rule.line = 1;
        rule.group = fic::identity::pam::PamManagementGroup::Password;
        rule.control = "required";
        rule.module = "pam_pwhistory.so";
        rule.arguments = arguments;
        return PamPwhistoryArguments::evaluate(rule, state, error);
    };

    PamPwhistoryArgumentState state;
    std::string error;
    require(evaluate({"use_authtok"}, state, error) &&
                !state.rememberOverride.has_value() &&
                state.effectiveRemember() == 10,
            "absent legacy remember did not use native default");
    require(evaluate({"use_authtok", "remember=10"}, state, error) &&
                state.rememberOverride == 10 &&
                state.effectiveRemember() == 10,
            "explicit legacy remember=10 was not preserved");
    require(evaluate({"use_authtok", "remember=3"}, state, error) &&
                state.effectiveRemember() == 3,
            "explicit legacy remember=3 was not preserved");
    require(evaluate({"use_authtok", "remember=0"}, state, error) &&
                state.effectiveRemember() == 0,
            "explicit legacy remember=0 was not preserved");
    for (const auto& invalid : std::vector<std::vector<std::string>>{
             {"use_authtok", "remember="},
             {"use_authtok", "remember=abc"},
             {"use_authtok", "remember=-1"},
             {"use_authtok", "remember=3", "remember=5"},
             {"use_authtok", "remember"},
             {"remember=3"}}) {
        require(!evaluate(invalid, state, error),
                "invalid legacy pwhistory arguments were accepted");
    }
    require(evaluate(
                {"use_authtok", "enforce_for_root"}, state, error) &&
                state.enforceForRoot && state.effectiveRemember() == 10,
            "legacy enforce_for_root semantics regressed");

    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.passwordServices = {"passwd"};
    platform.capabilities[2].configurationMode =
        fic::platform::PamCapabilityConfigurationMode::ModuleArguments;
    platform.capabilities[2].configPath = "/etc/security/pwhistory.conf";
    writeFile(temp.path() / "security/pam_pwhistory.so", "test", 0555);
    writeFile(temp.path() / "pam.d/passwd",
              "password required pam_pwhistory.so use_authtok\n"
              "password required pam_unix.so use_authtok\n");
    auto verification = verifyCapability(
        platform, fic::identity::pam::PamCapability::PasswordHistory,
        fic::identity::pam::PamProviderKind::PamPwhistory,
        platform.passwordServices);
    require(verification.state ==
                fic::identity::pam::PamEnforcementState::Effective,
            "native default remember=10 was not security-effective: " +
                verification.detail);

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    require(fic::identity::pam::PamProviderInspector::inspect(
                configuration, platform.passwordServices,
                fic::identity::pam::PamCapability::PasswordHistory,
                fic::identity::pam::PamProviderKind::PamPwhistory,
                inspection, error), error);
    fic::identity::pam::PamProviderPolicyBinding binding;
    binding.option = "remember";
    binding.syntax = fic::identity::pam::PamNativeOptionSyntax::Assignment;
    require(!PamPwhistoryArguments::hasExpectedState(
                inspection, binding, "3", false, error),
            "native default remember=10 satisfied explicit policy depth 3");

    writeFile(temp.path() / "pam.d/passwd",
              "password required pam_pwhistory.so use_authtok remember=0\n"
              "password required pam_unix.so use_authtok\n");
    verification = verifyCapability(
        platform, fic::identity::pam::PamCapability::PasswordHistory,
        fic::identity::pam::PamProviderKind::PamPwhistory,
        platform.passwordServices);
    require(verification.state ==
                fic::identity::pam::PamEnforcementState::Ineffective,
            "explicit legacy remember=0 was considered effective");
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

void testPasswdqcConfigArgumentAndInlineOverride() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.capabilities[1].provider =
        fic::platform::PamProviderKind::PamPasswdqc;
    platform.passwordQualityConfigPath = temp.path() / "passwdqc.conf";
    writeFile(
        platform.passwordQualityConfigPath,
        "min=disabled,20,10,8,7\n"
        "enforce=everyone\n");
    writeFile(temp.path() / "security/pam_passwdqc.so", "test", 0555);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_passwdqc.so config=" +
            platform.passwordQualityConfigPath.string() + " min=24,11,8,7,7\n");

    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    require(
        fic::identity::pam::PamProviderInspector::inspect(
            configuration, platform.passwordServices,
            fic::identity::pam::PamCapability::PasswordQuality,
            fic::identity::pam::PamProviderKind::PamPasswdqc,
            inspection, error),
        error);
    require(
        fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            inspection, platform.passwordQualityConfigPath.string(),
            "min", "24,11,8,7,7", error),
        error);
    auto missingConfig = inspection;
    missingConfig.providerRules.front().arguments.erase(
        missingConfig.providerRules.front().arguments.begin());
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            missingConfig, platform.passwordQualityConfigPath.string(),
            "min", "24,11,8,7,7", error) &&
            error.find("requires PAM config=") != std::string::npos,
        "passwdqc without required config= was accepted");
    auto malformedConfig = missingConfig;
    malformedConfig.providerRules.front().arguments.insert(
        malformedConfig.providerRules.front().arguments.begin(), "config");
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            malformedConfig, platform.passwordQualityConfigPath.string(),
            "min", "24,11,8,7,7", error) &&
            error.find("requires an assigned value") != std::string::npos,
        "malformed passwdqc config argument was accepted");
    auto wrongConfig = inspection;
    wrongConfig.providerRules.front().arguments.front() =
        "config=/other/passwdqc.conf";
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            wrongConfig, platform.passwordQualityConfigPath.string(), "min",
            "24,11,8,7,7", error) &&
            error.find("another configuration file") != std::string::npos,
        "passwdqc config= path mismatch was not rejected");
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            inspection, platform.passwordQualityConfigPath.string(),
            "min", "disabled,24,11,8,7", error) &&
            error.find("effective passwdqc min") != std::string::npos,
        "passwdqc inline min override was not rejected");
    auto duplicateConfig = inspection;
    duplicateConfig.providerRules.front().arguments.push_back(
        "config=" + platform.passwordQualityConfigPath.string());
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            duplicateConfig, platform.passwordQualityConfigPath.string(),
            "min", "24,11,8,7,7", error) &&
            error.find("duplicate PAM argument config") != std::string::npos,
        "duplicate passwdqc config argument was accepted");
    auto duplicateOption = inspection;
    duplicateOption.providerRules.front().arguments.push_back(
        "min=24,11,8,7,7");
    require(
        fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            duplicateOption, platform.passwordQualityConfigPath.string(),
            "min", "24,11,8,7,7", error),
        "native sequential passwdqc option repetition was rejected: " +
            error);

    const std::string configArgument =
        "config=" + platform.passwordQualityConfigPath.string();
    auto invalidArgument = inspection;
    invalidArgument.providerRules.front().arguments = {
        configArgument, "max=garbage"};
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            invalidArgument, platform.passwordQualityConfigPath.string(),
            "min", "disabled,20,10,8,7", error),
        "invalid non-policy passwdqc argument was ignored");

    auto unknownArgument = inspection;
    unknownArgument.providerRules.front().arguments = {
        "vendor_unknown=value", configArgument};
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            unknownArgument, platform.passwordQualityConfigPath.string(),
            "min", "disabled,20,10,8,7", error),
        "unknown passwdqc argument was ignored");

    auto beforeConfig = inspection;
    beforeConfig.providerRules.front().arguments = {
        "min=disabled,24,11,8,7", configArgument};
    require(
        fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            beforeConfig, platform.passwordQualityConfigPath.string(),
            "min", "disabled,20,10,8,7", error),
        "passwdqc config= did not override an earlier PAM min argument: " +
            error);

    auto afterConfig = inspection;
    afterConfig.providerRules.front().arguments = {
        configArgument, "min=disabled,24,11,8,7"};
    require(
        fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            afterConfig, platform.passwordQualityConfigPath.string(),
            "min", "disabled,24,11,8,7", error),
        "passwdqc PAM min argument did not override preceding config=: " +
            error);

    auto randomOnly = inspection;
    randomOnly.providerRules.front().arguments = {
        configArgument, "random=47,only"};
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            randomOnly, platform.passwordQualityConfigPath.string(),
            "min", "disabled,20,10,8,7", error),
        "passwdqc random=47,only cross-option minimum effect was ignored");

    auto enforceBeforeConfig = inspection;
    enforceBeforeConfig.providerRules.front().arguments = {
        "enforce=none", configArgument};
    require(
        fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            enforceBeforeConfig, platform.passwordQualityConfigPath.string(),
            "enforce", "everyone", error),
        "passwdqc config= did not override earlier enforce=none: " + error);

    auto enforceAfterConfig = inspection;
    enforceAfterConfig.providerRules.front().arguments = {
        configArgument, "enforce=users"};
    require(
        !fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
            enforceAfterConfig, platform.passwordQualityConfigPath.string(),
            "enforce", "everyone", error) &&
            fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
                enforceAfterConfig,
                platform.passwordQualityConfigPath.string(),
                "enforce", "users", error),
        "passwdqc final enforce mapping ignored PAM argv ordering");

    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_passwdqc.so " + configArgument +
            " enforce=none\n"
        "password required pam_unix.so use_authtok\n");
    auto ineffective = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPasswdqc,
        platform.passwordServices);
    require(
        ineffective.state ==
            fic::identity::pam::PamEnforcementState::Ineffective,
        "passwdqc enforce=none was reported as effective");

    platform.passwordServices = {"passwd", "chpasswd"};
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_passwdqc.so " + configArgument + "\n"
        "password required pam_unix.so use_authtok\n");
    writeFile(
        temp.path() / "pam.d/chpasswd",
        "password required pam_passwdqc.so " + configArgument +
            " enforce=none\n"
        "password required pam_unix.so use_authtok\n");
    ineffective = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPasswdqc,
        platform.passwordServices);
    require(
        ineffective.state ==
            fic::identity::pam::PamEnforcementState::Ineffective,
        "one ineffective passwdqc service was hidden by another service");
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
        testOptionalExternalConfigRequiresNativeDefaultPath();
        testFlagConflictingOptionFails();
        testWritableProviderFileFails();
        testWritableConfigurationFileFails();
        testOptionFileUpdatesAllDefinitions();
        testOptionFileSymlinkFails();
        testOptionFileFlagEnableDisable();
        testMalformedOptionFileFlagFailsWithoutWrite();
        testPwqualityEnforcingStateAndServices();
        testPwqualityEffectiveTopologyAndArguments();
        testPwqualityLineLengthBoundary();
        testPwqualityInvalidInputsAreBroken();
        testGenericFallbackFailsClosed();
        testEffectiveKnownProviders();
        testDebianPamAuthUpdateGeneratedStackIsEffective();
        testSubstackBoundaryIsEffective();
        testFaillockAccountTopologyIsEffective();
        testMissingInactiveAndBrokenStates();
        testAuthenticationEarlySuccessBypass();
        testTrustedSuRootokPathIsAccepted();
        testRootokOutsideTrustedServiceIsRejected();
        testSddmSucceedIfGateIsEffective();
        testSucceedIfSufficientBypassIsRejected();
        testGateSuccessDoesNotMaskCredentialFailure();
        testGateFailureIsNotCredentialFailure();
        testPasswordEarlySuccessBypass();
        testExtendedControlBypasses();
        testResetAndOptionalControlAreModeled();
        testBypassThroughIncludeAndSubstack();
        testUnknownAuthModuleCannotProveEnforcement();
        testFailureAccountingBypass();
        testCredentialFailureBeforeFaillockRemainsABypass();
        testRequiredProviderListParsing();
        testPamOptionValueCodec();
        testTrustedPamServiceAliasSecurityContract();
        testLegacyPwhistoryNativeRememberSemantics();
        testPasswordHistoryAlternativeIsDetected();
        testPasswdqcConfigArgumentAndInlineOverride();
    } catch (const std::exception& error) {
        std::cerr << "PamConfigurationTests failed: " << error.what() << '\n';
        return 1;
    }
    std::cout << "PamConfigurationTests passed\n";
    return 0;
}
