#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamOptionFile.h"
#include "modules/identity_access/pam/PamOptionValueCodec.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamProviderInspector.h"
#include "modules/identity_access/pam/PamPwhistoryArguments.h"
#include "modules/identity_access/pam/PamProviderSemanticVerifier.h"
#include "modules/identity_access/pam/PwhistoryConfigFile.h"
#include "platform/PlatformProfile.h"

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
             fic::platform::PamTopologyStrategyKind::StaticVerifyOnly, {}},
            {fic::platform::PamCapability::PasswordQuality,
             fic::platform::PamProviderKind::PamPwquality,
             fic::platform::PamScope::EffectivePasswordStack, {},
             fic::platform::PamTopologyStrategyKind::StaticVerifyOnly, {}},
            {fic::platform::PamCapability::PasswordHistory,
             fic::platform::PamProviderKind::PamPwhistory,
             fic::platform::PamScope::EffectivePasswordStack, {},
             fic::platform::PamTopologyStrategyKind::StaticVerifyOnly, {}}
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
    // Step 7D: the typed pwhistory config backend evaluates the REAL
    // topology, so the test fixture must bind the descriptor default
    // topology to the temporary primary path (no drop-ins upstream).
    auto historyTopology = fic::identity::pam::pamProviderDescriptor(
        fic::platform::PamProviderKind::PamPwhistory).defaultConfigTopology;
    historyTopology.primaryPath = platform.passwordHistoryConfigPath;
    platform.capabilities[2].configTopology = std::move(historyTopology);
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
        "auth [success=2 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail" + configArgument +
            " " + authExtra + "\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n");
    writeFile(
        temp.path() / "pam.d/common-account",
        "account required pam_faillock.so" + configArgument + "\n"
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
    if ((provider == fic::identity::pam::PamProviderKind::PamPwquality ||
            provider == fic::identity::pam::PamProviderKind::PamPwhistory) &&
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
    writeFile(
        temp.path() / "pam.d/common-account",
        "account required pam_unix.so\n");

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
        "generic structural capability ignored an active fallback: " +
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
        "generic structural capability ignored unmanaged drop-ins");

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
        "auth [success=2 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "auth required pam_faillock.so authsucc\n");
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
        "auth [success=3 default=bad] pam_unix.so\n"
        "auth [success=1 default=ignore] pam_env.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "auth required pam_faillock.so authsucc\n");
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

void testPamSucceedIfTrustedBypassMustMatchExactRule() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"gdm-password"};
    platform.trustedAuthenticationBypasses = {
        {"gdm-password", "pam_succeed_if.so",
         fic::platform::PamTrustedAuthenticationBypassReason::
             ExplicitPasswordlessLogin,
         "sufficient", {"user", "ingroup", "nopasswdlogin"},
         temp.path() / "pam.d/gdm-password"}
    };
    const auto stack = [](const std::string& rule) {
        return rule + "\n" +
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n";
    };
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verify = [&](const std::string& service,
                            const std::string& content) {
        writeFile(temp.path() / ("pam.d/" + service), content);
        return verifyCapability(
            platform,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            {service});
    };

    writeFile(
        temp.path() / "pam.d/common-login",
        "auth [success=2 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "auth required pam_faillock.so authsucc\n");
    const auto exact = verify(
        "gdm-password",
        "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\n"
        "auth substack common-login\n");
    require(exact.state == fic::identity::pam::PamEnforcementState::Effective,
            "exact ALT passwordless path was rejected: " +
                fic::identity::pam::formatPamCapabilityVerification(exact));
    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamControlFlowAnalysis analysis;
    std::string error;
    require(fic::identity::pam::PamControlFlowAnalyzer::analyze(
                configuration, platform, "gdm-password",
                fic::identity::pam::PamCapability::AuthenticationLockout,
                fic::identity::pam::PamProviderKind::PamFaillock,
                analysis, error), error);
    require(analysis.acceptedTrustedAuthenticationBypasses.size() == 1 &&
                analysis.acceptedTrustedAuthenticationBypasses.front().service ==
                    "gdm-password" &&
                analysis.acceptedTrustedAuthenticationBypasses.front().module ==
                    "pam_succeed_if.so" &&
                analysis.acceptedTrustedAuthenticationBypasses.front().reason ==
                    fic::platform::PamTrustedAuthenticationBypassReason::
                        ExplicitPasswordlessLogin &&
                analysis.acceptedTrustedAuthenticationBypasses.front().source ==
                    temp.path() / "pam.d/gdm-password",
            "exact passwordless acceptance evidence is incomplete");

    for (const std::string& control : {"required", "optional"}) {
        (void)verify(
            "gdm-password",
            stack("auth " + control +
                  " pam_succeed_if.so user ingroup nopasswdlogin"));
        fic::identity::pam::PamConfiguration controlConfiguration(platform);
        analysis = {};
        require(fic::identity::pam::PamControlFlowAnalyzer::analyze(
                    controlConfiguration, platform, "gdm-password",
                    fic::identity::pam::PamCapability::AuthenticationLockout,
                    fic::identity::pam::PamProviderKind::PamFaillock,
                    analysis, error), error);
        require(analysis.acceptedTrustedAuthenticationBypasses.empty(),
                "non-sufficient passwordless rule was trusted: " + control);
    }

    for (const std::string& untrusted : {
             "auth sufficient pam_succeed_if.so user ingroup wheel",
             "auth sufficient pam_succeed_if.so user ingroup other-group",
             "auth sufficient pam_succeed_if.so quiet user ingroup nopasswdlogin",
             "auth sufficient pam_succeed_if.so user ingroup",
             "auth sufficient pam_succeed_if.so ingroup nopasswdlogin user"}) {
        const auto rejected = verify("gdm-password", stack(untrusted));
        require(rejected.state ==
                    fic::identity::pam::PamEnforcementState::Ineffective &&
                    rejected.detail.find("authentication_bypass") !=
                        std::string::npos,
                "non-exact pam_succeed_if bypass was trusted: " + untrusted);
    }

    platform.authenticationServices.push_back("other-service");
    const auto otherService = verify(
        "other-service",
        stack("auth sufficient pam_succeed_if.so user ingroup nopasswdlogin"));
    require(otherService.state ==
                fic::identity::pam::PamEnforcementState::Ineffective,
            "passwordless rule was trusted for another service");

    writeFile(temp.path() / "pam.d/gdm-password-include",
              "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\n");
    const auto included = verify(
        "gdm-password",
        "auth include gdm-password-include\n"
        "auth substack common-login\n");
    require(included.state ==
                fic::identity::pam::PamEnforcementState::Ineffective &&
                included.detail.find("authentication_bypass") !=
                    std::string::npos,
            "passwordless rule from an include source was not rejected: " +
                fic::identity::pam::formatPamCapabilityVerification(included));
    fic::identity::pam::PamConfiguration includedConfiguration(platform);
    analysis = {};
    require(fic::identity::pam::PamControlFlowAnalyzer::analyze(
                includedConfiguration, platform, "gdm-password",
                fic::identity::pam::PamCapability::AuthenticationLockout,
                fic::identity::pam::PamProviderKind::PamFaillock,
                analysis, error), error);
    require(analysis.acceptedTrustedAuthenticationBypasses.empty(),
            "passwordless rule from an untrusted source was accepted");
}

void testAltLightdmPasswordlessBypassMustMatchExactRule() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"lightdm", "other-service"};
    platform.trustedAuthenticationBypasses = {
        {"lightdm", "pam_succeed_if.so",
         fic::platform::PamTrustedAuthenticationBypassReason::
             ExplicitPasswordlessLogin,
         "sufficient", {"user", "ingroup", "nopasswdlogin"},
         temp.path() / "pam.d/lightdm"}
    };
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    writeFile(
        temp.path() / "pam.d/common-login",
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=1 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth sufficient pam_faillock.so authsucc\n"
        "auth required pam_deny.so\n");
    const auto stack = [](const std::string& rule) {
        return rule + "\n" + "auth substack common-login\n";
    };
    const auto verify = [&](const std::string& service,
                            const std::string& content) {
        writeFile(temp.path() / ("pam.d/" + service), content);
        return verifyCapability(
            platform,
            fic::identity::pam::PamCapability::AuthenticationLockout,
            fic::identity::pam::PamProviderKind::PamFaillock,
            {service});
    };
    const auto acceptedBypasses = [&](const std::string& service) {
        fic::identity::pam::PamConfiguration configuration(platform);
        fic::identity::pam::PamControlFlowAnalysis analysis;
        std::string error;
        require(fic::identity::pam::PamControlFlowAnalyzer::analyze(
                    configuration, platform, service,
                    fic::identity::pam::PamCapability::AuthenticationLockout,
                    fic::identity::pam::PamProviderKind::PamFaillock,
                    analysis, error),
                error);
        return analysis.acceptedTrustedAuthenticationBypasses;
    };

    const auto exact = verify(
        "lightdm",
        stack("auth sufficient pam_succeed_if.so user ingroup nopasswdlogin"));
    require(exact.state == fic::identity::pam::PamEnforcementState::Effective &&
                exact.detail.find("authentication_bypass") ==
                    std::string::npos &&
                acceptedBypasses("lightdm").size() == 1,
            "exact ALT LightDM passwordless path was rejected: " +
                fic::identity::pam::formatPamCapabilityVerification(exact));

    const auto wrongArguments = verify(
        "lightdm",
        stack("auth sufficient pam_succeed_if.so user ingroup wheel"));
    require(wrongArguments.state ==
                fic::identity::pam::PamEnforcementState::Ineffective &&
                wrongArguments.detail.find("authentication_bypass") !=
                    std::string::npos,
            "LightDM passwordless rule with different argv was trusted");

    const auto wrongService = verify(
        "other-service",
        stack("auth sufficient pam_succeed_if.so user ingroup nopasswdlogin"));
    require(wrongService.state ==
                fic::identity::pam::PamEnforcementState::Ineffective &&
                wrongService.detail.find("authentication_bypass") !=
                    std::string::npos,
            "LightDM passwordless rule was trusted for another service");

    writeFile(temp.path() / "pam.d/lightdm-passwordless",
              "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\n");
    const auto wrongSource = verify(
        "lightdm",
        "auth include lightdm-passwordless\n"
        "auth substack common-login\n");
    require(wrongSource.state ==
                fic::identity::pam::PamEnforcementState::Ineffective &&
                wrongSource.detail.find("authentication_bypass") !=
                    std::string::npos,
            "LightDM passwordless rule from another source was trusted");

    const auto wrongControl = verify(
        "lightdm",
        stack("auth optional pam_succeed_if.so user ingroup nopasswdlogin"));
    require(wrongControl.state ==
                fic::identity::pam::PamEnforcementState::Effective &&
                acceptedBypasses("lightdm").empty(),
            "LightDM passwordless rule with another control was trusted");
}

void testAltGdmAuxiliaryKeyringPathIsEffective() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"gdm-password"};
    platform.trustedAuthenticationBypasses = {
        {"gdm-password", "pam_succeed_if.so",
         fic::platform::PamTrustedAuthenticationBypassReason::
             ExplicitPasswordlessLogin,
         "sufficient", {"user", "ingroup", "nopasswdlogin"},
         temp.path() / "pam.d/gdm-password"}
    };
    writeFile(
        temp.path() / "pam.d/gdm-password",
        "#%PAM-1.0\n"
        "auth required pam_shells.so\n"
        "auth required pam_succeed_if.so quiet uid ne 0\n"
        "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\n"
        "auth substack common-login\n"
        "auth optional pam_gnome_keyring.so\n"
        "account required pam_nologin.so\n"
        "account include common-login\n");
    writeFile(
        temp.path() / "pam.d/common-login",
        "#%PAM-1.0\n"
        "auth substack system-auth\n"
        "auth substack system-policy\n"
        "auth required pam_nologin.so\n"
        "account substack system-auth\n"
        "account substack system-policy\n"
        "account required pam_nologin.so\n");
    writeFile(
        temp.path() / "pam.d/system-auth",
        "#%PAM-1.0\n"
        "auth include system-auth-local-only\n"
        "auth include system-auth-common\n"
        "account include system-auth-local-only\n"
        "account include system-auth-common\n");
    writeFile(
        temp.path() / "pam.d/system-auth-local-only",
        "#%PAM-1.0\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth sufficient pam_tcb.so shadow fork nullok\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "account required pam_faillock.so\n"
        "account required pam_tcb.so shadow fork\n");
    writeFile(temp.path() / "pam.d/system-auth-common", "#%PAM-1.0\n");
    writeFile(temp.path() / "pam.d/system-policy", "#%PAM-1.0\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);

    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state == fic::identity::pam::PamEnforcementState::Effective,
        "real ALT GDM keyring path was rejected: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testPamTcbCredentialFailureBypassingAuthfailIsRejected() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"login"};
    writeFile(
        temp.path() / "pam.d/login",
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=1 auth_err=done default=bad] pam_tcb.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth required pam_permit.so\n"
        "account required pam_faillock.so\n");
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
                std::string::npos &&
            verification.detail.find("pam_tcb.so -> PAM_AUTH_ERR") !=
                std::string::npos,
        "pam_tcb credential failure bypass was not detected: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
}

void testSddmSucceedIfGateIsEffective() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"sddm"};
    platform.trustedAuthenticationExclusions = {
        {"sddm", "pam_succeed_if.so",
         fic::platform::PamTrustedAuthenticationExclusionReason::
             ExplicitSubjectExclusion,
         "root", "required", {"user", "!=", "root", "quiet_success"},
         temp.path() / "pam.d/sddm"}
    };
    writeFile(
        temp.path() / "pam.d/sddm",
        "auth required pam_succeed_if.so user != root quiet_success\n"
        "auth [success=2 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "auth required pam_faillock.so authsucc\n");
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
        "auth [success=2 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "auth required pam_faillock.so authsucc\n");
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
        "auth [success=3 default=bad] pam_unix.so\n"
        "auth [success=1 default=ignore] pam_env.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "account required pam_faillock.so\n"
        "account required pam_unix.so\n");
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
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=1 default=ignore] pam_env.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth required pam_permit.so\n"
        "account required pam_faillock.so\n"
        "account required pam_unix.so\n");
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
        "auth [success=3 default=bad] pam_unix.so\n"
        "auth [success=1 default=ignore] pam_env.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "account required pam_faillock.so\n"
        "account required pam_unix.so\n");
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
        "auth requisite pam_tcb.so\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=2 default=bad] pam_unix.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "account required pam_faillock.so\n"
        "account required pam_unix.so\n");
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

void testCredentialCollectorFailureBeforeGateIsNotAccountingBypass() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.authenticationServices = {"sshd"};
    writeFile(
        temp.path() / "pam.d/sshd",
        "auth required pam_userpass.so\n"
        "auth include system-check-localuser\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth [success=2 default=bad] pam_tcb.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
        "account required pam_faillock.so\n"
        "account required pam_tcb.so\n");
    writeFile(
        temp.path() / "pam.d/system-check-localuser",
        "auth [success=1 perm_denied=ignore default=die] pam_localuser.so\n"
        "auth optional pam_permit.so\n");
    writeFile(temp.path() / "security/pam_faillock.so", "test", 0555);
    const auto verification = verifyCapability(
        platform,
        fic::identity::pam::PamCapability::AuthenticationLockout,
        fic::identity::pam::PamProviderKind::PamFaillock,
        platform.authenticationServices);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Effective,
        "pam_userpass collection or pam_localuser gate failure was treated "
        "as an unaccounted credential rejection: " +
            fic::identity::pam::formatPamCapabilityVerification(verification));
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
                 {temp.path() / "pam.d/system-auth-local",
                  temp.path() / "pam.d/system-auth-sss"}}
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
    for (const auto& [alias, target] :
         std::vector<std::pair<std::string, std::string>>{
             {"system-auth", "system-auth-sss"},
             {"system-auth-use_first_pass",
              "system-auth-use_first_pass-sss"},
             {"system-check-localuser", "system-check-localuser-legacy"},
             {"system-check-localuser", "system-check-localuser-systemd"}}) {
        TempDirectory temp;
        auto platform = makePlatform(temp);
        platform.authenticationServices = {alias};
        platform.trustedServiceAliases = {
            {temp.path() / "pam.d" / alias,
             {temp.path() / "pam.d" / target}}};
        writeFile(temp.path() / "pam.d" / target,
                  "auth required pam_permit.so\n");
        std::filesystem::create_symlink(
            target, temp.path() / "pam.d" / alias);
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(collect(platform, alias, rules, sources, error) &&
                    rules.size() == 1 &&
                    rules.front().source == temp.path() / "pam.d" / target,
                "exact ALT PAM alias target was rejected: " + target +
                    ": " + error);
    }
    for (const auto& [target, targetKind] :
         std::vector<std::pair<std::string, std::string>>{
             {"system-check-localuser-evil", "regular"},
             {"../evil", "escape"},
             {"/tmp/evil", "absolute"},
             {"system-check-localuser-systemd", "nested"},
             {"system-check-localuser-systemd", "writable"},
             {"system-check-localuser-systemd", "directory"}}) {
        TempDirectory temp;
        auto platform = makePlatform(temp);
        platform.authenticationServices = {"system-check-localuser"};
        platform.trustedServiceAliases = {
            {temp.path() / "pam.d/system-check-localuser",
             {temp.path() / "pam.d/system-check-localuser-legacy",
              temp.path() / "pam.d/system-check-localuser-systemd"}}};
        const auto targetPath = temp.path() / "pam.d" / target;
        if (targetKind == "regular") {
            writeFile(targetPath, "auth required pam_permit.so\n");
        } else if (targetKind == "nested") {
            writeFile(temp.path() / "pam.d/real",
                      "auth required pam_permit.so\n");
            std::filesystem::create_symlink("real", targetPath);
        } else if (targetKind == "writable") {
            writeFile(targetPath, "auth required pam_permit.so\n", 0664);
        } else if (targetKind == "directory") {
            std::filesystem::create_directories(targetPath);
        } else {
            std::filesystem::create_directories(temp.path() / "pam.d");
        }
        std::filesystem::create_symlink(
            target, temp.path() / "pam.d/system-check-localuser");
        std::vector<fic::identity::pam::PamRule> rules;
        std::set<std::filesystem::path> sources;
        std::string error;
        require(!collect(platform, "system-check-localuser", rules,
                         sources, error),
                "unsafe system-check-localuser " + targetKind +
                    " target was accepted");
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

// ---------------------------------------------------------------------------
// Step 7D: typed pwhistory config evaluator + semantic backend.
// ---------------------------------------------------------------------------

using fic::identity::pam::PwhistoryConfigEvaluator;
using fic::identity::pam::PwhistoryEffectiveState;

fic::platform::PamProviderConfigTopology makePwhistoryTestTopology(
    const std::filesystem::path& primary) {
    fic::platform::PamProviderConfigTopology topology;
    topology.primaryPath = primary;
    topology.explicitConfig =
        fic::platform::PamExplicitConfigSemantics::ReplacesNativeTopology;
    return topology;
}

// Upstream fidelity of the config parser/evaluator:
// pam_modutil_search_key first-match (case-insensitive) per key,
// '#' comments, space/tab/'=' separators, conservative integer parsing;
// defaults remember=10/retry=1; module argv parsed AFTER the config and
// overrides it; missing primary fails closed (vendor fallback).
void testPwhistoryConfigFirstMatchSemantics() {
    TempDirectory temp;
    const auto primary = temp.path() / "pwhistory.conf";
    const auto topology = makePwhistoryTestTopology(primary);
    const auto evaluate = [&](const std::string& content,
                              const std::vector<std::string>& arguments = {},
                              bool* ok = nullptr) {
        writeFile(primary, content);
        PwhistoryEffectiveState state;
        std::string error;
        const bool success =
            PwhistoryConfigEvaluator::evaluateInvocation(
                arguments, primary, 1, topology, state, error);
        if (ok != nullptr) {
            *ok = success;
        }
        return std::pair<PwhistoryEffectiveState, std::string>(state, error);
    };

    // First match wins; later duplicates are inert (a last-match
    // implementation would report 40).
    {
        const auto [state, error] = evaluate("remember = 2\nremember = 40\n");
        require(error.empty() && state.remember == 2,
            "the evaluator must use the FIRST matching remember key, got " +
                std::to_string(state.remember) + ": " + error);
    }
    // Case-insensitive first match.
    {
        const auto [state, error] =
            evaluate("REMEMBER = 2\nReMeMbEr = 40\n");
        require(error.empty() && state.remember == 2,
            "the evaluator must match keys case-insensitively, got " +
                std::to_string(state.remember) + ": " + error);
    }
    // Comments (full-line and inline), leading whitespace, separators.
    {
        const auto [state, error] = evaluate(
            "# remember = 99\n   remember\t= 5 # trailing\nretry=3\n"
            "remember  =  7\n");
        require(error.empty() && state.remember == 5 && state.retry == 3,
            "comment/whitespace/separator handling regressed: " + error);
    }
    // Defaults on an existing empty file.
    {
        const auto [state, error] = evaluate("");
        require(error.empty() && state.remember == 10 && state.retry == 1 &&
                    !state.enforceForRoot,
            "upstream defaults remember=10/retry=1 were not modeled: " +
                error);
    }
    // Presence flags in the config file (upstream enables them whenever
    // the key search returns a value — the value is ignored).
    {
        const auto [state, error] = evaluate("enforce_for_root = 0\ndebug\n");
        require(error.empty() && state.enforceForRoot && state.debug,
            "config presence-flag semantics regressed: " + error);
    }
    // Unknown config keys are inert (upstream reads only the known keys).
    {
        const auto [state, error] = evaluate("whatever = 1\nremember = 4\n");
        require(error.empty() && state.remember == 4,
            "unknown config keys must stay inert: " + error);
    }
    // Malformed ACTIVE first occurrence of a known key → fail closed.
    for (const auto& content : std::vector<std::string>{
             "remember = abc\n", "remember\n", "remember =\n",
             "remember = -3\n"}) {
        bool ok = true;
        evaluate(content, {}, &ok);
        require(!ok,
            "malformed pwhistory directive must fail closed: " + content);
    }
    // Missing primary fails closed (vendor fallback cannot be proven).
    {
        std::filesystem::remove(primary);
        PwhistoryEffectiveState state;
        std::string error;
        require(!PwhistoryConfigEvaluator::evaluateInvocation(
                    {}, primary, 1, topology, state, error),
            "a missing pwhistory primary must fail closed");
        require(error.find("does not exist") != std::string::npos,
            "the absent-primary diagnostic is missing: " + error);
    }
    // Module argv parsed AFTER the config → overrides it (last-wins).
    {
        const auto [state, error] =
            evaluate("remember = 5\n", {"use_authtok", "remember=20"});
        require(error.empty() && state.remember == 20,
            "the PAM argv remember must override the config file: " + error);
    }
    // argv remember=0 disables history (upstream PAM_IGNORE).
    {
        const auto [state, error] =
            evaluate("remember = 5\n", {"remember=0"});
        require(error.empty() && state.remember == 0,
            "argv remember=0 must disable history: " + error);
    }
    // Upstream argv clamp [0, 400].
    {
        const auto [state, error] = evaluate("", {"remember=500"});
        require(error.empty() && state.remember == 400,
            "the upstream argv remember clamp must be modeled: " + error);
    }
    // Upstream argv option NAMES are matched case-insensitively
    // (strcasecmp / pam_str_skip_icase_prefix): valid case variants of the
    // inert transport options must be accepted and must NOT change the
    // effective state. Each variant is evaluated SEPARATELY — the strict
    // duplicate-argv contract (Step 7D follow-up) rejects two occurrences
    // of the same kind within ONE invocation.
    {
        for (const auto& variant : std::vector<std::string>{
                 "TRY_FIRST_PASS", "Try_First_Pass", "USE_FIRST_PASS",
                 "Use_First_Pass", "USE_AUTHTOK", "Use_Authtok",
                 "AUTHTOK_TYPE=", "Authtok_Type=Password"}) {
            const auto [state, error] =
                evaluate("remember = 10\n", {variant});
            require(error.empty() && state.remember == 10,
                "case variant of the inert pwhistory argv options must be "
                    "accepted without changing the effective remember: " +
                    variant + ": " + error);
        }
    }
    // Active argv options are matched case-insensitively too (upstream
    // pam_str_skip_icase_prefix on the option name).
    {
        const auto [state, error] = evaluate("", {"REMEMBER=20"});
        require(error.empty() && state.remember == 20,
            "the argv REMEMBER=20 case variant must be applied: " + error);
    }
    {
        const auto [state, error] = evaluate("", {"EnFoRcE_FoR_RoOt"});
        require(error.empty() && state.enforceForRoot,
            "the argv EnFoRcE_FoR_RoOt case variant must enable "
                "enforce_for_root: " +
                error);
    }
    {
        const auto [state, error] = evaluate("", {"DEBUG"});
        require(error.empty() && state.debug,
            "the argv DEBUG case variant must enable debug: " + error);
    }
    // Step 7D semantic cleanup: the presence flags debug and
    // enforce_for_root are WHOLE-TOKEN options upstream
    // (strcasecmp over the whole token) — ANY valued form, including an
    // EMPTY assignment, is a different token and must fail closed
    // BEFORE state evaluation instead of silently enabling the flag.
    for (const auto& arguments : std::vector<std::vector<std::string>>{
             {"debug=x"}, {"DEBUG=x"}, {"debug="}, {"DeBuG=1"},
             {"enforce_for_root=yes"}, {"enforce_for_root="},
             {"EnFoRcE_FoR_RoOt="}, {"ENFORCE_FOR_ROOT=yes"}}) {
        bool ok = true;
        const auto [state, error] = evaluate("", arguments, &ok);
        require(!ok,
            "a valued pwhistory presence-flag token must fail closed: " +
                error);
        require(
            error.find("must not have a value") != std::string::npos,
            "the valued flag diagnostic must name the whole-token "
            "contract: " + error);
        require(!state.debug && !state.enforceForRoot,
            "a refused valued flag token must not enable any flag: " +
                error);
    }
    {
        const auto [state, error] =
            evaluate("", {"FILE=/run/fic-opasswd"});
        require(error.empty() && state.file == "/run/fic-opasswd",
            "the argv FILE= case variant must be applied: " + error);
    }
    // A VALUED use_authtok token is NOT the upstream flag (strcasecmp
    // compares the whole token) → unknown argument, fail closed.
    {
        bool ok = true;
        evaluate("", {"use_authtok=yes"}, &ok);
        require(!ok,
            "a valued use_authtok argv token must fail closed");
    }
    // Upstream conf= selection is CASE-SENSITIVE
    // (pam_str_skip_prefix, NOT the icase variant): "CONF=..." is not a
    // config selector and falls through to the fail-closed unknown
    // argument handling instead of being silently interpreted as conf=.
    {
        bool ok = true;
        const auto [state, error] =
            evaluate("remember = 10\n", {"CONF=/etc/other.conf"}, &ok);
        require(!ok,
            "the uppercase CONF= argv prefix must NOT be treated as the "
            "case-sensitive conf= selector");
        require(error.find("unknown pwhistory PAM argument") !=
                std::string::npos,
            "CONF= must fail closed as an unknown argument: " + error);
    }
    // The lowercase conf= selector itself stays inert for the evaluator
    // (the file selection is a separate external contract).
    {
        const auto [state, error] =
            evaluate("remember = 10\n", {"conf=/etc/security/pwhistory.conf"});
        require(error.empty() && state.remember == 10,
            "the lowercase conf= selector must stay inert: " + error);
    }
    // Unknown PAM arguments fail closed (stricter than the upstream
    // silent ignore, per the FIC ambiguous-input policy).
    {
        PwhistoryEffectiveState state;
        std::string error;
        writeFile(primary, "");
        require(!PwhistoryConfigEvaluator::evaluateInvocation(
                    {"nullok"}, primary, 1, topology, state, error),
            "unknown pwhistory PAM arguments must fail closed");
    }
    // Valued enforce_for_root argv fails closed (ambiguous input).
    {
        PwhistoryEffectiveState state;
        std::string error;
        writeFile(primary, "");
        require(!PwhistoryConfigEvaluator::evaluateInvocation(
                    {"enforce_for_root=yes"}, primary, 1, topology, state,
                    error),
            "a valued pwhistory flag argument must fail closed");
    }
}

// Step 7D follow-up: strict duplicate-argv contract. Upstream applies
// duplicate argv keys last-wins; FIC rejects the whole invocation BEFORE
// any state evaluation (fail closed). Option NAMES are matched
// case-insensitively, so case variants and identical duplicates of the
// same kind are rejected alike; conf= stays outside this contract.
void testPwhistoryDuplicatePamArgumentsFailClosed() {
    TempDirectory temp;
    const auto primary = temp.path() / "pwhistory.conf";
    const auto topology = makePwhistoryTestTopology(primary);
    const auto evaluate = [&](const std::vector<std::string>& arguments) {
        writeFile(primary, "");
        PwhistoryEffectiveState state;
        std::string error;
        const bool ok = PwhistoryConfigEvaluator::evaluateInvocation(
            arguments, primary, 1, topology, state, error);
        return std::pair<bool, std::string>(ok, error);
    };

    // Duplicate remember assignments (mixed case and identical
    // duplicates included): an identical effective result does not make
    // the input unambiguous.
    for (const auto& arguments : std::vector<std::vector<std::string>>{
             {"remember=10", "remember=20"},
             {"remember=10", "REMEMBER=20"},
             {"remember=10", "REMEMBER=10"}}) {
        const auto [ok, error] = evaluate(arguments);
        require(!ok,
            "duplicate pwhistory remember argv must fail closed: " + error);
        require(
            error.find("duplicate pwhistory PAM argument remember") !=
                std::string::npos,
            "the duplicate remember diagnostic is missing: " + error);
    }
    // Representative remaining assignments: retry and file.
    for (const auto& arguments : std::vector<std::vector<std::string>>{
             {"retry=2", "RETRY=3"}, {"file=/a", "FILE=/b"}}) {
        const auto [ok, error] = evaluate(arguments);
        require(!ok,
            "duplicate pwhistory assignment argv must fail closed: " +
                error);
    }
    // Flags reject duplicates case-insensitively.
    for (const auto& arguments : std::vector<std::vector<std::string>>{
             {"enforce_for_root", "EnFoRcE_FoR_RoOt"}, {"debug", "DEBUG"}}) {
        const auto [ok, error] = evaluate(arguments);
        require(!ok,
            "duplicate pwhistory flag argv must fail closed: " + error);
    }
    // A valued malformed variant does NOT bypass the uniqueness contract:
    // "debug DEBUG=x" must fail closed (either as malformed or as a
    // duplicate — SUCCESS is never acceptable).
    for (const auto& arguments : std::vector<std::vector<std::string>>{
             {"debug", "DEBUG=x"}, {"debug=x", "debug"},
             {"enforce_for_root", "EnFoRcE_FoR_RoOt="}}) {
        const auto [ok, error] = evaluate(arguments);
        require(!ok,
            "a mixed valid/malformed pwhistory flag argv must fail "
            "closed: " + error);
    }
    // The diagnostic names the option kind, not the raw token casing.
    {
        const auto [ok, error] =
            evaluate({"enforce_for_root", "EnFoRcE_FoR_RoOt"});
        require(
            error.find("duplicate pwhistory PAM argument enforce_for_root") !=
                std::string::npos,
            "the duplicate flag diagnostic must name the option kind: " +
                error);
    }
    // Inert transport options reject duplicates too (strict uniqueness
    // for ALL known pwhistory argv kinds).
    for (const auto& arguments : std::vector<std::vector<std::string>>{
             {"use_authtok", "USE_AUTHTOK"},
             {"authtok_type=foo", "AUTHTOK_TYPE=bar"},
             {"try_first_pass", "TRY_FIRST_PASS"},
             {"use_first_pass", "use_first_pass"}}) {
        const auto [ok, error] = evaluate(arguments);
        require(!ok,
            "duplicate inert pwhistory argv must fail closed: " + error);
    }
    // conf= is NOT part of the case-insensitive option contract: an
    // uppercase CONF= token is an unknown pwhistory argument — never a
    // second config selector. The pair therefore fails closed for the
    // UNKNOWN reason, while lowercase conf= duplicates stay governed by
    // the case-sensitive external config contract.
    {
        const auto [ok, error] = evaluate({"conf=/a", "CONF=/b"});
        require(!ok, "conf=/a CONF=/b must fail closed: " + error);
        require(error.find("unknown pwhistory PAM argument CONF=/b") !=
                std::string::npos,
            "CONF= must be rejected as an unknown argument, not as a "
            "duplicate conf= selector: " + error);
    }
    // Valid single case variants still apply with upstream semantics
    // (the contract rejects duplicates, not case-insensitive matching).
    {
        PwhistoryEffectiveState state;
        std::string error;
        writeFile(primary, "");
        require(
            PwhistoryConfigEvaluator::evaluateInvocation(
                {"REMEMBER=20", "RETRY=4", "FILE=/foo", "EnFoRcE_FoR_RoOt",
                    "USE_AUTHTOK", "AUTHTOK_TYPE=x"},
                primary, 1, topology, state, error) &&
                state.remember == 20 && state.retry == 4 &&
                state.file == "/foo" && state.enforceForRoot,
            "valid single case-variant argv must keep upstream effective "
            "semantics: " +
                error);
    }
}

// Semantic backend (verifyOption / canApplyOption) over the REAL config:
// prospective BOF preflight, argv override preflight refusal, conf=
// external contract, and the Debian 12 ModuleArguments backend priority.
void testPwhistoryManagedOptionSemantics() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.passwordServices = {"passwd"};
    platform.capabilities[2].topology =
        fic::platform::PamTopologyStrategyKind::PamAuthUpdate;
    writeFile(temp.path() / "security/pam_pwhistory.so", "test", 0555);
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() + "\n");
    writeFile(platform.passwordHistoryConfigPath, "remember = 3\n");

    const auto inspect = [&]() {
        fic::identity::pam::PamConfiguration configuration(platform);
        fic::identity::pam::PamProviderInspection inspection;
        std::string error;
        require(
            fic::identity::pam::PamProviderInspector::inspect(
                configuration, platform.passwordServices,
                fic::identity::pam::PamCapability::PasswordHistory,
                fic::identity::pam::PamProviderKind::PamPwhistory,
                inspection, error),
            error);
        return inspection;
    };
    const auto& capability = platform.capabilities[2];

    // §10: the CURRENT config remember=3 must NOT reject the prospective
    // FIC BOF remember=10 (first-match override after the mutation).
    std::string error;
    require(
        fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
            inspect(), capability, "remember", "10", error),
        "the prospective BOF override must not be rejected by the current "
        "foreign value: " + error);

    // §11: the postcondition reads the ACTUAL physical config. Write a
    // real FIC BOF block (canonical grammar) and prove the effective
    // first-match value.
    writeFile(
        platform.passwordHistoryConfigPath,
        "# FIC_PAM_PROVIDER_BLOCK_BEGIN version=1 provider=pam_pwhistory "
        "lead=none\n"
        "# FIC_PAM_ENTRY_BEGIN version=1 "
        "policy=password_history_depth mutation=42\n"
        "remember = 10\n"
        "# FIC_PAM_ENTRY_END\n"
        "# FIC_PAM_PROVIDER_BLOCK_END\n"
        "remember = 3\n");
    require(
        fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspect(), capability, "remember", "10", error),
        "the FIC BOF entry must be proven effective over the foreign "
        "remember = 3: " + error);
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspect(), capability, "remember", "3", error),
        "the foreign remember = 3 must not satisfy the managed state");

    // §29: a conflicting PAM argv override fails the preflight, and the
    // postcondition proves the ARGV value, not the config value.
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() +
            " use_authtok remember=20\n");
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
            inspect(), capability, "remember", "10", error),
        "a conflicting PAM argv remember must fail the preflight closed");
    require(
        fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
            inspect(), capability, "remember", "20", error),
        "the effective value under the argv override is 20: " + error);

    // §30: a same-valued argv is acceptable.
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() +
            " remember=10\n");
    require(
        fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
            inspect(), capability, "remember", "10", error),
        "a same-valued PAM argv remember must be acceptable: " + error);

    // §31: a wrong conf= target must fail the preflight BEFORE any
    // journal mutation would happen (the FIC file would be ineffective).
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=/tmp/other.conf\n");
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
            inspect(), capability, "remember", "10", error),
        "a wrong conf= target must fail the external config contract");

    // Step 7D follow-up: a DUPLICATE known PAM argv option fails the
    // managed preflight closed — the upstream last-wins effective value
    // (20) is never accepted as the semantic proof, and the rejection
    // happens before any state evaluation (no partial prospective
    // modeling of an ambiguous argv set).
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() +
            " remember=10 REMEMBER=20\n");
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
            inspect(), capability, "remember", "10", error),
        "a duplicate PAM argv remember must fail the preflight closed");
    require(
        error.find("duplicate pwhistory PAM argument remember") !=
            std::string::npos,
        "the duplicate argv preflight diagnostic is missing: " + error);

    // §29b: the same duplicate contract at the prospective BOF level —
    // the FIC BOF remember=requested must not turn "remember=10
    // REMEMBER=20" into an effective-20 conflict; the argv set itself is
    // rejected first.
    writeFile(
        platform.passwordHistoryConfigPath, "remember = 3\n");
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() +
            " remember=10 REMEMBER=20\n");
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
            inspect(), capability, "remember", "10", error),
        "a duplicate PAM argv remember must fail the prospective BOF "
        "preflight closed (not an effective-20 conflict)");

    // conf= duplicates stay governed by the CASE-SENSITIVE external
    // config contract (verifyExternalConfigContract), not by the
    // case-insensitive option contract.
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() + " conf=" +
            platform.passwordHistoryConfigPath.string() + "\n");
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
            inspect(), capability, "remember", "10", error),
        "duplicate lowercase conf= selectors must fail the external "
        "config contract");
    require(
        error.find("duplicate PAM argument conf") != std::string::npos,
        "the duplicate conf= external-config diagnostic is missing: " +
            error);

    // conf=/a CONF=/b: the uppercase token is NOT a second selector —
    // the external contract passes and the rejection reason is the
    // unknown argv token.
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() + " CONF=/b\n");
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
            inspect(), capability, "remember", "10", error),
        "conf=/a CONF=/b must fail closed");
    require(
        error.find("unknown pwhistory PAM argument CONF=/b") !=
            std::string::npos,
        "CONF=/b must be rejected as an unknown argument, not as a "
        "duplicate conf= selector: " + error);

    // The legacy-writer flag preflight (canApplyFlag) enforces the same
    // duplicate-argv contract.
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() +
            " enforce_for_root EnFoRcE_FoR_RoOt\n");
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::canApplyFlag(
            inspect(), capability, "enforce_for_root", true, {}, error),
        "a duplicate PAM argv enforce_for_root must fail the flag "
        "preflight closed");
    require(
        error.find("duplicate pwhistory PAM argument enforce_for_root") !=
            std::string::npos,
        "the duplicate flag preflight diagnostic is missing: " + error);

    // Step 7D semantic cleanup: the legacy-writer flag preflight uses the
    // TYPED case-insensitive pwhistory argv semantics.
    // canApplyFlag(false): a mixed-case argv enforce_for_root override is
    // unreachable for the legacy config writer and must fail the
    // preflight closed BEFORE any mutation.
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() +
            " EnFoRcE_FoR_RoOt\n");
    const auto readConfig = [](const std::filesystem::path& path) {
        std::ifstream input(path);
        return std::string(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
    };
    const std::string preflightConfigBefore =
        readConfig(platform.passwordHistoryConfigPath);
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::canApplyFlag(
            inspect(), capability, "enforce_for_root", false, {}, error),
        "a mixed-case argv enforce_for_root must fail the disabled flag "
        "preflight closed");
    require(
        error.find("overrides the requested disabled state") !=
            std::string::npos,
        "the argv-override preflight diagnostic is missing: " + error);
    require(
        readConfig(platform.passwordHistoryConfigPath) ==
            preflightConfigBefore,
        "the refused argv-override preflight must not mutate the config");
    // canApplyFlag(true): the same-effective argv is NOT a conflict.
    require(
        fic::identity::pam::PamProviderSemanticVerifier::canApplyFlag(
            inspect(), capability, "enforce_for_root", true, {}, error),
        "a same-effective mixed-case argv must not block the enabled "
        "flag preflight: " + error);
    // Case variants are semantically identical for the preflight — no
    // case-sensitive generic fallback.
    for (const auto& argvFlag : std::vector<std::string>{
             "enforce_for_root", "ENFORCE_FOR_ROOT", "EnFoRcE_FoR_RoOt"}) {
        writeFile(
            temp.path() / "pam.d/passwd",
            "password required pam_pwhistory.so conf=" +
                platform.passwordHistoryConfigPath.string() + " " +
                argvFlag + "\n");
        require(
            !fic::identity::pam::PamProviderSemanticVerifier::canApplyFlag(
                inspect(), capability, "enforce_for_root", false, {},
                error),
            "every case variant of the argv flag must fail the disabled "
            "preflight closed: " + argvFlag);
        require(
            fic::identity::pam::PamProviderSemanticVerifier::canApplyFlag(
                inspect(), capability, "enforce_for_root", true, {}, error),
            "every case variant of the argv flag must keep the enabled "
            "preflight valid: " + argvFlag + ": " + error);
    }
    // A valued flag token fails the preflight closed as well.
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so conf=" +
            platform.passwordHistoryConfigPath.string() +
            " enforce_for_root=\n");
    require(
        !fic::identity::pam::PamProviderSemanticVerifier::canApplyFlag(
            inspect(), capability, "enforce_for_root", true, {}, error),
        "an empty-assignment enforce_for_root token must fail the flag "
        "preflight closed");
    require(
        error.find("must not have a value") != std::string::npos,
        "the valued flag preflight diagnostic is missing: " + error);

    // §41: Debian 12 ModuleArguments capability keeps the specialized
    // pwhistoryArguments backend with priority (the config evaluator is
    // never reached there).
    auto argumentsPlatform = platform;
    argumentsPlatform.capabilities[2].configurationMode =
        fic::platform::PamCapabilityConfigurationMode::ModuleArguments;
    argumentsPlatform.capabilities[2].configPath =
        "/etc/security/pwhistory.conf";
    writeFile(
        temp.path() / "pam.d/passwd",
        "password required pam_pwhistory.so use_authtok remember=7\n");
    {
        fic::identity::pam::PamConfiguration configuration(argumentsPlatform);
        fic::identity::pam::PamProviderInspection inspection;
        require(
            fic::identity::pam::PamProviderInspector::inspect(
                configuration, argumentsPlatform.passwordServices,
                fic::identity::pam::PamCapability::PasswordHistory,
                fic::identity::pam::PamProviderKind::PamPwhistory,
                inspection, error),
            error);
        require(
            fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
                inspection, argumentsPlatform.capabilities[2], "remember",
                "7", error),
            "the ModuleArguments backend must keep priority on Debian 12: " +
                error);
    }
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

void testAltPasswdqcUsesOnlyLocalPasswordBranch() {
    TempDirectory temp;
    auto platform = makePlatform(temp);
    platform.scopes.push_back({
        fic::platform::PamScope::LocalPasswordChange,
        {"system-auth-local-only"}});
    platform.capabilities[1].provider =
        fic::platform::PamProviderKind::PamPasswdqc;
    platform.capabilities[1].scope =
        fic::platform::PamScope::LocalPasswordChange;
    platform.capabilities[1].subjectScope =
        fic::platform::PamIdentitySubjectScope::LocalUsersOnly;
    platform.passwordQualityConfigPath = temp.path() / "passwdqc.conf";
    writeFile(platform.passwordQualityConfigPath, "enforce=everyone\n");
    writeFile(temp.path() / "security/pam_passwdqc.so", "test", 0555);
    writeFile(
        temp.path() / "pam.d/system-auth-local-only",
        "password required pam_passwdqc.so config=" +
            platform.passwordQualityConfigPath.string() + "\n"
        "password required pam_tcb.so use_authtok\n");
    writeFile(
        temp.path() / "pam.d/system-auth-sss-only",
        "password required pam_sss.so use_authtok\n");
    writeFile(
        temp.path() / "pam.d/system-auth-sss",
        "password substack system-auth-local-only\n"
        "password substack system-auth-sss-only\n");

    const fic::platform::PamCapabilityConfig* capability = nullptr;
    const std::vector<std::string>* services = nullptr;
    std::string error;
    require(
        fic::identity::pam::resolveCapability(
            platform, fic::platform::PamCapability::PasswordQuality,
            capability, services, error),
        error);
    require(
        capability != nullptr &&
            capability->subjectScope ==
                fic::platform::PamIdentitySubjectScope::LocalUsersOnly &&
            services != nullptr &&
            *services == std::vector<std::string>{"system-auth-local-only"},
        "ALT passwdqc capability did not resolve to the local password "
        "branch");

    auto verification = verifyCapability(
        platform, fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPasswdqc, *services);
    require(
        verification.state ==
            fic::identity::pam::PamEnforcementState::Effective,
        "remote pam_sss password branch incorrectly required passwdqc: " +
            fic::identity::pam::formatPamCapabilityVerification(
                verification));

    writeFile(
        temp.path() / "pam.d/system-auth-local-only",
        "password required pam_tcb.so use_authtok\n");
    verification = verifyCapability(
        platform, fic::identity::pam::PamCapability::PasswordQuality,
        fic::identity::pam::PamProviderKind::PamPasswdqc, *services);
    require(
        verification.state !=
            fic::identity::pam::PamEnforcementState::Effective,
        "ALT local password branch without passwdqc was accepted");
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--live-alt-alias") {
            const auto profile = fic::platform::makeBuildPlatformProfile();
            require(profile.id == "alt-p11", "live alias gate requires ALT p11");
            const auto alias = std::filesystem::path(
                "/etc/pam.d/system-check-localuser");
            require(std::filesystem::is_symlink(
                        std::filesystem::symlink_status(alias)),
                    "native system-check-localuser symlink is missing");
            fic::identity::pam::PamConfiguration configuration(profile.pam);
            std::vector<fic::identity::pam::PamRule> rules;
            std::set<std::filesystem::path> sources;
            std::string error;
            require(configuration.collectRules(
                        "system-check-localuser",
                        fic::identity::pam::PamManagementGroup::Auth,
                        rules, error, &sources), error);
            require(!rules.empty(), "native alias has no auth rules");
            std::cout << "native ALT PAM alias accepted: "
                      << std::filesystem::read_symlink(alias) << '\n';
            return 0;
        }
        require(argc == 1, "unknown pam_configuration_tests arguments");
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
        testPamSucceedIfTrustedBypassMustMatchExactRule();
        testAltLightdmPasswordlessBypassMustMatchExactRule();
        testAltGdmAuxiliaryKeyringPathIsEffective();
        testPamTcbCredentialFailureBypassingAuthfailIsRejected();
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
        testCredentialCollectorFailureBeforeGateIsNotAccountingBypass();
        testPamOptionValueCodec();
        testTrustedPamServiceAliasSecurityContract();
        testLegacyPwhistoryNativeRememberSemantics();
        testPwhistoryConfigFirstMatchSemantics();
        testPwhistoryDuplicatePamArgumentsFailClosed();
        testPwhistoryManagedOptionSemantics();
        testPasswordHistoryAlternativeIsDetected();
        testPasswdqcConfigArgumentAndInlineOverride();
        testAltPasswdqcUsesOnlyLocalPasswordBranch();
    } catch (const std::exception& error) {
        std::cerr << "PamConfigurationTests failed: " << error.what() << '\n';
        return 1;
    }
    std::cout << "PamConfigurationTests passed\n";
    return 0;
}
