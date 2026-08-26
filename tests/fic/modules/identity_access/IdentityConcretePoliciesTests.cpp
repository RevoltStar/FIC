#include "modules/identity_access/kerberos/policies/KerberosTicketLifetimePolicy.h"
#include "modules/identity_access/sssd/policies/SssdOfflineCredentialsExpirationPolicy.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const fs::path& path,
               const std::string& content,
               mode_t mode) {
    fs::create_directories(path.parent_path());
    ::chmod(path.parent_path().c_str(), 0755);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not create " + path.string());
    output << content;
    output.close();
    require(output.good(), "could not write " + path.string());
    require(::chmod(path.c_str(), mode) == 0, "could not chmod " + path.string());
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "could not read " + path.string());
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

fic::identity::SecureConfigurationFileOptions secureFile(
    const fs::path& path,
    std::optional<mode_t> exactMode = std::nullopt) {
    fic::identity::SecureConfigurationFileOptions options;
    options.path = fs::absolute(path);
    options.expectedOwner = ::geteuid();
    options.expectedGroup = ::getegid();
    options.exactMode = exactMode;
    options.forbiddenMode = 0022;
    return options;
}

void initializeRuntimePaths(const fs::path& root) {
    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
    paths.languageDir = root / "lang";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.dataDir = root / "data";
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "data/commandhash.txt";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/devices.lock";
    paths.lockDebugLogFile = root / "log/db-lock.log";
    fs::create_directories(paths.configDir);
    fs::create_directories(paths.logDir);
    fs::create_directories(paths.dataDir);
    writeFile(
        paths.configDir / "IDENTITY_ACCESS.conf",
        "sssd_offline_credentials_expiration.status=ENABLE\n"
        "sssd_offline_credentials_expiration.value=30\n"
        "kerberos_ticket_lifetime.status=ENABLE\n"
        "kerberos_ticket_lifetime.value=7200\n",
        0644);
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
}

fic::platform::PlatformExecutableResolver makeResolver(
    const fs::path& systemctl) {
    fic::platform::PlatformExecutables executables;
    executables.entries.push_back(
        {fic::platform::ExecutableId::Systemctl, {systemctl}});
    fic::platform::PlatformExecutableResolverOptions options;
    options.enforceTrustedOwnership = false;
    return fic::platform::PlatformExecutableResolver(
        std::move(executables), options);
}

fic::identity::sssd::SssdConfigurationOptions sssdOptions(
    const fs::path& main) {
    fic::identity::sssd::SssdConfigurationOptions options;
    options.mainFile = secureFile(main, 0600);
    return options;
}

void testSssdPolicyRestartsActiveService(const fs::path& root) {
    const fs::path main = root / "system/sssd-success.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 0\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    std::vector<std::vector<std::string>> calls;
    auto runner = [&calls](const std::string&,
                           const std::vector<std::string>& arguments,
                           const ProcessOptions&) {
        calls.push_back(arguments);
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        return result;
    };
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main), resolver, {"sssd.service"}, runner);
    require(policy.apply(), "SSSD policy failed");
    require(
        readFile(main).find("offline_credentials_expiration = 30") !=
            std::string::npos,
        "SSSD policy did not update the option");
    require(calls.size() == 3 && calls[1].front() == "restart",
            "SSSD policy did not inspect, restart and verify the service");
}

void testSssdPolicyRollsBackAfterRestartFailure(const fs::path& root) {
    const fs::path main = root / "system/sssd-rollback.conf";
    const std::string original =
        "[pam]\noffline_credentials_expiration = 7\n";
    writeFile(main, original, 0600);
    const fs::path systemctl = root / "bin/systemctl";
    auto resolver = makeResolver(systemctl);
    int restartCalls = 0;
    auto runner = [&restartCalls](const std::string&,
                                  const std::vector<std::string>& arguments,
                                  const ProcessOptions&) {
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        if (!arguments.empty() && arguments.front() == "restart" &&
            restartCalls++ == 0) {
            result.exitCode = 1;
        }
        return result;
    };
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main), resolver, {"sssd.service"}, runner);
    require(!policy.apply(), "SSSD restart failure must fail the policy");
    require(readFile(main) == original,
            "SSSD restart failure did not restore the original file");
    require(restartCalls == 2,
            "SSSD rollback did not restart the restored configuration");
}

void testSssdPolicyDoesNotStartInactiveService(const fs::path& root) {
    const fs::path main = root / "system/sssd-inactive.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 0\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    auto resolver = makeResolver(systemctl);
    int calls = 0;
    auto runner = [&calls](const std::string&,
                           const std::vector<std::string>& arguments,
                           const ProcessOptions&) {
        ++calls;
        require(arguments.front() == "is-active",
                "inactive SSSD service was started or restarted");
        ProcessResult result;
        result.started = true;
        result.exitCode = 3;
        return result;
    };
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main), resolver, {"sssd.service"}, runner);
    require(policy.apply(), "SSSD policy failed for an inactive service");
    require(calls == 1, "inactive SSSD service received an unexpected command");
    require(
        readFile(main).find("offline_credentials_expiration = 30") !=
            std::string::npos,
        "SSSD policy did not persist configuration for the next start");
}

void testKerberosTicketLifetimePolicy(const fs::path& root) {
    const fs::path main = root / "system/krb5.conf";
    writeFile(main, "[libdefaults]\nticket_lifetime = 10h\n", 0644);
    fic::identity::kerberos::KerberosConfigurationOptions options;
    options.mainFile = secureFile(main);
    KerberosTicketLifetimePolicy policy(std::move(options));
    require(policy.apply(), "Kerberos ticket lifetime policy failed");
    require(readFile(main).find("ticket_lifetime = 7200s") != std::string::npos,
            "Kerberos policy wrote an unexpected duration");
}

} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() /
        ("fic-identity-policy-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root);
    ::chmod(root.c_str(), 0755);
    try {
        initializeRuntimePaths(root);
        testSssdPolicyRestartsActiveService(root);
        testSssdPolicyRollsBackAfterRestartFailure(root);
        testSssdPolicyDoesNotStartInactiveService(root);
        testKerberosTicketLifetimePolicy(root);
    } catch (const std::exception& error) {
        std::cerr << "IdentityConcretePoliciesTests failed: "
                  << error.what() << '\n';
        fs::remove_all(root);
        return 1;
    }
    fs::remove_all(root);
    std::cout << "IdentityConcretePoliciesTests passed\n";
    return 0;
}
