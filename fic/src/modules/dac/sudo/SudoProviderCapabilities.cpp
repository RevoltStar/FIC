#include "modules/dac/sudo/SudoProviderCapabilities.h"

#include <fic/core/process/ProcessExecutor.h>
#include <fic/core/process/VerifiedProcessExecutor.h>

#include <set>
#include <sys/stat.h>

namespace fic::sudoers {
bool classifySudoProviderVersion(const std::string& output,
                                SudoProviderCapabilities& result, std::string& error) {
    result = {};
    const auto first = output.substr(0, output.find('\n'));
    if (first.compare(0, 13, "Sudo version ") == 0) {
        const auto version = first.substr(13);
        const std::set<std::string> admitted{
            "1.9.13p3", "1.9.16p2", "1.9.15p5", "1.9.17p2"};
        if (!admitted.count(version)) {
            error = "Classic sudo version has no proven capability contract: " + version;
            return false;
        }
        result.provider = SudoProvider::Classic;
        result.version = version;
        result.envReset = SudoCapabilityGuarantee::Configurable;
        result.exemptGroupDisabled = SudoCapabilityGuarantee::Configurable;
        result.continuationArgumentsProven = true;
    } else if (first.compare(0, 8, "sudo-rs ") == 0) {
        const auto version = first.substr(8);
        // Explicit admission, not "every future Rust provider has the same
        // semantics". Distro package revisions are retained in the witness.
        if (version != "0.2.13" && version != "0.2.13-0ubuntu1.2") {
            error = "sudo-rs version has no proven capability contract: " + version;
            return false;
        }
        result.provider = SudoProvider::Rust;
        result.version = version;
        result.envReset = SudoCapabilityGuarantee::VerifiedByConstruction;
        result.exemptGroupDisabled = SudoCapabilityGuarantee::VerifiedByConstruction;
        // Do not authorize multiline authentication rewrites from the version
        // number alone: historical argument-loss defects include this version.
        result.continuationArgumentsProven = false;
    } else {
        error = "Unknown active sudo provider version output";
        return false;
    }
    error.clear();
    return true;
}

bool detectSudoProviderCapabilities(
    const fic::platform::SudoPlatformConfig& config,
    const fic::platform::PlatformExecutableResolver& executables,
    SudoProviderCapabilities& capabilities, std::string& error, bool verifyHash) {
    capabilities = {};
    std::filesystem::path validator;
    if (!executables.resolve(fic::platform::ExecutableId::Visudo, validator, error))
        return false;
    std::filesystem::path executable;
    if (!executables.resolve(fic::platform::ExecutableId::Sudo, executable, error)) return false;
    struct stat info {};
    if (::lstat(executable.c_str(), &info) || !S_ISREG(info.st_mode) ||
        info.st_uid != 0 || (info.st_mode & 0022)) {
        error = "Active sudo executable is not trusted";
        return false;
    }
    ProcessOptions options;
    options.clearEnvironment = true;
    const std::vector<std::string> arguments{"--version"};
    const auto version = verifyHash
        ? VerifiedProcessExecutor::execute(executable.string(), arguments, options)
        : ProcessExecutor::execute(executable.string(), arguments, options);
    if (!version.success()) { error = "Cannot inspect active sudo version: " + version.error; return false; }
    SudoProviderCapabilities admitted;
    if (!classifySudoProviderVersion(version.standardOutput, admitted, error)) return false;
    const bool rustRoute = executable == "/usr/lib/cargo/bin/sudo" &&
                           validator == "/usr/lib/cargo/bin/visudo";
    const bool classicRoute = (executable == "/usr/bin/sudo" && validator == "/usr/sbin/visudo") ||
                             (executable == "/usr/bin/sudo.ws" && validator == "/usr/sbin/visudo.ws");
    if ((admitted.provider == SudoProvider::Rust && !rustRoute) ||
        (admitted.provider == SudoProvider::Classic && !classicRoute) ||
        config.mainConfigPath != "/etc/sudoers") {
        error = "Active sudo provider/configuration/validator route is not proven";
        return false;
    }
    if (admitted.provider == SudoProvider::Classic &&
        version.standardOutput.find("Sudoers path: " + config.mainConfigPath.string() + "\n") ==
            std::string::npos) {
        error = "Classic sudo reports a different or unproven sudoers path";
        return false;
    }
    // Resolver must still select the same authoritative validator, and the
    // selector must still name the provider whose version we just inspected.
    std::filesystem::path validatorAfter;
    std::filesystem::path executableAfter;
    if (!executables.resolve(fic::platform::ExecutableId::Visudo, validatorAfter, error) ||
        !executables.resolve(fic::platform::ExecutableId::Sudo, executableAfter, error) ||
        validatorAfter != validator || executableAfter != executable) {
        error = "Active sudo provider changed during capability detection";
        return false;
    }
    admitted.executable = executable;
    admitted.validator = validator;
    admitted.mainPath = config.mainConfigPath;
    capabilities = std::move(admitted);
    error.clear();
    return true;
}
} // namespace fic::sudoers
