#include "platform/PlatformCompatibility.h"
#include "platform/PlatformExecutableResolver.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <utility>

namespace fic::platform {
namespace {

std::string trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    }).base();
    if (first >= last) {
        return "";
    }
    return std::string(first, last);
}

bool contains(const std::vector<std::string>& values, const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

std::string join(const std::vector<std::string>& values) {
    std::string result;
    for (const std::string& value : values) {
        if (!result.empty()) {
            result += ", ";
        }
        result += value;
    }
    return result;
}

bool decodeValue(const std::string& encoded, std::string& value) {
    if (encoded.empty() || (encoded.front() != '"' && encoded.front() != '\'')) {
        value = encoded;
        return true;
    }

    const char quote = encoded.front();
    if (encoded.size() < 2 || encoded.back() != quote) {
        return false;
    }

    value.clear();
    for (size_t index = 1; index + 1 < encoded.size(); ++index) {
        const char ch = encoded[index];
        if (quote == '"' && ch == '\\' && index + 2 < encoded.size()) {
            const char escaped = encoded[++index];
            if (escaped == '"' || escaped == '\\' || escaped == '$' || escaped == '`') {
                value.push_back(escaped);
            } else {
                value.push_back('\\');
                value.push_back(escaped);
            }
            continue;
        }
        value.push_back(ch);
    }
    return true;
}

bool validAbsolutePath(const std::filesystem::path& path) {
    return path.is_absolute() && path == path.lexically_normal();
}

bool validateExecutableCandidates(
    const std::vector<std::filesystem::path>& candidates,
    const std::string& label,
    std::string& error) {
    if (candidates.empty()) {
        error = label + " candidates are empty";
        return false;
    }
    std::set<std::filesystem::path> uniqueCandidates;
    for (const std::filesystem::path& candidate : candidates) {
        if (!validAbsolutePath(candidate)) {
            error = label + " candidate must be an absolute normalized path: " +
                    candidate.string();
            return false;
        }
        if (!uniqueCandidates.insert(candidate).second) {
            error = label + " candidate is duplicated: " + candidate.string();
            return false;
        }
    }
    return true;
}

bool validateExecutables(const PlatformExecutables& executables,
                         std::string& error) {
    const std::vector<ExecutableId> supportedIds = allExecutableIds();
    std::set<ExecutableId> uniqueIds;
    for (const PlatformExecutableSpec& spec : executables.entries) {
        if (std::find(supportedIds.begin(), supportedIds.end(), spec.id) ==
            supportedIds.end()) {
            error = "platform profile contains an unsupported executable identifier";
            return false;
        }
        if (!uniqueIds.insert(spec.id).second) {
            error = std::string("executable is duplicated in platform profile: ") +
                    executableIdName(spec.id);
            return false;
        }
        if (!validateExecutableCandidates(
                spec.candidates, executableIdName(spec.id), error)) {
            return false;
        }
    }
    for (const ExecutableId id : supportedIds) {
        const PlatformExecutableSpec* spec =
            findExecutableSpec(executables, id);
        if (spec == nullptr || !spec->required) {
            error = std::string("platform profile must define required executable: ") +
                    executableIdName(id);
            return false;
        }
    }
    return true;
}

bool validatePath(const std::filesystem::path& path,
                  const std::string& label,
                  std::string& error) {
    if (!validAbsolutePath(path)) {
        error = label + " must be an absolute normalized path";
        return false;
    }
    return true;
}

bool validatePaths(const std::vector<std::filesystem::path>& paths,
                   const std::string& label,
                   std::string& error) {
    if (paths.empty()) {
        error = label + " list is empty";
        return false;
    }
    for (const std::filesystem::path& path : paths) {
        if (!validatePath(path, label, error)) {
            return false;
        }
    }
    return true;
}

bool validatePamServices(const std::vector<std::string>& services,
                         const std::string& label,
                         std::string& error) {
    if (services.empty()) {
        error = label + " list is empty";
        return false;
    }

    std::set<std::string> uniqueServices;
    for (const std::string& service : services) {
        if (service.empty() ||
            !std::all_of(service.begin(), service.end(), [](unsigned char ch) {
                return std::isalnum(ch) != 0 || ch == '_' || ch == '-' || ch == '.';
            })) {
            error = label + " contains an invalid PAM service name: " + service;
            return false;
        }
        if (!uniqueServices.insert(service).second) {
            error = label + " contains a duplicated PAM service: " + service;
            return false;
        }
    }
    return true;
}

bool validatePamTrustedAuthenticationBypasses(
    const PamPlatformConfig& pam,
    std::string& error) {
    std::set<std::pair<std::string, std::string>> uniqueRules;
    for (const auto& rule : pam.trustedAuthenticationBypasses) {
        if (!contains(pam.authenticationServices, rule.service)) {
            error = "trusted PAM authentication bypass references an "
                "unverified service: " + rule.service;
            return false;
        }
        if (rule.module.empty() ||
            !std::all_of(
                rule.module.begin(), rule.module.end(), [](unsigned char ch) {
                    return std::isalnum(ch) != 0 || ch == '_' || ch == '-' ||
                        ch == '.';
                }) ||
            rule.module.find('/') != std::string::npos) {
            error = "trusted PAM authentication bypass contains an invalid "
                "module name: " + rule.module;
            return false;
        }
        switch (rule.reason) {
        case PamTrustedAuthenticationBypassReason::AlreadyPrivilegedCaller:
            break;
        default:
            error = "trusted PAM authentication bypass contains an "
                "unsupported reason";
            return false;
        }
        if (!uniqueRules.emplace(rule.service, rule.module).second) {
            error = "trusted PAM authentication bypass is duplicated: " +
                rule.service + ":" + rule.module;
            return false;
        }
    }
    return true;
}

bool validateArguments(const std::vector<std::string>& arguments,
                       const std::string& label,
                       std::string& error) {
    for (const std::string& argument : arguments) {
        if (argument.empty() || argument.find_first_of("\r\n") !=
                std::string::npos || argument.find('\0') != std::string::npos) {
            error = label + " contains an invalid argument";
            return false;
        }
    }
    return true;
}

bool validateFileAccessRules(const std::vector<FileAccessRule>& rules,
                             const std::string& label,
                             std::string& error) {
    if (rules.empty()) {
        error = label + " list is empty";
        return false;
    }
    std::set<std::filesystem::path> uniquePaths;
    for (const FileAccessRule& rule : rules) {
        if (!validatePath(rule.path, label + " path", error)) {
            return false;
        }
        if (rule.owner.empty() || rule.group.empty()) {
            error = label + " owner and group must not be empty: " +
                    rule.path.string();
            return false;
        }
        if (rule.permissions == 0 || (rule.permissions & ~07777U) != 0) {
            error = label + " permissions are invalid: " + rule.path.string();
            return false;
        }
        if (!uniquePaths.insert(rule.path).second) {
            error = label + " path is duplicated: " + rule.path.string();
            return false;
        }
        std::set<std::filesystem::path> uniqueSymlinkTargets;
        for (const std::filesystem::path& target :
             rule.allowedFinalSymlinkTargets) {
            if (!validAbsolutePath(target)) {
                error = label +
                    " allowed final symlink target must be a non-empty "
                    "absolute normalized path: " + target.string();
                return false;
            }
            if (!uniqueSymlinkTargets.insert(target).second) {
                error = label + " allowed final symlink target is duplicated: " +
                    target.string();
                return false;
            }
        }
    }
    return true;
}

} // namespace

bool validatePlatformProfile(const PlatformProfile& profile, std::string& error) {
    if (profile.id.empty() || profile.displayName.empty()) {
        error = "platform id and display name must not be empty";
        return false;
    }
    if (profile.hostCompatibility.osIds.empty()) {
        error = "platform profile must declare at least one compatible os-release ID";
        return false;
    }
    if (!validatePath(profile.ssh.configPath, "SSH configuration path", error)) {
        return false;
    }
    if (!profile.ssh.includeBasePath.empty() &&
        !validAbsolutePath(profile.ssh.includeBasePath)) {
        error = "SSH Include base path must be absolute and normalized";
        return false;
    }
    if (!validateExecutables(profile.executables, error)) {
        return false;
    }
    if (!validateExecutableCandidates(
            profile.packageManager.queryCandidates,
            "package manager query executable",
            error)) {
        return false;
    }
    if (profile.ssh.serviceUnits.empty()) {
        error = "SSH service unit list is empty";
        return false;
    }
    if (!validatePath(profile.sudo.mainConfigPath, "sudoers main path", error) ||
        !validatePath(profile.sudo.managedConfigPath, "sudoers managed path", error) ||
        !validatePath(profile.sysctl.managedConfigPath, "sysctl managed path", error) ||
        !validatePaths(profile.pam.configDirectories,
                       "PAM configuration directory", error) ||
        !validatePaths(profile.pam.moduleDirectories,
                       "PAM module directory", error) ||
        !validatePamServices(profile.pam.authenticationServices,
                             "PAM authentication service", error) ||
        !validatePamServices(profile.pam.passwordServices,
                             "PAM password service", error) ||
        !validatePamTrustedAuthenticationBypasses(profile.pam, error) ||
        !validatePath(profile.pam.faillockConfigPath,
                      "pam_faillock configuration path", error) ||
        !validatePath(profile.pam.passwordQualityConfigPath,
                      "pam_pwquality configuration path", error) ||
        !validatePath(profile.pam.passwordHistoryConfigPath,
                      "pam_pwhistory configuration path", error) ||
        !validatePath(profile.passwordAging.loginDefsPath,
                      "login.defs path", error) ||
        !validatePath(profile.passwordAging.passwdPath,
                      "local passwd path", error) ||
        !validatePath(profile.passwordAging.shadowPath,
                      "local shadow path", error) ||
        !validatePath(profile.passwordAging.tcbDirectory,
                      "local TCB directory", error) ||
        !validatePath(profile.displayManager.sddmConfigPath,
                      "SDDM configuration path", error) ||
        !validatePath(profile.displayManager.lightDmConfigPath,
                      "LightDM configuration path", error) ||
        !validatePaths(profile.displayManager.gdmConfigCandidates,
                       "GDM configuration path", error) ||
        !validatePath(profile.grub.defaultsPath,
                      "GRUB defaults path", error) ||
        !validateArguments(profile.grub.rebuildArguments,
                           "GRUB rebuild arguments", error) ||
        !validateFileAccessRules(profile.dac.protectedSystemFiles,
                                 "DAC protected system file", error) ||
        !validateFileAccessRules(profile.dac.protectedSystemCommands,
                                 "DAC protected system command", error)) {
        return false;
    }
    const PasswordAgingDefaults& aging = profile.passwordAging.defaults;
    if (aging.minDays < 0 || aging.maxDays < -1 || aging.warningDays < -1 ||
        (aging.maxDays != -1 && aging.minDays > aging.maxDays) ||
        aging.uidMin < 0 || aging.uidMax < aging.uidMin) {
        error = "invalid password-aging platform defaults";
        return false;
    }
    if (profile.sysctl.managedConfigPath.extension() != ".conf") {
        error = "sysctl managed path must use .conf extension";
        return false;
    }
    error.clear();
    return true;
}

bool readOsRelease(const std::filesystem::path& path,
                   OsReleaseValues& values,
                   std::string& error) {
    std::ifstream stream(path);
    if (!stream.is_open()) {
        error = "cannot open " + path.string();
        return false;
    }

    values.clear();
    std::string line;
    size_t lineNumber = 0;
    while (std::getline(stream, line)) {
        ++lineNumber;
        line = trim(std::move(line));
        if (line.empty() || line.front() == '#') {
            continue;
        }

        const size_t separator = line.find('=');
        if (separator == std::string::npos || separator == 0) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                    ": malformed os-release entry";
            return false;
        }

        const std::string key = trim(line.substr(0, separator));
        const std::string encodedValue = trim(line.substr(separator + 1));
        if (!std::all_of(key.begin(), key.end(), [](unsigned char ch) {
                return std::isupper(ch) != 0 || std::isdigit(ch) != 0 || ch == '_';
            })) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                    ": invalid os-release key";
            return false;
        }

        std::string decodedValue;
        if (!decodeValue(encodedValue, decodedValue)) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                    ": malformed quoted os-release value";
            return false;
        }
        values[key] = std::move(decodedValue);
    }

    if (!stream.eof()) {
        error = "failed while reading " + path.string();
        return false;
    }
    error.clear();
    return true;
}

bool isHostCompatible(const PlatformProfile& profile,
                      const OsReleaseValues& values,
                      std::string& error) {
    const auto id = values.find("ID");
    if (id == values.end() || !contains(profile.hostCompatibility.osIds, id->second)) {
        error = "compiled profile '" + profile.id + "' expects os-release ID in [" +
                join(profile.hostCompatibility.osIds) + "], detected '" +
                (id == values.end() ? std::string("<missing>") : id->second) + "'";
        return false;
    }

    if (!profile.hostCompatibility.versionIds.empty()) {
        const auto version = values.find("VERSION_ID");
        if (version == values.end() ||
            !contains(profile.hostCompatibility.versionIds, version->second)) {
            error = "compiled profile '" + profile.id +
                    "' expects VERSION_ID in [" +
                    join(profile.hostCompatibility.versionIds) + "], detected '" +
                    (version == values.end() ? std::string("<missing>") : version->second) +
                    "'";
            return false;
        }
    }

    if (!profile.hostCompatibility.altBranchIds.empty()) {
        const auto branch = values.find("ALT_BRANCH_ID");
        if (branch == values.end() ||
            !contains(profile.hostCompatibility.altBranchIds, branch->second)) {
            error = "compiled profile '" + profile.id +
                    "' expects ALT_BRANCH_ID in [" +
                    join(profile.hostCompatibility.altBranchIds) + "], detected '" +
                    (branch == values.end() ? std::string("<missing>") : branch->second) +
                    "'";
            return false;
        }
    }

    error.clear();
    return true;
}

bool validateHostCompatibility(const PlatformProfile& profile,
                               const std::filesystem::path& osReleasePath,
                               std::string& error) {
    OsReleaseValues values;
    return readOsRelease(osReleasePath, values, error) &&
           isHostCompatible(profile, values, error);
}

} // namespace fic::platform
