#include "incident/PamIncidentAccessGateVerifier.h"

#include "modules/identity_access/pam/PamConfiguration.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace fic::incident {
namespace {
using ::fic::identity::pam::PamStackEntry;

bool trustedRegularFile(const std::filesystem::path& path,
                        uid_t expectedOwner,
                        std::string& diagnostic) {
    struct stat parentInfo {};
    if (::lstat(path.parent_path().c_str(), &parentInfo) != 0 ||
        !S_ISDIR(parentInfo.st_mode) || parentInfo.st_uid != expectedOwner ||
        (parentInfo.st_mode & 0022) != 0) {
        diagnostic = "untrusted PAM file directory: " +
            path.parent_path().string();
        return false;
    }
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != expectedOwner || (info.st_mode & 0022) != 0) {
        diagnostic = "untrusted PAM file: " + path.string();
        return false;
    }
    return true;
}

void flatten(const std::vector<PamStackEntry>& entries,
             std::vector<const PamStackEntry*>& output) {
    for (const auto& entry : entries) {
        if (entry.isSubstack()) {
            flatten(entry.substack, output);
        } else {
            output.push_back(&entry);
        }
    }
}

bool mayFinishBeforeGate(const std::string& control) {
    if (control == "sufficient") return true;
    if (control == "required" || control == "requisite" ||
        control == "optional") return false;
    if (control.size() < 2 || control.front() != '[' ||
        control.back() != ']') return true;
    // Before the hook, accept only actions that continue or deny. A numeric
    // jump or a successful termination needs full symbolic analysis, so this
    // verifier refuses such topology instead of claiming non-bypassability.
    const std::string actions = control.substr(1, control.size() - 2);
    std::size_t cursor = 0;
    while (cursor < actions.size()) {
        const auto start = actions.find_first_not_of(" \t", cursor);
        if (start == std::string::npos) break;
        const auto end = actions.find_first_of(" \t", start);
        const auto clause = actions.substr(start, end - start);
        const auto equals = clause.find('=');
        if (equals == std::string::npos) return true;
        const auto action = clause.substr(equals + 1);
        if (action != "ok" && action != "ignore" && action != "bad" &&
            action != "die") return true;
        cursor = end == std::string::npos ? actions.size() : end + 1;
    }
    return false;
}

bool mayEraseGateFailure(const std::string& control) {
    return control == "reset" || control.find("=reset") != std::string::npos;
}

bool proveStack(const ::fic::identity::pam::PamEffectiveStack& stack,
                uid_t expectedOwner,
                std::string& diagnostic) {
    std::vector<const PamStackEntry*> rules;
    flatten(stack.entries, rules);
    std::size_t gateIndex = rules.size();
    for (std::size_t i = 0; i < rules.size(); ++i) {
        const auto& rule = rules[i]->rule;
        if (rule.module != "pam_fic_access.so") continue;
        if (gateIndex != rules.size() || rule.control != "required" ||
            !rule.arguments.empty()) {
            diagnostic = "ambiguous or non-required incident gate in " + stack.service;
            return false;
        }
        gateIndex = i;
    }
    if (gateIndex == rules.size()) {
        diagnostic = "incident account gate is absent in " + stack.service;
        return false;
    }
    for (std::size_t i = 0; i < gateIndex; ++i) {
        if (mayFinishBeforeGate(rules[i]->rule.control)) {
            diagnostic = "account control may bypass incident gate in " +
                stack.service;
            return false;
        }
    }
    for (std::size_t i = gateIndex + 1; i < rules.size(); ++i) {
        if (mayEraseGateFailure(rules[i]->rule.control)) {
            diagnostic = "account control may erase incident denial in " +
                stack.service;
            return false;
        }
    }
    for (const auto& source : stack.sourceFiles) {
        if (!trustedRegularFile(source, expectedOwner, diagnostic)) return false;
    }
    return true;
}

bool readProofFile(const std::filesystem::path& path, uid_t expectedOwner,
                   std::string& content, std::string& diagnostic) {
    if (!trustedRegularFile(path, expectedOwner, diagnostic)) return false;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        diagnostic = "cannot open PAM proof file " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    struct stat before {};
    if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != expectedOwner || (before.st_mode & 0022) != 0 ||
        before.st_size > 1024 * 1024) {
        diagnostic = "PAM proof file metadata is unprovable: " + path.string();
        ::close(fd);
        return false;
    }
    content.clear();
    char buffer[8192];
    bool readFailed = false;
    for (;;) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            content.append(buffer, static_cast<std::size_t>(count));
            if (content.size() > 1024U * 1024U) break;
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            readFailed = true;
            break;
        } else {
            continue;
        }
    }
    struct stat after {};
    const bool stable = !readFailed && content.size() <= 1024U * 1024U &&
        ::fstat(fd, &after) == 0 &&
        after.st_dev == before.st_dev && after.st_ino == before.st_ino &&
        after.st_size == before.st_size &&
        after.st_mtim.tv_sec == before.st_mtim.tv_sec &&
        after.st_mtim.tv_nsec == before.st_mtim.tv_nsec &&
        after.st_ctim.tv_sec == before.st_ctim.tv_sec &&
        after.st_ctim.tv_nsec == before.st_ctim.tv_nsec &&
        static_cast<off_t>(content.size()) == before.st_size;
    ::close(fd);
    if (!stable) {
        diagnostic = "PAM proof file changed or could not be read: " +
            path.string();
        return false;
    }
    return true;
}

enum class IncidentModuleReference { Other, Referenced, Unprovable };

IncidentModuleReference incidentModuleReference(
    const std::string& module,
    const ::fic::platform::PamPlatformConfig& platform) {
    if (module.empty()) return IncidentModuleReference::Other; // include rule
    const std::filesystem::path path(module);
    if (path.filename() == "pam_fic_access.so") {
        return IncidentModuleReference::Referenced;
    }
    if (module.find('\0') != std::string::npos || path.filename().empty()) {
        return IncidentModuleReference::Unprovable;
    }
    for (const auto& component : path) {
        if (component == "." || component == "..") {
            return IncidentModuleReference::Unprovable;
        }
    }
    if (!path.is_absolute() && path.has_parent_path()) {
        return IncidentModuleReference::Unprovable;
    }
    if (platform.moduleDirectories.empty()) {
        return IncidentModuleReference::Unprovable;
    }
    std::vector<std::filesystem::path> candidates;
    if (path.is_absolute()) {
        candidates.push_back(path);
    } else {
        for (const auto& directory : platform.moduleDirectories) {
            candidates.push_back(directory / path);
        }
    }
    for (const auto& candidate : candidates) {
        std::error_code error;
        const auto status = std::filesystem::symlink_status(candidate, error);
        if (error == std::errc::no_such_file_or_directory) continue;
        if (error || std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status)) {
            return IncidentModuleReference::Unprovable;
        }
        struct stat candidateInfo {};
        if (::stat(candidate.c_str(), &candidateInfo) != 0) {
            return IncidentModuleReference::Unprovable;
        }
        std::vector<std::filesystem::path> gatePaths;
        gatePaths.push_back(candidate.parent_path() / "pam_fic_access.so");
        for (const auto& directory : platform.moduleDirectories) {
            gatePaths.push_back(directory / "pam_fic_access.so");
        }
        for (const auto& gatePath : gatePaths) {
            struct stat gateInfo {};
            if (::stat(gatePath.c_str(), &gateInfo) != 0) {
                if (errno != ENOENT) return IncidentModuleReference::Unprovable;
                continue;
            }
            if (candidateInfo.st_dev == gateInfo.st_dev &&
                candidateInfo.st_ino == gateInfo.st_ino) {
                return IncidentModuleReference::Referenced;
            }
        }
    }
    return IncidentModuleReference::Other;
}

IncidentGateDetachProof proveDetachedImpl(
    const ::fic::platform::PamPlatformConfig& platform,
    const std::filesystem::path& selectionPath, uid_t expectedOwner,
    std::string& diagnostic) {
    std::string selection;
    if (!readProofFile(selectionPath, expectedOwner, selection, diagnostic)) {
        return IncidentGateDetachProof::Unprovable;
    }
    std::istringstream state(selection);
    std::string line;
    while (std::getline(state, line)) {
        if (line == "Module: fic-incident-access") {
            diagnostic = "incident gate remains selected";
            return IncidentGateDetachProof::Referenced;
        }
        if (line.find("fic-incident-access") != std::string::npos) {
            diagnostic = "incident gate selection state is ambiguous";
            return IncidentGateDetachProof::Unprovable;
        }
    }
    if (platform.configDirectories.empty()) {
        diagnostic = "PAM configuration directories are not declared";
        return IncidentGateDetachProof::Unprovable;
    }
    bool requiredDirectorySeen = false;
    for (std::size_t index = 0; index < platform.configDirectories.size(); ++index) {
        const auto& directory = platform.configDirectories[index];
        std::error_code error;
        const auto status = std::filesystem::symlink_status(directory, error);
        if (error == std::errc::no_such_file_or_directory) {
            if (index == 0) {
                diagnostic = "primary PAM configuration directory is missing";
                return IncidentGateDetachProof::Unprovable;
            }
            continue;
        }
        if (error || !std::filesystem::is_directory(status)) {
            diagnostic = "PAM configuration directory is unprovable: " +
                directory.string();
            return IncidentGateDetachProof::Unprovable;
        }
        if (index == 0) requiredDirectorySeen = true;
        struct stat directoryInfo {};
        if (::lstat(directory.c_str(), &directoryInfo) != 0 ||
            directoryInfo.st_uid != expectedOwner ||
            (directoryInfo.st_mode & 0022) != 0) {
            diagnostic = "PAM configuration directory is untrusted: " +
                directory.string();
            return IncidentGateDetachProof::Unprovable;
        }
        std::filesystem::directory_iterator entries(directory, error);
        if (error) {
            diagnostic = "cannot enumerate PAM directory: " + directory.string();
            return IncidentGateDetachProof::Unprovable;
        }
        const std::filesystem::directory_iterator end;
        for (; entries != end; entries.increment(error)) {
            if (error) break;
            const auto& entry = *entries;
            const auto fileStatus = entry.symlink_status(error);
            if (error || !std::filesystem::is_regular_file(fileStatus)) {
                diagnostic = "PAM service entry is unprovable: " +
                    entry.path().string();
                return IncidentGateDetachProof::Unprovable;
            }
            std::string content;
            if (!readProofFile(entry.path(), expectedOwner, content, diagnostic)) {
                return IncidentGateDetachProof::Unprovable;
            }
            std::vector<::fic::identity::pam::PamRule> rules;
            if (!::fic::identity::pam::PamConfiguration::parseRulesContent(
                    entry.path(), content, rules, diagnostic)) {
                return IncidentGateDetachProof::Unprovable;
            }
            for (const auto& rule : rules) {
                const auto reference = incidentModuleReference(rule.module, platform);
                if (reference == IncidentModuleReference::Referenced) {
                    diagnostic = "incident PAM module remains referenced: " +
                        entry.path().string();
                    return IncidentGateDetachProof::Referenced;
                }
                if (reference == IncidentModuleReference::Unprovable) {
                    diagnostic = "PAM module path is unprovable: " +
                        entry.path().string();
                    return IncidentGateDetachProof::Unprovable;
                }
            }
        }
        if (error) {
            diagnostic = "PAM directory changed during enumeration: " +
                directory.string();
            return IncidentGateDetachProof::Unprovable;
        }
    }
    if (!requiredDirectorySeen) {
        diagnostic = "primary PAM configuration directory is unprovable";
        return IncidentGateDetachProof::Unprovable;
    }
    diagnostic = "incident gate is detached";
    return IncidentGateDetachProof::ProvenDetached;
}
} // namespace

bool proveImpl(
    const ::fic::platform::PamPlatformConfig& platform,
    uid_t expectedOwner,
    bool checkLoadable,
    std::string& diagnostic) {
    bool moduleProven = false;
    dev_t moduleDevice = 0;
    ino_t moduleInode = 0;
    std::filesystem::path modulePath;
    for (const auto& directory : platform.moduleDirectories) {
        const auto path = directory / "pam_fic_access.so";
        if (!std::filesystem::exists(path)) continue;
        if (!trustedRegularFile(path, expectedOwner, diagnostic)) return false;
        struct stat info {};
        if (::stat(path.c_str(), &info) != 0) {
            diagnostic = "cannot identify incident PAM module";
            return false;
        }
        if (moduleProven && (moduleDevice != info.st_dev ||
                             moduleInode != info.st_ino)) {
            diagnostic = "different incident PAM modules exist in loader directories";
            return false;
        }
        moduleDevice = info.st_dev;
        moduleInode = info.st_ino;
        modulePath = path;
        moduleProven = true;
    }
    if (!moduleProven) {
        diagnostic = "pam_fic_access.so is absent from trusted module directories";
        return false;
    }
    if (checkLoadable) {
        void* handle = ::dlopen(modulePath.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (handle == nullptr) {
            diagnostic = "incident PAM module cannot be loaded";
            return false;
        }
        const bool hasAccountEntry = ::dlsym(handle, "pam_sm_acct_mgmt") != nullptr;
        ::dlclose(handle);
        if (!hasAccountEntry) {
            diagnostic = "incident PAM module has no account entry point";
            return false;
        }
    }
    ::fic::identity::pam::PamConfiguration configuration(platform);
    std::vector<std::string> installedServices;
    if (!configuration.existingServices(
            platform.incidentAccessGate.controlledServices,
            installedServices, diagnostic)) return false;
    for (const auto& service : installedServices) {
        ::fic::identity::pam::PamEffectiveStack stack;
        if (!configuration.buildEffectiveStack(
                service, ::fic::identity::pam::PamManagementGroup::Account,
                stack, diagnostic)) return false;
        if (!proveStack(stack, expectedOwner, diagnostic)) return false;
    }
    diagnostic = "installed controlled PAM services reach the incident gate";
    return true;
}

bool PamIncidentAccessGateVerifier::prove(
    const ::fic::platform::PamPlatformConfig& platform,
    std::string& diagnostic) {
    return proveImpl(platform, 0, true, diagnostic);
}

bool PamIncidentAccessGateVerifier::proveForTests(
    const ::fic::platform::PamPlatformConfig& platform,
    uid_t expectedOwner, std::string& diagnostic) {
    return proveImpl(platform, expectedOwner, false, diagnostic);
}

IncidentGateDetachProof PamIncidentAccessGateVerifier::proveDetached(
    const ::fic::platform::PamPlatformConfig& platform,
    std::string& diagnostic) {
    return proveDetachedImpl(
        platform, "/var/lib/pam/account", 0, diagnostic);
}

IncidentGateDetachProof PamIncidentAccessGateVerifier::proveDetachedForTests(
    const ::fic::platform::PamPlatformConfig& platform,
    const std::filesystem::path& selectionPath,
    uid_t expectedOwner, std::string& diagnostic) {
    return proveDetachedImpl(
        platform, selectionPath, expectedOwner, diagnostic);
}

} // namespace fic::incident
