#include "incident/PamIncidentAccessGateVerifier.h"

#include "modules/identity_access/pam/PamConfiguration.h"

#include <sys/stat.h>
#include <dlfcn.h>

#include <algorithm>
#include <filesystem>
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

} // namespace fic::incident
