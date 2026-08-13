#include "platform/PlatformExecutableResolver.h"

#include <cerrno>
#include <cstring>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace fic::platform {

const char* executableIdName(ExecutableId id) {
    switch (id) {
    case ExecutableId::Sshd:
        return "sshd";
    case ExecutableId::Systemctl:
        return "systemctl";
    case ExecutableId::Loginctl:
        return "loginctl";
    case ExecutableId::Visudo:
        return "visudo";
    case ExecutableId::Lscpu:
        return "lscpu";
    case ExecutableId::Dmidecode:
        return "dmidecode";
    case ExecutableId::Udevadm:
        return "udevadm";
    case ExecutableId::UpdateGrub:
        return "update-grub";
    case ExecutableId::Nft:
        return "nft";
    }
    return "unknown";
}

std::vector<ExecutableId> allExecutableIds() {
    return {
        ExecutableId::Sshd,
        ExecutableId::Systemctl,
        ExecutableId::Loginctl,
        ExecutableId::Visudo,
        ExecutableId::Lscpu,
        ExecutableId::Dmidecode,
        ExecutableId::Udevadm,
        ExecutableId::UpdateGrub,
        ExecutableId::Nft
    };
}

const PlatformExecutableSpec* findExecutableSpec(
    const PlatformExecutables& executables,
    ExecutableId id) {
    for (const PlatformExecutableSpec& spec : executables.entries) {
        if (spec.id == id) {
            return &spec;
        }
    }
    return nullptr;
}

PlatformExecutableResolver::PlatformExecutableResolver(
    PlatformExecutables executables,
    PlatformExecutableResolverOptions options)
    : executables_(std::move(executables)),
      options_(options) {
}

bool PlatformExecutableResolver::validateCandidate(
    const std::filesystem::path& candidate,
    std::string& error) const {
    if (!candidate.is_absolute() || candidate != candidate.lexically_normal()) {
        error = "path is not absolute and normalized";
        return false;
    }

    struct stat info {};
    if (::lstat(candidate.c_str(), &info) != 0) {
        error = std::string("cannot inspect path: ") + std::strerror(errno);
        return false;
    }
    if (S_ISLNK(info.st_mode)) {
        error = "path is a symbolic link";
        return false;
    }
    if (!S_ISREG(info.st_mode)) {
        error = "path is not a regular file";
        return false;
    }
    if (::access(candidate.c_str(), X_OK) != 0) {
        error = "path is not executable";
        return false;
    }
    if (options_.enforceTrustedOwnership) {
        if (info.st_uid != 0) {
            error = "file is not owned by root";
            return false;
        }
        if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            error = "file is writable by group or others";
            return false;
        }
    }
    error.clear();
    return true;
}

bool PlatformExecutableResolver::resolve(
    ExecutableId id,
    std::filesystem::path& executable,
    std::string& error) const {
    {
        std::filesystem::path cachedPath;
        {
            const std::lock_guard<std::mutex> lock(cacheMutex_);
            const auto cached = resolved_.find(id);
            if (cached != resolved_.end()) {
                cachedPath = cached->second;
            }
        }
        if (!cachedPath.empty()) {
            std::string validationError;
            if (validateCandidate(cachedPath, validationError)) {
                executable = std::move(cachedPath);
                error.clear();
                return true;
            }
            const std::lock_guard<std::mutex> lock(cacheMutex_);
            const auto cached = resolved_.find(id);
            if (cached != resolved_.end() && cached->second == cachedPath) {
                resolved_.erase(cached);
            }
        }
    }

    const PlatformExecutableSpec* spec = findExecutableSpec(executables_, id);
    if (spec == nullptr) {
        error = std::string("platform profile does not define executable ") +
                executableIdName(id);
        return false;
    }

    std::ostringstream failures;
    bool hasFailure = false;
    for (const std::filesystem::path& candidate : spec->candidates) {
        std::string candidateError;
        if (validateCandidate(candidate, candidateError)) {
            const std::lock_guard<std::mutex> lock(cacheMutex_);
            const auto inserted = resolved_.emplace(id, candidate);
            executable = inserted.first->second;
            error.clear();
            return true;
        }
        if (hasFailure) {
            failures << "; ";
        }
        hasFailure = true;
        failures << candidate.string() << ": " << candidateError;
    }

    error = std::string("no usable ") + executableIdName(id) +
            " executable was found";
    const std::string details = failures.str();
    if (!details.empty()) {
        error += " (" + details + ")";
    }
    return false;
}

} // namespace fic::platform
