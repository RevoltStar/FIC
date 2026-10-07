#pragma once

#include <fic/core/fs/FileStats.h>

#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::ssh {

inline bool trustedSshInput(const std::filesystem::path& path, bool directory,
                            bool optional, std::string& error) {
    if (!path.is_absolute()) {
        error = "SSH input path is not absolute: " + path.string();
        return false;
    }
    for (const auto& component : path)
        if (component == "..") {
            error = "SSH input path contains parent traversal: " + path.string();
            return false;
        }
    // FileStats pins each path component and rejects unsafe intermediate
    // directories and symlinks. A root-owned sticky parent (e.g. /tmp) may
    // contain a trusted directory, but never an optional missing file.
    const auto parent = FileStats::openPolicyPath(
        path.parent_path(), {}, PolicyPathResolution::TrustedIntermediateComponents);
    if (!parent.exists || !S_ISDIR(parent.file_type()) ||
        (parent.owner_id() != 0 && parent.owner_id() != ::geteuid()) ||
        ((parent._permissions & (S_IWGRP | S_IWOTH)) != 0 &&
         !(directory && parent.owner_id() == 0 &&
           (parent._permissions & S_ISVTX) != 0))) {
        error = "SSH input parent directory is not trusted: " +
                path.parent_path().string();
        return false;
    }
    const auto input = FileStats::openPolicyPath(
        path, {}, PolicyPathResolution::TrustedIntermediateComponents);
    if (input.is_missing() && optional) return true;
    if (!input.exists ||
        (directory ? !S_ISDIR(input.file_type()) : !input.is_regular_file()) ||
        (input.owner_id() != 0 && input.owner_id() != ::geteuid()) ||
        (input._permissions & (S_IWGRP | S_IWOTH)) != 0) {
        error = "SSH input is not trusted: " + path.string();
        return false;
    }
    return true;
}

} // namespace fic::ssh
