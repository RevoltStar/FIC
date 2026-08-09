#ifndef SYSCTLCONFIGURATION_H
#define SYSCTLCONFIGURATION_H

#include <filesystem>
#include <string>
#include <vector>

#include "platform/PlatformProfile.h"

struct SysctlSourceLocation {
    std::filesystem::path path;
    size_t line = 0;
};

struct SysctlValueObservation {
    bool found = false;
    std::string value;
    SysctlSourceLocation source;
};

struct SysctlOperationResult {
    bool ok = false;
    bool changed = false;
    std::string message;
    std::vector<std::string> diagnostics;
};

struct SysctlConfigurationOptions {
    fic::platform::SysctlPlatformConfig platform;
    std::vector<std::filesystem::path> directories = {
        "/etc/sysctl.d",
        "/run/sysctl.d",
        "/usr/local/lib/sysctl.d",
        "/usr/lib/sysctl.d",
        "/lib/sysctl.d"
    };
    std::filesystem::path procpsMainPath = "/etc/sysctl.conf";
    bool enforceOwnership = true;
};

// Models the boot-effective sysctl loader selected by the platform profile.
class SysctlConfiguration {
public:
    explicit SysctlConfiguration(SysctlConfigurationOptions options = {});

    bool load(std::string& error);
    SysctlValueObservation inspect(const std::string& key) const;
    SysctlOperationResult ensureManagedValue(const std::string& key,
                                             const std::string& value);

private:
    struct Document {
        std::filesystem::path path;
        std::string content;
        bool allowDevNullMask = true;
    };

    struct Assignment {
        std::string key;
        std::string value;
        SysctlSourceLocation source;
        bool pattern = false;
        bool exclusion = false;
    };

    SysctlConfigurationOptions options_;
    std::vector<Document> documents_;
    std::vector<Assignment> assignments_;
    bool managedExisted_ = false;
    std::string managedContent_;

    bool loadDirectoryDocuments(std::string& error);
    bool loadProcpsMainDocument(std::string& error);
    bool loadManagedDocument(std::string& error);
    bool addDocument(const std::filesystem::path& path,
                     bool allowDevNullMask,
                     std::string& error);
    bool parseDocument(const Document& document, std::string& error);
    bool checkDirectorySafety(const std::filesystem::path& path,
                              std::string& error) const;
    bool checkFileSafety(const std::filesystem::path& path,
                         bool allowDevNull,
                         std::string& error) const;
    bool snapshotUnchanged(std::string& error) const;
    bool writeManaged(const std::string& content, std::string& error) const;
    bool restoreManaged(std::string& error) const;
    void clear();
};

#endif // SYSCTLCONFIGURATION_H
