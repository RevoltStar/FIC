#ifndef FIC_OSS_GRUB_CONFIGURATION_H
#define FIC_OSS_GRUB_CONFIGURATION_H

#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include <fic/core/ProcessExecutor.h>

struct GrubValueObservation {
    bool found = false;
    std::string value;
    std::filesystem::path source;
    size_t line = 0;
};

struct GrubOperationResult {
    bool ok = false;
    bool changed = false;
    std::string message;
    std::vector<std::string> diagnostics;
};

struct GrubConfigurationOptions {
    std::filesystem::path defaultsPath = "/etc/default/grub";
    std::vector<std::filesystem::path> rebuildCandidates;
    bool enforceOwnership = true;
};

using GrubCommandRunner = std::function<ProcessResult(
    const std::string&,
    const std::vector<std::string>&,
    const ProcessOptions&
)>;

// Safe editor for /etc/default/grub. Reads and validates the GRUB defaults
// file, atomically writes managed changes, and rebuilds the bootloader
// configuration through the verified platform command.
class GrubConfiguration {
public:
    explicit GrubConfiguration(GrubConfigurationOptions options = {},
                               GrubCommandRunner runner = {});

    bool load(std::string& error);
    GrubValueObservation inspect(const std::string& key) const;
    GrubOperationResult ensureManagedValue(const std::string& key,
                                           const std::string& value);

private:
    struct Document {
        std::filesystem::path path;
        std::string content;
    };

    GrubConfigurationOptions options_;
    GrubCommandRunner runner_;
    Document document_;
    bool existed_ = false;
    std::string originalContent_;

    bool checkFileSafety(std::string& error) const;
    bool readDocument(std::string& error);
    bool snapshotUnchanged(std::string& error) const;
    bool writeDocument(const std::string& content, std::string& error) const;
    bool restoreDocument(std::string& error) const;
    bool rebuild(std::string& error) const;
    void clear();
};

#endif // FIC_OSS_GRUB_CONFIGURATION_H