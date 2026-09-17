#ifndef FIC_OSS_GRUB_CONFIGURATION_H
#define FIC_OSS_GRUB_CONFIGURATION_H

#include <fic/core/process/ProcessExecutor.h>

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

struct GrubValueObservation {
    bool found = false;
    bool valid = true;
    std::string value;
    std::filesystem::path source;
    size_t line = 0;
    std::string error;
};

struct GrubOperationResult {
    bool ok = false;
    bool changed = false;
    std::string message;
    std::vector<std::string> diagnostics;
};

struct GrubConfigurationOptions {
    std::filesystem::path defaultsPath = "/etc/default/grub";
    std::filesystem::path rebuildExecutable;
    std::vector<std::string> rebuildArguments;
    bool enforceOwnership = true;
};

struct GrubManagedConfigurationOptions {
    std::filesystem::path managedPath;
    std::filesystem::path rebuildExecutable;
    std::vector<std::string> rebuildArguments;
    bool enforceOwnership = true;
    // Validate-only base defaults (Debian/Ubuntu: /etc/default/grub).
    // FIC never edits this file, but update-grub still sources it as root
    // shell code, so it must be proven safe before the managed drop-in is
    // mutated or the rebuild runs. Empty when the platform has no base
    // defaults (ALT shared-file topology).
    std::filesystem::path baseDefaultsPath;
};

using GrubCommandRunner = std::function<ProcessResult(
    const std::string&,
    const std::vector<std::string>&,
    const ProcessOptions&
)>;

// Safe editor for the simple top-level assignments used by /etc/default/grub.
// Values are decoded as shell literals and always written as escaped double-
// quoted literals. Dynamic shell expressions and duplicate target assignments
// are rejected instead of being evaluated or ambiguously rewritten.
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
    std::string originalContent_;

    bool checkFileSafety(std::string& error) const;
    bool readDocument(std::string& error);
    bool snapshotUnchanged(std::string& error) const;
    bool writeDocument(const std::string& content, std::string& error) const;
    bool restoreDocument(std::string& error) const;
    bool verifyOriginalRestored(std::string& error) const;
    bool rebuild(std::string& error) const;
    bool rollbackAfterRebuildFailure(std::string& error) const;
    void clear();
};

// Validate-only safety proof for the platform base defaults file (Debian/
// Ubuntu: /etc/default/grub). Never mutates anything. A missing file is
// acceptable; an existing file must be a regular non-symlink file of a
// bounded size without group/world write bits, owned by root when
// enforceOwnership is set, inside a safe directory chain. Runs before any
// managed drop-in mutation or GRUB rebuild because update-grub still sources
// this file as root shell code.
bool validateBaseGrubDefaults(const std::filesystem::path& path,
                              bool enforceOwnership,
                              std::string& error);

GrubOperationResult ensureManagedGrubDropInValue(
    const GrubManagedConfigurationOptions& options,
    const std::string& key,
    const std::string& value,
    GrubCommandRunner runner = {});

#endif // FIC_OSS_GRUB_CONFIGURATION_H
