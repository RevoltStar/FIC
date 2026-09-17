#ifndef SSHCONFIGFILE_H
#define SSHCONFIGFILE_H

#include "modules/net/ssh/SshManagedBlock.h"

#include <fic/core/fs/FileHandler.h>

#include <string>
#include <vector>

// Minimal sshd_config file handler over the shared FileHandler transactional
// snapshot: loads the file capturing the exact optimistic target state,
// validates the FIC marker structure (fail closed) and provides first-wins
// global-section reads. All structured edits are performed on the loaded
// line vector through the managed-block operations; persistence uses
// saveFileIfUnchanged() (conditional atomic write + durability metadata).
class SshConfigFileHandler : public FileHandler {
public:
    explicit SshConfigFileHandler(const std::string& filepath);

    // Captures the optimistic snapshot, splits the content into exact lines
    // and validates the FIC marker model. Returns false on unreadable,
    // unparsable or marker-malformed files.
    bool loadConfig() override;

    std::string getValue(const std::string& parameter) const override;
    void printConfig() const override;
    bool isParameterExists(const std::string& parameter) const;

    // Not used by the managed-block model: structured edits go through the
    // SshManagedBlock operations on lines(). Kept to satisfy the FileHandler
    // interface; always fails closed without touching anything.
    bool setValue(const std::string& parameter, const std::string& value) override;

    // The exact line vector of the loaded snapshot. Editable in memory;
    // persistence goes through saveFileIfUnchanged().
    std::vector<std::string>& lines() { return original_lines_; }
    const std::vector<std::string>& lines() const { return original_lines_; }

    // The configured file path.
    const std::string& filePath() const { return filepath_; }

private:
    bool findFirstMatchLine(std::size_t& line) const;

    std::unordered_map<std::string, std::string> config_;
    std::unordered_map<std::string, std::string> canonicalNames_;
};

#endif // SSHCONFIGFILE_H
