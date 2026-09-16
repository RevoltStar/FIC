#ifndef SSHCONFIGFILE_H
#define SSHCONFIGFILE_H

#include "rollback/MutationRecord.h"

#include <fic/core/fs/FileHandler.h>

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

// In-memory plan of the exact textual mutation setValue() performs. Built
// BEFORE the file is written so the rollback journal can record the reverse
// delta and the post-mutation global section fingerprint first.
struct SshDirectiveMutationPlan {
    std::string parameter;          // normalized parameter
    std::string canonicalParameter; // keyword used for the written line
    std::string appliedValue;       // value FIC applies
    std::vector<fic::rollback::SshLineReverseEdit> reverseEdits;
    std::string appliedGlobalSectionFingerprint; // fingerprint after mutation
};

class SshConfigFileHandler : public FileHandler {
public:
    explicit SshConfigFileHandler(const std::string& filepath);

    bool loadConfig() override;
    std::string getValue(const std::string& parameter) const override;
    bool setValue(const std::string& parameter, const std::string& value) override;
    void printConfig() const override;
    bool isParameterExists(const std::string& parameter) const;

    // Builds the exact mutation setValue() would perform without mutating
    // anything: reverse edits for every changed global-section line and the
    // fingerprint of the post-mutation global section.
    bool planSetValue(const std::string& parameter,
                      const std::string& value,
                      SshDirectiveMutationPlan& plan) const;

    // Applies recorded reverse edits (rollback). Fails closed when the
    // current global section does not exactly match the recorded after-state.
    // Edits are applied from the bottom so indices stay valid.
    bool applyReverseEdits(
        const std::vector<fic::rollback::SshLineReverseEdit>& edits,
        std::string& error);

    // Fingerprint of the current global section (start of file up to the
    // first Match directive).
    std::string globalSectionFingerprint() const;

private:
    bool findFirstMatchLine(std::size_t& line) const;

    std::unordered_map<std::string, std::string> config_;
    std::unordered_map<std::string, std::string> canonicalNames_;
};

#endif // SSHCONFIGFILE_H
