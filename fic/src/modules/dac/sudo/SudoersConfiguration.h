#ifndef SUDOERSCONFIGURATION_H
#define SUDOERSCONFIGURATION_H

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct SudoersSourceLocation {
    std::filesystem::path path;
    size_t line = 0;
};

struct SudoersValueObservation {
    bool found = false;
    std::string value;
    SudoersSourceLocation source;
};

struct SudoersOperationResult {
    bool ok = false;
    bool changed = false;
    // Rollback diagnostics: the FIC-owned value drifted from the recorded one.
    bool conflict = false;
    // Rollback diagnostics: the managed file does not own the requested key.
    bool targetMissing = false;
    std::string message;
    std::vector<std::string> diagnostics;
};

struct SudoersConfigurationOptions {
    std::filesystem::path mainPath;
    std::filesystem::path managedPath;
    std::string validatorPath;
    bool verifyValidatorHash = true;
    bool enforceOwnership = true;
    size_t maximumIncludeDepth = 128;
};

class SudoersConfiguration {
public:
    explicit SudoersConfiguration(SudoersConfigurationOptions options);

    bool load(std::string& error);
    SudoersValueObservation inspectGlobalDefault(const std::string& key) const;

    // Rollback support: inspect the FIC managed sudoers artifact only. The
    // result reflects what FIC physically owns in options_.managedPath and
    // is independent of which sudoers source currently wins precedence.
    SudoersValueObservation inspectManagedGlobalDefault(
        const std::string& key) const;

    SudoersOperationResult ensureManagedGlobalDefault(
        const std::string& key,
        const std::string& renderedLine,
        const std::string& expectedValue);

    // Rollback support: remove the FIC-managed global Defaults entry for the
    // given key. Ownership is the managed artifact content: an external
    // sudoers source may shadow the FIC entry while the entry still exists
    // and is FIC-owned. Fails closed on drift (conflict) and reports
    // targetMissing when the managed file has no entry for the key.
    SudoersOperationResult removeManagedGlobalDefault(
        const std::string& key,
        const std::string& expectedValue);

    SudoersOperationResult enforceAuthentication();
    std::vector<std::string> authenticationViolations() const;

    // --- Contextual/scoped Defaults policy (sudo_disable_scoped_defaults) ---
    //
    // Detects every ACTIVE sudoers entry of the forms `Defaults:user`,
    // `Defaults@host`, `Defaults>runas` and `Defaults!command` across the
    // whole include graph. Detection is purely syntactic: FIC never evaluates
    // User_Alias/Host_Alias/Runas_Alias/Cmnd_Alias, %group, netgroups,
    // negation or ALL,!foo — the presence of a scoped Defaults IS the
    // violation, which is what makes the hard P2 cases decidable.
    std::vector<std::string> scopedDefaultsViolations() const;

    // Number of FIC_SUDO_DISABLED wrappers of the policy present in the
    // current graph. Rollback uses it as the unrecorded-ownership proof: an
    // orphan wrapper without an active journal record cannot be attributed and
    // must fail closed instead of being silently ignored. A malformed marker
    // structure yields -1 (fail closed).
    long scopedDefaultsWrapperCount(const std::string& policyName) const;

    // Generates the provenance ids the caller must journal BEFORE the
    // filesystem mutation, one per scoped Defaults entry that is about to be
    // wrapped. The ids are then passed to disableScopedDefaults(), so the
    // prepared journal record is complete and never has to be rewritten.
    static std::vector<std::string> planScopedDefaultsWrapperIds(
        size_t violationCount);

    // Temporarily deactivates every active scoped Defaults entry by wrapping
    // the offending PHYSICAL lines into explicit FIC markers inside the very
    // file that contains them (see SudoersDisabledWrapper.h).
    //
    // `wrapperIds` are the ids produced by planScopedDefaultsWrapperIds() for
    // the CURRENTLY loaded graph; a mismatch with the actual violation count
    // fails closed before any write.
    //
    // Failure semantics:
    //   * the input graph is CAS-checked before any write;
    //   * on any post-write failure the exact previous content of every
    //     already written file is restored and re-validated by visudo;
    //   * on a failed semantic postcondition the same compensation runs and
    //     the policy is NOT reported as applied;
    //   * crash-consistency of the whole transaction is NOT claimed: recovery
    //     is the journal's Prepared record, which the caller writes before
    //     calling this method.
    SudoersOperationResult disableScopedDefaults(
        const std::string& policyName,
        const std::vector<std::string>& wrapperIds);

    // Rollback support: unwraps exactly the FIC-owned wrappers of the policy
    // that still exist and whose ids the journal payload proves. Wrappers
    // that already disappeared externally are treated as released and are
    // never reconstructed. An unknown wrapper id or drifted markers fail
    // closed with conflict=true.
    SudoersOperationResult restoreScopedDefaults(
        const std::string& policyName,
        const std::vector<std::string>& allowedWrapperIds);

private:
    struct Document {
        std::filesystem::path path;
        std::string content;
    };

    struct OrderedLine {
        size_t documentIndex = 0;
        size_t firstLine = 0;
        // Number of PHYSICAL lines this logical entry occupies (1 for a
        // single-line entry). Needed to disable/restore a whole logical entry
        // including its continuation lines.
        size_t lineCount = 1;
        std::string text;
    };

    SudoersConfigurationOptions options_;
    std::vector<Document> documents_;
    std::vector<OrderedLine> orderedLines_;
    std::vector<std::filesystem::path> includedDirectories_;

    bool expandFile(const std::filesystem::path& path,
                    std::vector<std::filesystem::path>& includeStack,
                    size_t depth,
                    std::string& error);
    bool expandDocument(size_t documentIndex,
                        std::vector<std::filesystem::path>& includeStack,
                        size_t depth,
                        std::string& error);
    std::optional<size_t> loadDocument(const std::filesystem::path& path,
                                       std::string& error);

    bool validate(std::string& error) const;
    bool isManagedDirectoryIncluded() const;
    bool checkDocumentSafety(const std::filesystem::path& path, std::string& error) const;
    bool checkDirectorySafety(const std::filesystem::path& path, std::string& error) const;
    bool contentUnchanged(const Document& document, std::string& error) const;
    bool writeDocument(const std::filesystem::path& path,
                       const std::string& content,
                       bool managedFile,
                       std::string& error) const;
    bool restoreManagedFile(bool existed,
                            const std::string& content,
                            std::string& error) const;

    void clear();
};

#endif // SUDOERSCONFIGURATION_H
