#ifndef SUDOERSCONFIGURATION_H
#define SUDOERSCONFIGURATION_H

#include <filesystem>
#include <mutex>
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
    // THE single mutex serializing EVERY filesystem-mutating SUDO path:
    // scalar managed Defaults apply, the authentication rewrite, scoped
    // Defaults apply, managed-Defaults rollback and scoped-Defaults rollback.
    // The previous per-translation-unit mutexes did NOT actually serialize
    // apply against rollback, so the comment claiming they did was false.
    //
    // Lock ordering: this is the INNERMOST lock. Never hold a journal-internal
    // mutex while acquiring it, and never hold it across a long process
    // operation unless the backend genuinely needs it (the backend does: a
    // read-modify-write of the same sudoers graph must not interleave).
    static std::mutex& mutationMutex();

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

    // Read-only view of the loaded graph, consumed by
    // SudoersScopedDefaultsTransaction. SudoersConfiguration stays the OWNER
    // of parsing and the include graph; all scoped-Defaults remediation
    // (planning, ownership proof, transactions, compensation) lives in the
    // dedicated transaction component.
    struct GraphDocument {
        std::filesystem::path path;
        std::string content;
    };

    struct GraphEntry {
        size_t documentIndex = 0;
        size_t firstLine = 0;
        // PHYSICAL lines the logical entry occupies (1 for a single line).
        size_t lineCount = 1;
        std::string text;
    };

    std::vector<GraphDocument> graphDocuments() const;
    std::vector<GraphEntry> graphEntries() const;

    // The exact @includedir membership the LAST SUCCESSFUL load() used to build
    // the graph.
    //
    // SECURITY ROLE: a captured file set alone is not a sufficient security
    // proof. If the membership of an @includedir changed after load(), the
    // effective graph FIC planned and proved against is stale: a brand-new
    // eligible member may carry active scoped Defaults or a copied FIC wrapper
    // that no capture path knows about. So membership is part of the proof
    // state and any change invalidates it.
    //
    // Membership identity is deliberately NOT a content identity: the content of
    // each member is proven separately by the ordinary file capture/proof
    // layer. This answers exactly one question: "do the same eligible physical
    // members still constitute this @includedir?".
    struct IncludedDirectoryTopology {
        // Canonical path of the directory.
        std::filesystem::path canonicalPath;
        // Whether the directory EXISTED at load time. A directory that was
        // absent then and is absent now is unchanged; a directory that was
        // known and then disappears is NOT an empty directory.
        bool existed = false;
        // Exactly the names the loader itself would expand, in the SAME
        // lexical order the parser uses. Ignored names are never listed, so an
        // ignored member can never cause a false mismatch.
        std::vector<std::string> eligibleMembers;
    };

    // Topology captured by the last successful load().
    const std::vector<IncludedDirectoryTopology>& includedDirectoryTopology() const {
        return includedDirectoryTopology_;
    }

    // Re-enumerates every @includedir captured by load() and fails closed unless
    // the membership is still identical: no member added, removed or renamed,
    // and no directory that became missing / not-a-directory / unreadable.
    //
    // The comparison reuses the SAME eligibility rule as the parser, so an
    // ignored filename cannot produce a false mismatch.
    bool verifyIncludedDirectoryTopologyUnchanged(std::string& error) const;

    // Runs the configured validator (visudo) over the current configuration.
    // Exposed for the scoped-Defaults transaction, which owns the filesystem
    // steps but must not duplicate the sudoers-specific validation logic.
    bool validateConfiguration(std::string& error) const { return validate(error); }

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
    std::vector<IncludedDirectoryTopology> includedDirectoryTopology_;

    // THE single implementation of "@includedir membership": existence check,
    // directory safety, eligibility filter and lexical ordering. Used BOTH by
    // load() to build the graph AND by verifyIncludedDirectoryTopologyUnchanged()
    // to re-prove membership, so the parser and the topology verifier can never
    // drift apart.
    bool enumerateIncludedirMembers(
        const std::filesystem::path& directory,
        std::vector<std::filesystem::path>& entries,
        bool& exists,
        std::string& error) const;

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
