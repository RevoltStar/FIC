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

    SudoersOperationResult ensureManagedGlobalDefault(
        const std::string& key,
        const std::string& renderedLine,
        const std::string& expectedValue);

    SudoersOperationResult enforceAuthentication();
    std::vector<std::string> authenticationViolations() const;

private:
    struct Document {
        std::filesystem::path path;
        std::string content;
    };

    struct OrderedLine {
        size_t documentIndex = 0;
        size_t firstLine = 0;
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
