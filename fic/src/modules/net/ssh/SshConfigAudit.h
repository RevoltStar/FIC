#ifndef SSHCONFIGAUDIT_H
#define SSHCONFIGAUDIT_H

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

struct SshConditionalOccurrence {
    std::filesystem::path path;
    std::size_t line = 0;
    std::string value;
    std::string condition;
};

struct SshConfigAuditOptions {
    std::filesystem::path configPath;
    std::filesystem::path includeBasePath;
    std::size_t maximumIncludeDepth = 16;
    std::size_t maximumIncludedFiles = 256;
};

class SshConfigAudit {
public:
    explicit SshConfigAudit(SshConfigAuditOptions options);

    bool findConditionalOccurrences(
        const std::string& parameter,
        std::vector<SshConditionalOccurrence>& occurrences,
        std::string& error
    ) const;

private:
    SshConfigAuditOptions options_;
};

#endif // SSHCONFIGAUDIT_H
