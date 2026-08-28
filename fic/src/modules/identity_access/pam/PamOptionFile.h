#ifndef FIC_IDENTITY_ACCESS_PAM_OPTION_FILE_H
#define FIC_IDENTITY_ACCESS_PAM_OPTION_FILE_H

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace fic::identity::pam {

class PamOptionFile {
public:
    using Writer = std::function<bool(
        const std::string&,
        const std::string&,
        const AtomicWriteOptions&,
        std::string*)>;

    static bool setValue(const std::filesystem::path& path,
                         const std::string& key,
                         const std::string& value,
                         std::string& error,
                         Writer writer = {});

    static bool hasOnlyValue(const std::filesystem::path& path,
                             const std::string& key,
                             const std::string& expectedValue,
                             std::string& error);

    static bool setFlag(const std::filesystem::path& path,
                        const std::string& key,
                        bool enabled,
                        std::string& error,
                        Writer writer = {});

    static bool hasFlag(const std::filesystem::path& path,
                        const std::string& key,
                        bool expectedEnabled,
                        std::string& error);

    static bool verifyNoActiveDirectives(
        const std::filesystem::path& path,
        const std::vector<std::string>& directives,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_OPTION_FILE_H
