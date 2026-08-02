#ifndef FIC_IDENTITY_ACCESS_PAM_OPTION_FILE_H
#define FIC_IDENTITY_ACCESS_PAM_OPTION_FILE_H

#include <filesystem>
#include <string>

namespace fic::identity::pam {

class PamOptionFile {
public:
    static bool setValue(const std::filesystem::path& path,
                         const std::string& key,
                         const std::string& value,
                         std::string& error);

    static bool hasOnlyValue(const std::filesystem::path& path,
                             const std::string& key,
                             const std::string& expectedValue,
                             std::string& error);

    static bool setFlag(const std::filesystem::path& path,
                        const std::string& key,
                        bool enabled,
                        std::string& error);

    static bool hasFlag(const std::filesystem::path& path,
                        const std::string& key,
                        bool expectedEnabled,
                        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_OPTION_FILE_H
