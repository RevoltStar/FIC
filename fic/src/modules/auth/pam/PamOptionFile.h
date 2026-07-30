#ifndef FIC_AUTH_PAM_OPTION_FILE_H
#define FIC_AUTH_PAM_OPTION_FILE_H

#include <filesystem>
#include <string>

namespace fic::auth {

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
};

} // namespace fic::auth

#endif // FIC_AUTH_PAM_OPTION_FILE_H
