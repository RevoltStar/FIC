#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWDQC_CONFIG_FILE_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWDQC_CONFIG_FILE_H

#include <array>
#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace fic::identity::pam {

struct PasswdqcMinimums {
    std::array<std::optional<unsigned int>, 5> values;

    bool operator==(const PasswdqcMinimums& other) const {
        return values == other.values;
    }
};

class PasswdqcMinimumsCodec {
public:
    static bool parse(const std::string& value,
                      PasswdqcMinimums& result,
                      std::string& error);
    static std::string serialize(const PasswdqcMinimums& value);
};

class PasswdqcConfigFile {
public:
    using Writer = std::function<bool(
        const std::string&,
        const std::string&,
        const AtomicWriteOptions&,
        std::string*)>;

    static bool setValue(const std::filesystem::path& path,
                         const std::string& option,
                         const std::string& value,
                         std::string& error,
                         Writer writer = {});

    static bool hasOnlyValue(const std::filesystem::path& path,
                             const std::string& option,
                             const std::string& expectedValue,
                             std::string& error);

    static bool validateNativeValue(const std::string& option,
                                    const std::string& value,
                                    std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWDQC_CONFIG_FILE_H
