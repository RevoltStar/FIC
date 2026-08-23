#ifndef FIC_IDENTITY_LOGIN_DEFS_FILE_HANDLER_H
#define FIC_IDENTITY_LOGIN_DEFS_FILE_HANDLER_H

#include <fic/core/ConfigFileHandler.h>

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

namespace fic::identity::password_aging {

enum class LoginDefsValueState {
    Missing,
    Unique,
    Duplicate,
    Malformed
};

struct LoginDefsValue {
    LoginDefsValueState state = LoginDefsValueState::Missing;
    std::string value;
};

class LoginDefsFileHandler final : public ConfigFileHandler {
public:
    explicit LoginDefsFileHandler(
        const std::string& path,
        FileHandlerOptions options = {});

    bool loadConfig() override;
    std::string getValue(const std::string& parameter) const override;
    bool setValue(
        const std::string& parameter,
        const std::string& value) override;
    LoginDefsValue lookup(const std::string& parameter) const;
    bool saveAndReload();

private:
    struct Occurrence {
        std::size_t line = 0;
        std::string value;
        bool valid = false;
    };

    std::unordered_map<std::string, std::vector<Occurrence>> occurrences_;
};

} // namespace fic::identity::password_aging

#endif
