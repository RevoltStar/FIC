#ifndef FIC_IDENTITY_USERADD_DEFAULTS_FILE_HANDLER_H
#define FIC_IDENTITY_USERADD_DEFAULTS_FILE_HANDLER_H

#include <fic/core/ConfigFileHandler.h>

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

namespace fic::identity {

enum class UseraddDefaultsValueState {
    Missing,
    Unique,
    Duplicate,
    Malformed
};

struct UseraddDefaultsValue {
    UseraddDefaultsValueState state = UseraddDefaultsValueState::Missing;
    std::string value;
};

class UseraddDefaultsFileHandler final : public ConfigFileHandler {
public:
    explicit UseraddDefaultsFileHandler(
        const std::string& path,
        FileHandlerOptions options = {});

    bool loadConfig() override;
    std::string getValue(const std::string& parameter) const override;
    bool setValue(const std::string& parameter, const std::string& value) override;
    UseraddDefaultsValue lookup(const std::string& parameter) const;
    bool saveAndReload();

private:
    struct Occurrence {
        std::size_t line = 0;
        std::string value;
        bool valid = false;
    };

    std::unordered_map<std::string, std::vector<Occurrence>> occurrences_;
};

} // namespace fic::identity

#endif
