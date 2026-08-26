#ifndef FIC_IDENTITY_ADDUSER_CONFIG_FILE_HANDLER_H
#define FIC_IDENTITY_ADDUSER_CONFIG_FILE_HANDLER_H

#include <fic/core/config/ConfigFileHandler.h>

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

namespace fic::identity {

enum class AdduserConfigValueState {
    Missing,
    Unique,
    Duplicate,
    Malformed
};

struct AdduserConfigValue {
    AdduserConfigValueState state = AdduserConfigValueState::Missing;
    std::string value;
};

class AdduserConfigFileHandler final : public ConfigFileHandler {
public:
    explicit AdduserConfigFileHandler(
        const std::string& path,
        FileHandlerOptions options = {});

    bool loadConfig() override;
    std::string getValue(const std::string& parameter) const override;
    AdduserConfigValue lookup(const std::string& parameter) const;
    bool setSupplementaryGroups(
        bool enabled,
        const std::vector<std::string>& groups);
    bool saveAndReload();

private:
    struct Occurrence {
        std::size_t line = 0;
        std::string value;
        bool valid = false;
    };

    bool setCanonicalValue(
        const std::string& parameter,
        const std::string& value,
        bool quoted);

    std::unordered_map<std::string, std::vector<Occurrence>> occurrences_;
};

} // namespace fic::identity

#endif
