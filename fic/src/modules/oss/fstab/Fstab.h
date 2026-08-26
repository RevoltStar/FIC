#ifndef FSTAB_H
#define FSTAB_H

#include "modules/oss/OSS.h"

#include <optional>
#include <string>
#include <vector>

class Fstab : public OSS
{
public:
    enum class Scope {
        ExplicitMountPoints,
        WorldWritableMountPoints
    };

    Fstab();
    virtual ~Fstab() = default;

    bool apply() override;

protected:
    struct OptionProfile {
        std::string name;
        std::vector<std::string> options;
    };

    Scope scope = Scope::ExplicitMountPoints;
    std::vector<std::string> mountPoints;
    std::vector<std::string> requiredOptions;
    std::vector<OptionProfile> optionProfiles;

    void configureFixedOptions(const std::vector<std::string>& options);
    void configureProfiles(const std::vector<OptionProfile>& profiles);

private:
    struct Entry {
        size_t lineIndex = 0;
        std::vector<std::string> fields;
    };

    std::optional<std::vector<std::string>> selectedOptions();
    std::vector<Entry> loadEntries() const;
    bool shouldProcessEntry(const Entry& entry) const;
    bool isWorldWritableDirectory(const std::string& path) const;
    bool ensureOptions(Entry& entry, const std::vector<std::string>& optionsToRequire) const;
    std::vector<std::string> splitOptions(const std::string& options) const;
    std::string joinOptions(const std::vector<std::string>& options) const;
    std::string optionKey(const std::string& option) const;
    std::vector<std::string> oppositeOptions(const std::string& option) const;
    std::string formatEntry(const Entry& entry) const;
};

#endif // FSTAB_H
