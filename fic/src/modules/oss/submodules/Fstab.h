#ifndef FSTAB_H
#define FSTAB_H

#include "modules/oss/OSS.h"

#include <functional>
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
    Scope scope = Scope::ExplicitMountPoints;
    std::vector<std::string> mountPoints;
    std::vector<std::string> requiredOptions;

private:
    struct Entry {
        size_t lineIndex = 0;
        std::vector<std::string> fields;
    };

    std::vector<Entry> loadEntries() const;
    bool shouldProcessEntry(const Entry& entry) const;
    bool isWorldWritableDirectory(const std::string& path) const;
    bool ensureOptions(Entry& entry) const;
    std::vector<std::string> splitOptions(const std::string& options) const;
    std::string joinOptions(const std::vector<std::string>& options) const;
    std::string oppositeOption(const std::string& option) const;
    std::string formatEntry(const Entry& entry) const;
};

#endif // FSTAB_H
