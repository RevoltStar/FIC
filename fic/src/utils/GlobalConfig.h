#ifndef GLOBALCONFIG_H
#define GLOBALCONFIG_H

#include <optional>
#include <string>

class GlobalConfig
{
public:
    static std::optional<std::string> getEnabledValue(const std::string& parameter);
};

#endif // GLOBALCONFIG_H
