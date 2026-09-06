#include "modules/oss/desktop_environment/ControlledDesktopEnvironmentsPolicyTypeValue.h"

#include <algorithm>
#include <cctype>

namespace {
std::string trim(std::string value)
{
    const auto nonSpace = [](unsigned char character) {
        return std::isspace(character) == 0;
    };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), nonSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), nonSpace).base(), value.end());
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::toupper(character));
    });
    return value;
}
}

ControlledDesktopEnvironmentsPolicyTypeValue::
ControlledDesktopEnvironmentsPolicyTypeValue()
{
    defaultValue.clear();
}

PolicyEditorSpec ControlledDesktopEnvironmentsPolicyTypeValue::getEditorSpec() const
{
    PolicyEditorSpec spec;
    spec.editor = "textedit";
    spec.textDelimiter = ",";
    // The daemon remains authoritative for enum validation. The GUI's shared
    // descriptor contract intentionally supports only its existing validators.
    spec.validator = "none";
    return spec;
}

std::vector<std::string> ControlledDesktopEnvironmentsPolicyTypeValue::tokens(
    const std::string& value)
{
    std::vector<std::string> result;
    std::string current;
    for (const char character : value) {
        if (character == ',' || character == '\n' || character == '\r') {
            if (!current.empty() || character == ',') result.push_back(trim(current));
            current.clear();
            continue;
        }
        current.push_back(character);
    }
    if (!current.empty() || (!value.empty() && value.back() == ',')) {
        result.push_back(trim(current));
    }
    return result;
}

bool ControlledDesktopEnvironmentsPolicyTypeValue::parse(
    const std::string& value,
    DesktopEnvironmentSet& environments)
{
    environments.clear();
    if (value.empty()) return true;
    for (const std::string& token : tokens(value)) {
        const DesktopEnvironmentKind kind =
            DesktopEnvironmentBackend::kindFromCanonicalName(token);
        if (token.empty() || kind == DesktopEnvironmentKind::Unknown ||
            !environments.insert(kind).second) {
            environments.clear();
            return false;
        }
    }
    return true;
}

bool ControlledDesktopEnvironmentsPolicyTypeValue::validate(
    const std::string& value)
{
    DesktopEnvironmentSet environments;
    return parse(value, environments);
}

std::string ControlledDesktopEnvironmentsPolicyTypeValue::postProcessingValue(
    const std::string& value)
{
    DesktopEnvironmentSet environments;
    if (!parse(value, environments)) return {};
    json serialized = json::array();
    for (const DesktopEnvironmentKind kind : environments) {
        serialized.push_back(DesktopEnvironmentBackend::kindName(kind));
    }
    return serialized.dump();
}

std::string ControlledDesktopEnvironmentsPolicyTypeValue::reverse_postProcessingValue(
    const std::string& value)
{
    try {
        const json serialized = json::parse(value);
        if (!serialized.is_array()) return value;
        std::string result;
        for (const auto& item : serialized) {
            if (!item.is_string()) return value;
            if (!result.empty()) result += ',';
            result += item.get<std::string>();
        }
        return result;
    } catch (const std::exception&) {
        return value;
    }
}

std::string ControlledDesktopEnvironmentsPolicyTypeValue::getPolicyRestrictionInfo()
{
    return "Comma-separated administrative scope: FLY, GNOME, KDE, XFCE, LXQT. "
           "An empty list is unconfigured, not an allow-list containing no desktops.";
}
