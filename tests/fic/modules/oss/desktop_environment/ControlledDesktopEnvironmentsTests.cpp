#include "modules/oss/desktop_environment/ControlledDesktopEnvironmentsPolicyTypeValue.h"

#include <stdexcept>
#include <string>

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
}

int main() {
    ControlledDesktopEnvironmentsPolicyTypeValue value;
    require(value.getDefaultValue().empty(), "default scope must be unconfigured");
    DesktopEnvironmentSet parsed;
    require(ControlledDesktopEnvironmentsPolicyTypeValue::parse("", parsed) &&
            parsed.empty(), "empty scope must parse as unconfigured");
    require(ControlledDesktopEnvironmentsPolicyTypeValue::parse(
                "GNOME, KDE, XFCE, LXQT, FLY", parsed),
            "supported canonical desktops were rejected");
    require(parsed.size() == 5, "typed desktop set has wrong size");
    require(!ControlledDesktopEnvironmentsPolicyTypeValue::parse("GNOME,", parsed),
            "trailing empty entry was accepted");
    require(!ControlledDesktopEnvironmentsPolicyTypeValue::parse("GNOME,GNOME", parsed),
            "duplicate desktop was accepted");
    require(!ControlledDesktopEnvironmentsPolicyTypeValue::parse("MATE", parsed),
            "unsupported arbitrary desktop was accepted");
    require(value.postProcessingValue("GNOME,KDE") == "[\"GNOME\",\"KDE\"]",
            "serialized scope is not canonical JSON");
    return 0;
}
