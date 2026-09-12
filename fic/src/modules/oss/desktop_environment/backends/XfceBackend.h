#ifndef XFCE_BACKEND_H
#define XFCE_BACKEND_H

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

#include <functional>
#include <string>

// Storage type of an Xfconf property as reported by the fic-xfconf-inspect
// session helper. Exact type identity is part of XFCE policy compliance:
// a textually equal value stored with a wrong GType is not compliant because
// xfce4-screensaver reads properties through the typed libxfconf API and uses
// its application default on a type mismatch.
enum class XfcePropertyType {
    Bool,
    Int,
    UInt,
    Double,
    String,
    Other
};

struct XfcePropertyState {
    XfcePropertyType type = XfcePropertyType::Other;
    std::string value;
};

inline const char* xfcePropertyTypeName(XfcePropertyType type) {
    switch (type) {
    case XfcePropertyType::Bool: return "bool";
    case XfcePropertyType::Int: return "int";
    case XfcePropertyType::UInt: return "uint";
    case XfcePropertyType::Double: return "double";
    case XfcePropertyType::String: return "string";
    case XfcePropertyType::Other: return "other";
    }
    return "other";
}

struct XfceBackendDependencies {
    std::function<std::string(const std::vector<std::string>&)> findExecutable;
    std::function<bool(const std::string&, const std::vector<std::string>&,
                       std::string&, std::string&)> execute;
};

class XfceBackend final : public DesktopEnvironmentBackend {
public:
    XfceBackend(const UserSession& session, const SessionContext& context);
    XfceBackend(const UserSession& session, const SessionContext& context,
                XfceBackendDependencies dependencies);

    const char* name() const override { return "XFCE"; }

    // Typed mutation: always uses `--create --type <type>` so that an existing
    // property with a wrong storage type is repaired in place. A plain `--set`
    // preserves the existing storage type and can never repair it.
    bool setProperty(
        const std::string& channel,
        const std::string& property,
        const std::string& type,
        const std::string& value,
        std::string& error
    ) const;

    // Type-aware read through the trusted session helper. A successfully read
    // property with a wrong storage type is reported as regular state (the
    // type is part of XfcePropertyState); only absent/unreadable properties
    // and helper/protocol failures return false.
    bool getPropertyState(
        const std::string& channel,
        const std::string& property,
        XfcePropertyState& state,
        std::string& error
    ) const;

    bool screenSaverAvailable(std::string& error) const;

private:
    XfceBackendDependencies dependencies_;

    std::string findCommand(const std::vector<std::string>& paths) const;
    bool runCommand(const std::string& executable,
                    const std::vector<std::string>& arguments,
                    std::string& output, std::string& error) const;
};

#endif // XFCE_BACKEND_H
