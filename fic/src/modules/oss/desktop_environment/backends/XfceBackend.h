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

// Explicit presence of an Xfconf property. Absent is a well-defined,
// authoritative Xfconf state (exact D-Bus error
// org.xfce.Xfconf.Error.PropertyNotFound from a live daemon) and is distinct
// from read/runtime/protocol failures, which are reported as backend method
// failure instead. Absence is legitimate on a fresh XFCE profile and must be
// treated as a mismatch that the typed writer materializes, never as a read
// error.
enum class XfcePropertyStateKind {
    Present,
    Absent
};

struct XfcePropertyState {
    XfcePropertyStateKind kind = XfcePropertyStateKind::Absent;
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

    // Type-aware read through the trusted session helper. Semantics:
    //   true  + kind=Present → property successfully read; the storage type is
    //           part of XfcePropertyState, a wrong type is regular state;
    //   true  + kind=Absent  → authoritative PropertyNotFound from a live
    //           Xfconf daemon (the property does not exist);
    //   false                → real read/runtime/protocol/helper failure;
    //           the caller must fail closed and never write.
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
