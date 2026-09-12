// FIC session helper: typed Xfconf property inspection with explicit absence.
//
// The daemon runs this helper inside the target graphical session through the
// session-scoped execution path, so it talks to the session D-Bus. Plain
// `xfconf-query` text output cannot report the actual storage type of a
// property, while XFCE policies must verify that the stored type matches the
// type xfce4-screensaver reads through the typed API.
//
// The property is read through the `org.xfce.Xfconf` D-Bus API directly
// (GDBus) instead of the public libxfconf C API. The C API swallows every
// failure into a plain `FALSE` return, so an absent property is
// indistinguishable there from a dead Xfconf daemon or a real read failure.
// At the D-Bus level the states are cleanly separated: an absent property is
// answered with the exact remote error name
// `org.xfce.Xfconf.Error.PropertyNotFound`, while a missing daemon or a
// runtime failure surfaces as a different D-Bus error (ServiceUnknown,
// Spawn.ExecFailed, ReadFailure, PermissionDenied, InternalError, ...). Only
// that exact error name is classified as absence; every other failure is a
// real error and fails closed. Auto-start of the Xfconf daemon is disabled so
// that a dead daemon can never be silently resurrected into an "absent"
// answer.
//
// Success output (stdout), a versioned machine-readable line protocol:
//   fic-xfconf-inspect-protocol=2
//   state=present
//   type=<bool|int|uint|double|string|<storage type name>>
//   value=<scalar text>
// The value line is emitted only for scalar types with a policy-known alias.
// Unknown/aggregate storage types are reported with their type name and no
// value, so the caller sees "type mismatch" instead of a guessed value.
// An absent property is a valid protocol result, not a failure:
//   fic-xfconf-inspect-protocol=2
//   state=absent
//
// Exit codes:
//   0  valid protocol result (state=present or state=absent)
//   2  usage error
//   3  real read/runtime D-Bus error (daemon down, read failure, ...)
//   4  helper initialization failure (session bus unreachable, ...)
#include <gio/gio.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace {

constexpr int EXIT_OK = 0;
constexpr int EXIT_USAGE = 2;
constexpr int EXIT_READ_FAILED = 3;
constexpr int EXIT_INIT_FAILED = 4;

constexpr const char* kProtocolHeader = "fic-xfconf-inspect-protocol=2\n";
constexpr const char* kPropertyNotFound =
    "org.xfce.Xfconf.Error.PropertyNotFound";

enum class RemoteErrorKind {
    PropertyNotFound,
    OtherFailure
};

// Exact remote D-Bus error name mapping. Deliberately name-based, not
// substring-based: only the authoritative PropertyNotFound error denotes an
// absent property. A missing remote error name (local GLib failure) and every
// other error (ServiceUnknown, Spawn.ExecFailed, PermissionDenied,
// ReadFailure, InternalError, ...) is a real failure.
RemoteErrorKind classifyRemoteErrorName(const char* remoteErrorName) {
    if (remoteErrorName != nullptr &&
        std::strcmp(remoteErrorName, kPropertyNotFound) == 0)
        return RemoteErrorKind::PropertyNotFound;
    return RemoteErrorKind::OtherFailure;
}

// Display name for a storage type: policy-known scalar aliases keep their
// short names, the common 64-bit types keep their xfconf GType names, and
// anything else is reported as its raw GVariant type string.
const char* storageTypeName(const char* variantType) {
    if (std::strcmp(variantType, "b") == 0) return "bool";
    if (std::strcmp(variantType, "i") == 0) return "int";
    if (std::strcmp(variantType, "u") == 0) return "uint";
    if (std::strcmp(variantType, "d") == 0) return "double";
    if (std::strcmp(variantType, "s") == 0) return "string";
    if (std::strcmp(variantType, "x") == 0) return "gint64";
    if (std::strcmp(variantType, "t") == 0) return "guint64";
    return variantType;
}

// Policy-known scalar types are the only ones that may carry a value line.
bool policyKnownScalar(const char* variantType) {
    return std::strcmp(variantType, "b") == 0 ||
           std::strcmp(variantType, "i") == 0 ||
           std::strcmp(variantType, "u") == 0 ||
           std::strcmp(variantType, "d") == 0 ||
           std::strcmp(variantType, "s") == 0;
}

std::string serializeScalarValue(GVariant* value) {
    switch (g_variant_classify(value)) {
    case G_VARIANT_CLASS_BOOLEAN:
        return g_variant_get_boolean(value) ? "true" : "false";
    case G_VARIANT_CLASS_INT32:
        return std::to_string(g_variant_get_int32(value));
    case G_VARIANT_CLASS_UINT32:
        return std::to_string(g_variant_get_uint32(value));
    case G_VARIANT_CLASS_DOUBLE: {
        char buffer[G_ASCII_DTOSTR_BUF_SIZE];
        g_ascii_formatd(buffer, sizeof(buffer), "%.17g",
                        g_variant_get_double(value));
        return buffer;
    }
    case G_VARIANT_CLASS_STRING: {
        const gchar* raw = g_variant_get_string(value, nullptr);
        return raw != nullptr ? std::string(raw) : std::string();
    }
    default:
        return std::string();
    }
}

std::string formatPresentState(GVariant* value) {
    const char* variantType = g_variant_get_type_string(value);
    std::string output;
    output += kProtocolHeader;
    output += "state=present\ntype=";
    // Never masquerade a policy-unknown storage type as a known one: unknown
    // types are reported by name only, without a guessed value.
    output += storageTypeName(variantType);
    if (policyKnownScalar(variantType)) {
        output += "\nvalue=";
        output += serializeScalarValue(value);
    }
    output += "\n";
    return output;
}

std::string formatAbsentState() {
    // Absence carries no fake type/value records.
    std::string output;
    output += kProtocolHeader;
    output += "state=absent\n";
    return output;
}

struct PresentSelfTestExpectation {
    GVariant* value;
    const char* name;
    const char* expectedTypeLine;
    const char* expectedValueLine; // nullptr when no value line is expected
};

bool runSelfTest() {
    bool passed = true;
    const PresentSelfTestExpectation expectations[] = {
        {g_variant_new_boolean(TRUE), "bool true", "type=bool", "value=true"},
        {g_variant_new_boolean(FALSE), "bool false", "type=bool",
         "value=false"},
        {g_variant_new_int32(5), "int 5", "type=int", "value=5"},
        {g_variant_new_int32(0), "int 0", "type=int", "value=0"},
        {g_variant_new_uint32(5), "uint 5", "type=uint", "value=5"},
        {g_variant_new_double(5.0), "double 5", "type=double", "value=5"},
        {g_variant_new_string("5"), "string 5", "type=string", "value=5"},
        {g_variant_new_string("true"), "string true", "type=string",
         "value=true"},
        // Policy-unknown storage types keep their type name and no value:
        // the caller must see the mismatch, never a guessed value.
        {g_variant_new_int64(5), "gint64 5", "type=gint64", nullptr},
        {g_variant_new_uint64(5), "guint64 5", "type=guint64", nullptr},
    };

    for (const PresentSelfTestExpectation& expectation : expectations) {
        const std::string output = formatPresentState(expectation.value);
        g_variant_unref(expectation.value);

        std::string expected = kProtocolHeader;
        expected += "state=present\n";
        expected += expectation.expectedTypeLine;
        expected += "\n";
        if (expectation.expectedValueLine != nullptr) {
            expected += expectation.expectedValueLine;
            expected += "\n";
        }
        if (output != expected) {
            std::fprintf(stderr,
                         "self-test: %s emitted unexpected output: %s",
                         expectation.name, output.c_str());
            passed = false;
        }
    }

    const std::string absent = formatAbsentState();
    if (absent != "fic-xfconf-inspect-protocol=2\nstate=absent\n") {
        std::fprintf(stderr,
                     "self-test: absent state emitted unexpected output: %s",
                     absent.c_str());
        passed = false;
    }

    struct RemoteErrorExpectation {
        const char* remoteErrorName;
        RemoteErrorKind expected;
    };
    const RemoteErrorExpectation errorExpectations[] = {
        {"org.xfce.Xfconf.Error.PropertyNotFound",
         RemoteErrorKind::PropertyNotFound},
        // Every other remote error name is a real failure, never absence.
        {"org.freedesktop.DBus.Error.ServiceUnknown",
         RemoteErrorKind::OtherFailure},
        {"org.freedesktop.DBus.Error.Spawn.ExecFailed",
         RemoteErrorKind::OtherFailure},
        {"org.xfce.Xfconf.Error.PermissionDenied",
         RemoteErrorKind::OtherFailure},
        {"org.xfce.Xfconf.Error.ReadFailure", RemoteErrorKind::OtherFailure},
        {"org.xfce.Xfconf.Error.InternalError",
         RemoteErrorKind::OtherFailure},
        {"org.xfce.Xfconf.Error.InvalidProperty",
         RemoteErrorKind::OtherFailure},
        {nullptr, RemoteErrorKind::OtherFailure},
        {"", RemoteErrorKind::OtherFailure},
    };
    for (const RemoteErrorExpectation& expectation : errorExpectations) {
        if (classifyRemoteErrorName(expectation.remoteErrorName) !=
            expectation.expected) {
            std::fprintf(stderr,
                         "self-test: remote D-Bus error name %s was "
                         "classified wrong\n",
                         expectation.remoteErrorName != nullptr
                             ? expectation.remoteErrorName
                             : "(local error)");
            passed = false;
        }
    }
    return passed;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--self-test") == 0) {
        return runSelfTest() ? EXIT_OK : 1;
    }

    const char* channelName = nullptr;
    const char* propertyPath = nullptr;
    for (int index = 1; index < argc; index += 2) {
        if (index + 1 >= argc) {
            std::fprintf(stderr, "usage: fic-xfconf-inspect --channel <name> "
                                 "--property <path>\n");
            return EXIT_USAGE;
        }
        if (std::strcmp(argv[index], "--channel") == 0 &&
            channelName == nullptr) {
            channelName = argv[index + 1];
        } else if (std::strcmp(argv[index], "--property") == 0 &&
                   propertyPath == nullptr) {
            propertyPath = argv[index + 1];
        } else {
            std::fprintf(stderr, "usage: fic-xfconf-inspect --channel <name> "
                                 "--property <path>\n");
            return EXIT_USAGE;
        }
    }
    if (channelName == nullptr || propertyPath == nullptr) {
        std::fprintf(stderr, "usage: fic-xfconf-inspect --channel <name> "
                             "--property <path>\n");
        return EXIT_USAGE;
    }

    GError* error = nullptr;
    // DO_NOT_AUTO_START keeps a dead Xfconf daemon dead: a missing service
    // must surface as a real failure, never as an "absent property" answer.
    GDBusProxy* proxy = g_dbus_proxy_new_for_bus_sync(
        G_BUS_TYPE_SESSION, G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START, nullptr,
        "org.xfce.Xfconf", "/org/xfce/Xfconf", "org.xfce.Xfconf", nullptr,
        &error);
    if (proxy == nullptr) {
        std::fprintf(stderr, "failed to connect to the session D-Bus: %s\n",
                     error != nullptr ? error->message : "unknown error");
        if (error != nullptr) g_error_free(error);
        return EXIT_INIT_FAILED;
    }

    GVariant* reply = g_dbus_proxy_call_sync(
        proxy, "GetProperty",
        g_variant_new("(ss)", channelName, propertyPath),
        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1, nullptr, &error);
    if (reply == nullptr) {
        gchar* remoteErrorName = g_dbus_error_get_remote_error(error);
        const RemoteErrorKind kind = classifyRemoteErrorName(remoteErrorName);
        if (remoteErrorName != nullptr) g_free(remoteErrorName);
        if (kind == RemoteErrorKind::PropertyNotFound) {
            // Authoritative absence: the daemon is up and answered that the
            // property does not exist. A valid protocol result, not a failure.
            std::fputs(formatAbsentState().c_str(), stdout);
            g_error_free(error);
            g_object_unref(proxy);
            return EXIT_OK;
        }
        std::fprintf(stderr, "failed to read property %s on channel %s: %s\n",
                     propertyPath, channelName,
                     error != nullptr ? error->message : "unknown error");
        g_error_free(error);
        g_object_unref(proxy);
        return EXIT_READ_FAILED;
    }

    GVariant* value = nullptr;
    g_variant_get(reply, "(v)", &value);
    g_variant_unref(reply);
    std::fputs(formatPresentState(value).c_str(), stdout);
    g_variant_unref(value);
    g_object_unref(proxy);
    return EXIT_OK;
}
