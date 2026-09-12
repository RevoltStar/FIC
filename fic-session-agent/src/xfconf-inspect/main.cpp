// FIC session helper: typed Xfconf property inspection.
//
// The daemon runs this helper inside the target graphical session through the
// session-scoped execution path, so it talks to the session Xfconf daemon over
// the session D-Bus. Plain `xfconf-query` text output cannot report the actual
// storage GType of a property, while XFCE policies must verify that the stored
// type matches the type xfce4-screensaver reads through the typed API.
//
// Success output (stdout), a versioned machine-readable line protocol:
//   fic-xfconf-inspect-protocol=1
//   type=<bool|int|uint|double|string|<GType name>>
//   value=<scalar text>
// The value line is emitted only for scalar types with a policy-known alias.
// Unknown/aggregate storage types are reported with their GType name and no
// value, so the caller sees "type mismatch" instead of a guessed value.
//
// Exit codes:
//   0  property successfully read
//   2  usage error
//   3  property absent / unreadable
//   4  Xfconf runtime initialization failure
#include <xfconf/xfconf.h>

#include <glib.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace {

constexpr int EXIT_OK = 0;
constexpr int EXIT_USAGE = 2;
constexpr int EXIT_READ_FAILED = 3;
constexpr int EXIT_XFCONF_INIT_FAILED = 4;

const char* scalarTypeAlias(GType type) {
    if (type == G_TYPE_BOOLEAN) return "bool";
    if (type == G_TYPE_INT) return "int";
    if (type == G_TYPE_UINT) return "uint";
    if (type == G_TYPE_DOUBLE) return "double";
    if (type == G_TYPE_STRING) return "string";
    return nullptr;
}

std::string serializeScalarValue(const GValue& value) {
    if (G_VALUE_HOLDS_BOOLEAN(&value))
        return g_value_get_boolean(&value) ? "true" : "false";
    if (G_VALUE_HOLDS_INT(&value))
        return std::to_string(g_value_get_int(&value));
    if (G_VALUE_HOLDS_UINT(&value))
        return std::to_string(g_value_get_uint(&value));
    if (G_VALUE_HOLDS_DOUBLE(&value)) {
        char buffer[G_ASCII_DTOSTR_BUF_SIZE];
        g_ascii_formatd(buffer, sizeof(buffer), "%.17g",
                        g_value_get_double(&value));
        return buffer;
    }
    if (G_VALUE_HOLDS_STRING(&value)) {
        const gchar* raw = g_value_get_string(&value);
        return raw != nullptr ? std::string(raw) : std::string();
    }
    return std::string();
}

void emitPropertyState(std::FILE* output, const GValue& value) {
    const GType type = G_VALUE_TYPE(&value);
    const char* alias = scalarTypeAlias(type);
    std::fprintf(output, "fic-xfconf-inspect-protocol=1\n");
    if (alias != nullptr) {
        std::fprintf(output, "type=%s\n", alias);
        std::fprintf(output, "value=%s\n", serializeScalarValue(value).c_str());
    } else {
        // Never masquerade a policy-unknown storage type as a known one.
        std::fprintf(output, "type=%s\n", g_type_name(type));
    }
}

struct SelfTestExpectation {
    GType type;
    bool withValue;
    const char* expectedTypeLine;
    const char* expectedValueLine; // nullptr when withValue is false
};

bool runSelfTest() {
    const SelfTestExpectation expectations[] = {
        {G_TYPE_BOOLEAN, true, "type=bool", "value=true"},
        {G_TYPE_INT, true, "type=int", "value=5"},
        {G_TYPE_INT, true, "type=int", "value=0"},
        {G_TYPE_UINT, true, "type=uint", "value=5"},
        {G_TYPE_DOUBLE, true, "type=double", "value=5"},
        {G_TYPE_STRING, true, "type=string", "value=5"},
        {G_TYPE_STRING, true, "type=string", "value=true"},
        {G_TYPE_INT64, false, "type=gint64", nullptr},
    };

    bool passed = true;
    for (const SelfTestExpectation& expectation : expectations) {
        GValue value = G_VALUE_INIT;
        g_value_init(&value, expectation.type);
        if (expectation.type == G_TYPE_BOOLEAN)
            g_value_set_boolean(&value, TRUE);
        if (expectation.type == G_TYPE_INT)
            g_value_set_int(&value,
                            std::strcmp(expectation.expectedValueLine,
                                        "value=0") == 0 ? 0 : 5);
        if (expectation.type == G_TYPE_UINT)
            g_value_set_uint(&value, 5U);
        if (expectation.type == G_TYPE_DOUBLE)
            g_value_set_double(&value, 5.0);
        if (expectation.type == G_TYPE_STRING)
            g_value_set_static_string(
                &value,
                std::strcmp(expectation.expectedValueLine,
                            "value=true") == 0 ? "true" : "5");

        char* recorded = nullptr;
        std::size_t recordedSize = 0;
        FILE* sink = open_memstream(&recorded, &recordedSize);
        if (sink == nullptr) {
            std::fprintf(stderr, "self-test: open_memstream failed\n");
            g_value_unset(&value);
            return false;
        }
        emitPropertyState(sink, value);
        std::fclose(sink);
        g_value_unset(&value);

        const std::string output(recorded, recordedSize);
        std::free(recorded);

        std::string expected = "fic-xfconf-inspect-protocol=1\n";
        expected += expectation.expectedTypeLine;
        expected += "\n";
        if (expectation.withValue) {
            expected += expectation.expectedValueLine;
            expected += "\n";
        }
        if (output != expected) {
            std::fprintf(stderr, "self-test: %s emitted unexpected output: %s",
                         expectation.expectedTypeLine, output.c_str());
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
    if (!xfconf_init(&error)) {
        std::fprintf(stderr, "failed to initialize Xfconf: %s\n",
                     error != nullptr ? error->message : "unknown error");
        if (error != nullptr) g_error_free(error);
        return EXIT_XFCONF_INIT_FAILED;
    }

    XfconfChannel* channel = xfconf_channel_new(channelName);
    if (channel == nullptr) {
        std::fprintf(stderr, "failed to open Xfconf channel: %s\n",
                     channelName);
        xfconf_shutdown();
        return EXIT_READ_FAILED;
    }

    GValue value = G_VALUE_INIT;
    if (!xfconf_channel_get_property(channel, propertyPath, &value)) {
        std::fprintf(stderr, "failed to read property %s on channel %s\n",
                     propertyPath, channelName);
        g_object_unref(channel);
        xfconf_shutdown();
        return EXIT_READ_FAILED;
    }

    emitPropertyState(stdout, value);
    g_value_unset(&value);
    g_object_unref(channel);
    xfconf_shutdown();
    return EXIT_OK;
}
