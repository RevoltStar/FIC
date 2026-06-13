#include "modules/oss/submodules/DesktopEnvironment/backends/KdeBackend.h"

namespace {
struct KConfigTools {
    std::string writer;
    std::string reader;
};

KConfigTools find_kconfig_tools()
{
    for (const int version : {6, 5}) {
        const std::string suffix = std::to_string(version);
        const std::string writer = DesktopEnvironmentBackend::findExecutable({
            "/usr/bin/kwriteconfig" + suffix,
            "/bin/kwriteconfig" + suffix
        });
        const std::string reader = DesktopEnvironmentBackend::findExecutable({
            "/usr/bin/kreadconfig" + suffix,
            "/bin/kreadconfig" + suffix
        });
        if (!writer.empty() && !reader.empty()) {
            return {writer, reader};
        }
    }
    return {};
}
} // namespace

bool KdeBackend::writeConfig(
    const std::string& file,
    const std::string& group,
    const std::string& key,
    const std::string& value,
    std::string& error
) const
{
    const KConfigTools tools = find_kconfig_tools();
    if (tools.writer.empty()) {
        error = "kwriteconfig and kreadconfig were not found";
        return false;
    }
    std::string output;
    return execute(
        tools.writer,
        {"--file", file, "--group", group, "--key", key, value},
        output,
        error
    );
}

bool KdeBackend::readConfig(
    const std::string& file,
    const std::string& group,
    const std::string& key,
    std::string& value,
    std::string& error
) const
{
    const KConfigTools tools = find_kconfig_tools();
    if (tools.reader.empty()) {
        error = "kwriteconfig and kreadconfig were not found";
        return false;
    }
    return execute(
        tools.reader,
        {"--file", file, "--group", group, "--key", key},
        value,
        error
    );
}

bool KdeBackend::callDbusMethod(
    const std::string& service,
    const std::string& path,
    const std::string& interface,
    const std::string& method,
    std::string& error
) const
{
    const std::string busctl = findExecutable({
        "/usr/bin/busctl",
        "/bin/busctl"
    });
    if (busctl.empty()) {
        error = "busctl was not found";
        return false;
    }
    std::string output;
    return execute(
        busctl,
        {"--user", "call", service, path, interface, method},
        output,
        error
    );
}
