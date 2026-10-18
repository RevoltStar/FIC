#include "service/VerifiedConfigLaunchContract.h"
#include <fic/core/integrity/ContentDigest.h>
#include <nlohmann/json.hpp>
#include <systemd/sd-bus.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <set>
#include <sys/socket.h>
#include <unistd.h>

namespace fic::service::detail {
namespace {
using Json = nlohmann::json;
using Message = std::unique_ptr<sd_bus_message, decltype(&sd_bus_message_unref)>;
const std::vector<std::string> commands{
    "ExecConditionEx", "ExecStartPreEx", "ExecStartEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopEx", "ExecStopPostEx"};
const std::vector<std::string> unitProperties{"FragmentPath", "SourcePath", "DropInPaths", "NeedDaemonReload", "Transient", "TriggeredBy"};
const std::vector<std::string> serviceProperties{
    "PIDFile", "Restart", "ExitType", "RemainAfterExit", "FileDescriptorStoreMax", "NFileDescriptorStore",
    "Environment", "EnvironmentFiles", "PassEnvironment", "UnsetEnvironment", "User", "Group", "SupplementaryGroups",
    "DynamicUser", "PAMName", "WorkingDirectory", "UMask", "ExecSearchPath", "ExecPaths", "NoExecPaths",
    "RootDirectory", "RootImage", "RootHash", "RootHashPath", "RootHashSignature", "RootImageOptions",
    "PrivateUsers", "PrivateNetwork", "PrivateIPC", "NetworkNamespacePath", "IPCNamespacePath",
    "MountAPIVFS", "ProtectProc", "ProcSubset", "RuntimeDirectory", "StateDirectory", "CacheDirectory",
    "LogsDirectory", "ConfigurationDirectory", "StandardInput", "StandardOutput", "StandardError", "LogNamespace",
    "ExtensionDirectories", "ExtensionImages",
    "LoadCredential", "LoadCredentialEncrypted", "SetCredential", "SetCredentialEncrypted"};
void requireBus(int result, const std::string& operation) {
    if (result <= 0) throw Failure(result == -ETIMEDOUT ? ActivationStatus::TimedOut : ActivationStatus::UnsupportedConfiguration,
        "systemd launch contract unavailable: " + operation + (result < 0 ? ": " + std::string(std::strerror(-result)) : ""));
}
void timeout(sd_bus* bus, std::chrono::steady_clock::time_point deadline) {
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(deadline - std::chrono::steady_clock::now()).count();
    if (us <= 0) throw Failure(ActivationStatus::TimedOut, "launch contract deadline exceeded");
    if (sd_bus_set_method_call_timeout(bus, us) < 0) throw Failure(ActivationStatus::UnsupportedConfiguration, "bus timeout unavailable");
}
// Preserve D-Bus types in the outer signature and argv/array boundaries in JSON.
// Never parse human-readable ExecStart output or include execution timestamps.
Json readValue(sd_bus_message* message, unsigned& count, unsigned depth = 0) {
    if (++count > 16384 || depth > 16) throw Failure(ActivationStatus::UnsupportedConfiguration, "launch contract limit exceeded");
    char type; const char* contents = nullptr;
    requireBus(sd_bus_message_peek_type(message, &type, &contents), "property type");
    if (type == 'a' || type == 'r' || type == 'e' || type == 'v') {
        requireBus(sd_bus_message_enter_container(message, type, contents), "property container");
        Json values = Json::array();
        while (sd_bus_message_at_end(message, 0) == 0) values.push_back(readValue(message, count, depth + 1));
        requireBus(sd_bus_message_exit_container(message), "property container end");
        return values;
    }
    if (type == 's' || type == 'o' || type == 'g') {
        const char* value = nullptr; requireBus(sd_bus_message_read_basic(message, type, &value), "string value");
        if (!value || std::strlen(value) > 65536) throw Failure(ActivationStatus::UnsupportedConfiguration, "launch string limit exceeded");
        return value;
    }
    if (type == 'b') { int value = 0; requireBus(sd_bus_message_read_basic(message, type, &value), "boolean value"); return value != 0; }
    if (type == 't') { std::uint64_t value = 0; requireBus(sd_bus_message_read_basic(message, type, &value), "uint64 value"); return value; }
    if (type == 'x') { std::int64_t value = 0; requireBus(sd_bus_message_read_basic(message, type, &value), "int64 value"); return value; }
    if (type == 'u') { std::uint32_t value = 0; requireBus(sd_bus_message_read_basic(message, type, &value), "uint32 value"); return value; }
    if (type == 'i') { std::int32_t value = 0; requireBus(sd_bus_message_read_basic(message, type, &value), "int32 value"); return value; }
    if (type == 'y') { std::uint8_t value = 0; requireBus(sd_bus_message_read_basic(message, type, &value), "byte value"); return value; }
    throw Failure(ActivationStatus::UnsupportedConfiguration, "unsupported launch property type");
}
void readProperties(sd_bus* bus, const std::string& object, const char* interface,
                    const std::vector<std::string>& wanted, LaunchContract& contract,
                    std::chrono::steady_clock::time_point deadline) {
    timeout(bus, deadline);
    sd_bus_message* raw = nullptr;
    const int result = sd_bus_call_method(bus, "org.freedesktop.systemd1", object.c_str(),
        "org.freedesktop.DBus.Properties", "GetAll", nullptr, &raw, "s", interface);
    Message message(raw, sd_bus_message_unref); requireBus(result, "GetAll");
    requireBus(sd_bus_message_enter_container(message.get(), 'a', "{sv}"), "properties array");
    unsigned count = 0;
    while (sd_bus_message_enter_container(message.get(), 'e', "sv") > 0) {
        const char* key = nullptr; requireBus(sd_bus_message_read(message.get(), "s", &key), "property name");
        if (std::find(wanted.begin(), wanted.end(), key) == wanted.end() && std::string(key) != "ImportCredential") requireBus(sd_bus_message_skip(message.get(), "v"), "skip property");
        else {
            char type; const char* contents = nullptr; requireBus(sd_bus_message_peek_type(message.get(), &type, &contents), "variant type");
            if (type != 'v' || !contents) throw Failure(ActivationStatus::UnsupportedConfiguration, "invalid launch variant");
            const std::string signature(contents);
            requireBus(sd_bus_message_enter_container(message.get(), 'v', contents), "variant");
            auto value = readValue(message.get(), count);
            requireBus(sd_bus_message_exit_container(message.get()), "variant end");
            if (std::find(commands.begin(), commands.end(), key) != commands.end()) {
                if (signature != "a(sasasttttuii)" || !value.is_array())
                    throw Failure(ActivationStatus::UnsupportedConfiguration, "unsupported Exec*Ex schema");
                for (auto& command : value) {
                    if (!command.is_array() || command.size() != 10 || !command[0].is_string() ||
                        !command[1].is_array() || !command[2].is_array())
                        throw Failure(ActivationStatus::UnsupportedConfiguration, "invalid Exec*Ex command");
                    command = Json::array({command[0], command[1], command[2]});
                }
            }
            if (!contract.emplace("launch." + std::string(key), Json{{"signature", signature}, {"value", value}}.dump()).second)
                throw Failure(ActivationStatus::UnsupportedConfiguration, "duplicate launch property");
        }
        requireBus(sd_bus_message_exit_container(message.get()), "property end");
    }
    for (const auto& key : wanted) if (!contract.count("launch." + key))
        throw Failure(ActivationStatus::UnsupportedConfiguration, "required launch property missing: " + key);
}
Json value(const LaunchContract& contract, const std::string& key) {
    const auto it = contract.find("launch." + key);
    if (it == contract.end()) throw Failure(ActivationStatus::UnsupportedConfiguration, "required launch property missing: " + key);
    return Json::parse(it->second).at("value");
}
std::string fingerprint(const std::string& name, std::uint64_t& budget) {
    const std::filesystem::path path(name);
    if (!path.is_absolute() || path != path.lexically_normal()) throw Failure(ActivationStatus::UnsupportedConfiguration, "invalid unit path");
    auto fd = openAbsolute(path, O_RDONLY);
    struct stat before{}, after{};
    if (::fstat(fd.get(), &before) || !S_ISREG(before.st_mode) || before.st_uid != 0 || (before.st_mode & 0022))
        throw Failure(ActivationStatus::UnsupportedConfiguration, "unit file is not root-controlled");
    std::string bytes; char buffer[8192];
    while (true) {
        auto n = ::read(fd.get(), buffer, sizeof buffer);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || std::uint64_t(n) > budget) throw Failure(ActivationStatus::UnsupportedConfiguration, "cannot read bounded unit file");
        if (!n) break;
        budget -= n; bytes.append(buffer, n);
    }
    if (::fstat(fd.get(), &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mode != after.st_mode || before.st_uid != after.st_uid || before.st_gid != after.st_gid ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        throw Failure(ActivationStatus::InterferenceDetected, "unit file changed during capture");
    return Json::array({before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode,
        before.st_mtim.tv_sec, before.st_mtim.tv_nsec, before.st_ctim.tv_sec, before.st_ctim.tv_nsec,
        fic::core::ContentDigest::sha256Hex(bytes)}).dump();
}
}
LaunchContract readLaunchContract(const std::string& unit, std::chrono::steady_clock::time_point deadline) {
    sd_bus* rawBus = nullptr;
    if (sd_bus_new(&rawBus) < 0) throw Failure(ActivationStatus::UnsupportedConfiguration, "cannot allocate systemd connection");
    std::unique_ptr<sd_bus, decltype(&sd_bus_unref)> bus(rawBus, sd_bus_unref);
    // Direct PID1 peer connection: never inherit DBUS_SYSTEM_BUS_ADDRESS.
    if (sd_bus_set_address(bus.get(), "unix:path=/run/systemd/private") < 0 || sd_bus_start(bus.get()) < 0)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "systemd private connection unavailable");
    ucred peer{}; socklen_t length = sizeof peer;
    if (::getsockopt(sd_bus_get_fd(bus.get()), SOL_SOCKET, SO_PEERCRED, &peer, &length) || peer.pid != 1 || peer.uid != 0)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "systemd peer is not root PID1");
    timeout(bus.get(), deadline);
    sd_bus_message* raw = nullptr;
    const int result = sd_bus_call_method(bus.get(), "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "GetUnit", nullptr, &raw, "s", unit.c_str());
    Message reply(raw, sd_bus_message_unref); requireBus(result, "GetUnit");
    const char* object = nullptr; requireBus(sd_bus_message_read(reply.get(), "o", &object), "unit object");
    LaunchContract contract;
    readProperties(bus.get(), object, "org.freedesktop.systemd1.Unit", unitProperties, contract, deadline);
    auto service = serviceProperties; service.insert(service.end(), commands.begin(), commands.end());
    readProperties(bus.get(), object, "org.freedesktop.systemd1.Service", service, contract, deadline);
    timeout(bus.get(), deadline);
    sd_bus_message* envRaw = nullptr;
    const int envResult = sd_bus_get_property(bus.get(), "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "Environment", nullptr, &envRaw, "as");
    Message env(envRaw, sd_bus_message_unref);
    if (envResult < 0) requireBus(envResult, "manager Environment");
    unsigned count = 0; auto environment = readValue(env.get(), count);
    std::sort(environment.begin(), environment.end()); contract["launch.ManagerEnvironment"] = environment.dump();
    const auto fragment = value(contract, "FragmentPath").get<std::string>();
    const auto dropins = value(contract, "DropInPaths");
    if (fragment.empty() || !dropins.is_array() || dropins.size() > 64)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "persistent unit fragment required");
    std::uint64_t budget = 1024*1024;
    contract["launch.file:" + fragment] = fingerprint(fragment, budget);
    for (const auto& path : dropins) contract["launch.file:" + path.get<std::string>()] = fingerprint(path.get<std::string>(), budget);
    return contract;
}
std::set<std::string> validateEnvironmentFiles(const LaunchContract& contract,
                                                const std::vector<ControlledPath>* targets) {
    const auto reject = [] { throw Failure(ActivationStatus::UnsupportedConfiguration,
        "EnvironmentFiles requires typed literal existing explicit file target coverage"); };
    const auto found = contract.find("launch.EnvironmentFiles");
    if (found == contract.end()) reject();
    Json property;
    try { property = Json::parse(found->second); }
    catch (const Json::exception&) { reject(); }
    if (!property.is_object() || property.value("signature", Json()) != "a(sb)" ||
        !property.contains("value") || !property["value"].is_array()) reject();
    std::set<std::string> covered;
    for (const auto& entry : property["value"]) {
        if (!entry.is_array() || entry.size() != 2 || !entry[0].is_string() || !entry[1].is_boolean()) reject();
        const auto name = entry[0].get<std::string>();
        const std::filesystem::path path(name);
        if (name.empty() || name.size() > 4096 || !path.is_absolute() || path == path.root_path() ||
            path.lexically_normal().string() != name || name.find_first_of("*?[]%\\") != std::string::npos ||
            std::any_of(name.begin(), name.end(), [](unsigned char c) { return c < 32 || c == 127; })) reject();
        for (const auto& part : path) if (part.empty() || part == "." || part == "..") reject();
        if (!targets) reject();
        const auto target = std::find_if(targets->begin(), targets->end(), [&](const ControlledPath& p) {
            return p.path.string() == name && p.kind == ControlledPathKind::File && p.manifest.empty() &&
                p.sha256.size() == 64 && std::all_of(p.sha256.begin(), p.sha256.end(), [](char c) {
                    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
        });
        if (target == targets->end()) reject();
        // Deduplicate only the coverage lookup. The pinned typed property retains
        // original ordering, optional flags and every duplicate for comparison.
        covered.insert(name);
    }
    return covered;
}
void validateLaunchContract(const LaunchContract& contract, const std::vector<ControlledPath>* targets) {
    // First require ALL core properties even when the provided map is malformed.
    for (const auto& key : unitProperties) value(contract, key);
    for (const auto& key : serviceProperties) value(contract, key);
    for (const auto& key : commands) value(contract, key);
    if (!contract.count("launch.ManagerEnvironment"))
        throw Failure(ActivationStatus::UnsupportedConfiguration, "required manager environment missing");
    if (value(contract, "NeedDaemonReload") != false || value(contract, "Transient") != false || value(contract, "SourcePath") != "")
        throw Failure(ActivationStatus::UnsupportedConfiguration, "unit needs reload, is transient, or has external generated source");
    if (!value(contract, "TriggeredBy").empty() || value(contract, "FileDescriptorStoreMax") != 0 ||
        value(contract, "NFileDescriptorStore") != 0 || value(contract, "PIDFile") != "" ||
        value(contract, "ExitType") != "main" || value(contract, "RemainAfterExit") != false)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "activation triggers, retained FDs or alternate main identity unsupported");
    if (value(contract, "ExecStartEx").size() != 1)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "exactly one ExecStart is required");
    validateEnvironmentFiles(contract, targets);
    for (const auto& key : {"LoadCredential", "LoadCredentialEncrypted", "SetCredential", "SetCredentialEncrypted", "ExtensionDirectories", "ExtensionImages"})
        if (!value(contract, key).empty()) throw Failure(ActivationStatus::UnsupportedConfiguration, std::string("external launch input unsupported: ") + key);
    for (const auto& key : {"PAMName", "NetworkNamespacePath", "IPCNamespacePath", "LogNamespace"})
        if (value(contract, key) != "") throw Failure(ActivationStatus::UnsupportedConfiguration, std::string("external launch context unsupported: ") + key);
    for (const auto& key : {"DynamicUser", "PrivateUsers", "PrivateNetwork", "PrivateIPC", "MountAPIVFS"})
        if (value(contract, key) != false) throw Failure(ActivationStatus::UnsupportedConfiguration, std::string("namespace/identity launch context unsupported: ") + key);
    if (contract.count("launch.ImportCredential") && !value(contract, "ImportCredential").empty())
        throw Failure(ActivationStatus::UnsupportedConfiguration, "external credential imports unsupported");
    for (const auto& key : {"StandardOutput", "StandardError"}) {
        const auto output = value(contract, key).get<std::string>();
        if (output != "null" && output != "journal" && output != "inherit" && output != "kmsg")
            throw Failure(ActivationStatus::UnsupportedConfiguration, "stdio launch redirection unsupported");
    }
    if (value(contract, "StandardInput") != "null" || value(contract, "ProtectProc") != "default" || value(contract, "ProcSubset") != "all")
        throw Failure(ActivationStatus::UnsupportedConfiguration, "stdin/proc launch context unsupported");
}
} // namespace fic::service::detail
