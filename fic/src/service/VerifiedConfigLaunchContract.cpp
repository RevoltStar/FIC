#include "service/VerifiedConfigLaunchContract.h"
#include "platform/PlatformProfile.h"
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
const std::vector<std::string> unitProperties{"StartLimitIntervalUSec", "StartLimitBurst", "UnitFileState", "FragmentPath", "SourcePath", "DropInPaths", "NeedDaemonReload", "Transient", "TriggeredBy"};
const std::vector<std::string> serviceProperties{
    "PIDFile", "Restart", "KillMode", "ExitType", "RemainAfterExit", "FileDescriptorStoreMax", "NFileDescriptorStore",
    "Environment", "EnvironmentFiles", "PassEnvironment", "UnsetEnvironment", "User", "Group", "SupplementaryGroups",
    "DynamicUser", "PAMName", "WorkingDirectory", "UMask", "ExecSearchPath", "ExecPaths", "NoExecPaths",
    "RootDirectory", "RootImage", "RootHash", "RootHashPath", "RootHashSignature", "RootImageOptions",
    "PrivateUsers", "PrivateNetwork", "PrivateIPC", "NetworkNamespacePath", "IPCNamespacePath",
    "MountAPIVFS", "ProtectProc", "ProcSubset", "RuntimeDirectory", "StateDirectory", "CacheDirectory",
    "LogsDirectory", "ConfigurationDirectory", "RuntimeDirectoryMode", "StandardInput", "StandardOutput", "StandardError", "LogNamespace",
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
}
std::string fingerprintUnitSource(int root, const std::string& name, std::uint64_t& budget
#ifdef FIC_ACTIVATOR_TESTING
                                 , const std::function<void()>& captured
#endif
                                 ) {
    const std::filesystem::path path(name);
    if (name.empty() || name.size() > 4096 || !path.is_absolute() || path.lexically_normal().string() != name ||
        path == path.root_path())
        throw Failure(ActivationStatus::UnsupportedConfiguration, "invalid unit path");
    unsigned depth = 0;
    for (const auto& part : path) if (part.empty() || part == "." || part == ".." || ++depth > 128)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "invalid unit path component/depth");
    const bool vendor = name.rfind("/lib/systemd/system/", 0) == 0;
    // Every traversal starts at a pinned root and opens only no-follow descriptors.
    // The sole accepted alias is inspected via its own O_PATH descriptor, never followed.
    struct Capture { Json chain; std::string canonical; Fd file; std::vector<Fd> held; };
    const auto capture = [&]() {
        Json chain = Json::array();
        std::vector<Fd> held;
        const auto record = [&](int fd, const std::string& component, bool link) {
            const auto id = identity(fd); struct stat st{};
            if (::fstat(fd, &st) || id.uid != 0 ||
                (link ? !S_ISLNK(id.mode) : (!S_ISDIR(id.mode) || (id.mode & 0022))))
                throw Failure(ActivationStatus::UnsupportedConfiguration, "untrusted unit source component");
            Json entry{{"path", component}, {"mount", id.mount}, {"device", id.device},
                       {"inode", id.inode}, {"uid", id.uid}, {"gid", id.gid}, {"mode", id.mode}};
            if (link) {
                char target[4097]; const auto n = ::readlinkat(fd, "", target, sizeof target);
                if (n <= 0 || n == sizeof target)
                    throw Failure(ActivationStatus::UnsupportedConfiguration, "unit alias target unavailable");
                const std::string text(target, n);
                if (text != "usr/lib" && text != "/usr/lib")
                    throw Failure(ActivationStatus::UnsupportedConfiguration, "unsupported unit alias target");
                entry["target"] = text;
                entry["mtime"] = Json::array({st.st_mtim.tv_sec, st.st_mtim.tv_nsec});
                entry["ctime"] = Json::array({st.st_ctim.tv_sec, st.st_ctim.tv_nsec});
            }
            Fd pinned(::fcntl(fd, F_DUPFD_CLOEXEC, 3));
            if (!pinned) throw Failure(ActivationStatus::UnsupportedConfiguration, "cannot pin unit component");
            held.push_back(std::move(pinned));
            chain.push_back(entry);
        };
        Fd current(::fcntl(root, F_DUPFD_CLOEXEC, 3));
        record(current.get(), "/", false);
        std::string resolved = name;
        if (vendor) {
            Fd lib(::openat(current.get(), "lib", O_PATH|O_NOFOLLOW|O_CLOEXEC));
            if (!lib) throw Failure(ActivationStatus::UnsupportedConfiguration, "unit alias unavailable");
            if (S_ISLNK(identity(lib.get()).mode)) {
                record(lib.get(), "/lib", true);
                resolved = "/usr/lib" + name.substr(4);
            }
        }
        std::string component;
        const auto relative = std::filesystem::path(resolved).relative_path();
        for (auto it = relative.begin(); it != relative.end(); ++it) {
            component += "/" + it->string();
            auto next = it; ++next;
            Fd child(::openat(current.get(), it->c_str(), O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK|
                             (next == relative.end() ? O_RDONLY : O_PATH|O_DIRECTORY)));
            if (!child) throw Failure(ActivationStatus::UnsupportedConfiguration, "cannot open trusted unit source");
            if (next != relative.end()) record(child.get(), component, false);
            else {
                const auto id = identity(child.get());
                chain.push_back(Json{{"path", component}, {"mount", id.mount}, {"device", id.device},
                    {"inode", id.inode}, {"mode", id.mode}, {"uid", id.uid}, {"gid", id.gid}});
            }
            current = std::move(child);
        }
        return Capture{std::move(chain), resolved, std::move(current), std::move(held)};
    };
    auto initial = capture(); const auto& chain = initial.chain; auto& fd = initial.file;
    struct stat before{}, after{};
    if (::fstat(fd.get(), &before) || !S_ISREG(before.st_mode) || before.st_uid != 0 || (before.st_mode & 0022))
        throw Failure(ActivationStatus::UnsupportedConfiguration, "unit file is not root-controlled");
#ifdef FIC_ACTIVATOR_TESTING
    if (captured) captured();
#endif
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
    auto repeated = [&]() {
        try { return capture(); }
        catch (const Failure& e) { throw Failure(ActivationStatus::InterferenceDetected, e.what()); }
    }();
    if (chain != repeated.chain || identity(fd.get()).mount != identity(repeated.file.get()).mount ||
        !sameObject(identity(fd.get()), identity(repeated.file.get())))
        throw Failure(ActivationStatus::InterferenceDetected, "unit resolution changed during capture");
    if (::fstat(fd.get(), &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mode != after.st_mode || before.st_uid != after.st_uid || before.st_gid != after.st_gid ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        throw Failure(ActivationStatus::InterferenceDetected, "unit file changed during capture");
    return Json{{"original", name}, {"canonical", initial.canonical}, {"chain", chain},
        {"file", Json::array({before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode,
        before.st_size, before.st_mtim.tv_sec, before.st_mtim.tv_nsec, before.st_ctim.tv_sec, before.st_ctim.tv_nsec,
        fic::core::ContentDigest::sha256Hex(bytes)})}}.dump();
}
struct SshUnitReferences {
    std::unique_ptr<sd_bus,decltype(&sd_bus_unref)> bus{nullptr,sd_bus_unref};
    std::string manager;
    ~SshUnitReferences(){if(bus)sd_bus_close(bus.get());}
};
namespace {
std::string referencedManager(sd_bus* bus,std::chrono::steady_clock::time_point deadline) {
    timeout(bus,deadline);sd_bus_creds* raw=nullptr;
    const auto code=sd_bus_get_name_creds(bus,"org.freedesktop.systemd1",SD_BUS_CREDS_PID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_UNIQUE_NAME,&raw);
    std::unique_ptr<sd_bus_creds,decltype(&sd_bus_creds_unref)> credentials(raw,sd_bus_creds_unref);
    pid_t pid=0;uid_t uid=static_cast<uid_t>(-1);const char* owner=nullptr;
    if(code<0||!credentials||sd_bus_creds_get_pid(credentials.get(),&pid)<0||sd_bus_creds_get_euid(credentials.get(),&uid)<0||
       sd_bus_creds_get_unique_name(credentials.get(),&owner)<0||pid!=1||uid!=0||!owner||owner[0]!=':'||std::strlen(owner)>255)
        throw Failure(ActivationStatus::UnsupportedConfiguration,"SSH unit GC-reference manager identity unavailable");
    return owner;
}
}
std::shared_ptr<const SshUnitReferences> retainSshUnitsForValidation(ActivationProfile profile,std::chrono::steady_clock::time_point deadline) {
    if(profile!=ActivationProfile::ActiveNotifyService&&profile!=ActivationProfile::UbuntuSshSocket&&profile!=ActivationProfile::AltSshSimple&&profile!=ActivationProfile::SssdNotify)
        throw Failure(ActivationStatus::UnsupportedConfiguration,"unknown service unit-reference profile");
    // Fixed root-controlled system bus endpoint. The broker may run as
    // messagebus: its credentials are not confused with PID1 credentials.
    // RefUnit requires the API-bus sender, whereas authoritative launch queries
    // below remain on the direct /run/systemd/private root-PID1 connection.
    for(const auto& path:{"/run","/run/dbus"}) {
        auto fd=openAbsolute(path,O_PATH|O_DIRECTORY);const auto st=identity(fd.get());
        if(st.uid!=0||(st.mode&0022))throw Failure(ActivationStatus::UnsupportedConfiguration,"untrusted unit-reference bus directory");
    }
    auto socket=openAbsolute("/run/dbus/system_bus_socket",O_PATH);const auto st=identity(socket.get());
    if(st.uid!=0||!S_ISSOCK(st.mode))throw Failure(ActivationStatus::UnsupportedConfiguration,"untrusted unit-reference bus socket");
    auto refs=std::make_shared<SshUnitReferences>();sd_bus* raw=nullptr;
    if(sd_bus_new(&raw)<0)throw Failure(ActivationStatus::UnsupportedConfiguration,"unit-reference bus allocation failed");
    refs->bus.reset(raw);timeout(raw,deadline);
    if(sd_bus_set_address(raw,"unix:path=/run/dbus/system_bus_socket")<0||sd_bus_set_bus_client(raw,1)<0||sd_bus_start(raw)<0)
        throw Failure(ActivationStatus::UnsupportedConfiguration,"unit-reference API bus unavailable");
    refs->manager=referencedManager(raw,deadline);
    std::vector<std::string> names{profile==ActivationProfile::SssdNotify?"sssd.service":profile==ActivationProfile::AltSshSimple?"sshd.service":"ssh.service"};
    if(profile==ActivationProfile::UbuntuSshSocket)names.push_back("ssh.socket");
    for(const auto& name:names) {
        timeout(raw,deadline);
        // systemd v252 method_ref_unit: GENERIC_UNIT_LOAD |
        // GENERIC_UNIT_VALIDATE_LOADED, then bus_unit_method_ref, in one call.
        // https://github.com/systemd/systemd/blob/v252/src/core/dbus-manager.c
        requireBus(sd_bus_call_method(raw,refs->manager.c_str(),"/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager","RefUnit",nullptr,nullptr,"s",name.c_str()),"retain installed service unit");
    }
    verifySshUnitReferences(*refs,deadline);return refs;
}
void verifySshUnitReferences(const SshUnitReferences& refs,std::chrono::steady_clock::time_point deadline) {
    if(!refs.bus||referencedManager(refs.bus.get(),deadline)!=refs.manager)
        throw Failure(ActivationStatus::InterferenceDetected,"unit-reference systemd owner changed");
}
static LaunchContract readContract(const std::string& unit, std::chrono::steady_clock::time_point deadline, bool socket, bool runtime=false, bool sssd=false, bool releaseEpoch=false) {
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
    if(runtime) {
        readProperties(bus.get(),object,"org.freedesktop.systemd1.Unit",{"Id","LoadState","ActiveState","SubState","Job"},contract,deadline);
    }
    if(sssd) readProperties(bus.get(),object,"org.freedesktop.systemd1.Unit",{"InvocationID"},contract,deadline);
    if(socket) {
        const std::vector<std::string> socketUnit{"Id","Names","LoadState","ActiveState","SubState","Job","InvocationID","Triggers"};
        readProperties(bus.get(),object,"org.freedesktop.systemd1.Unit",socketUnit,contract,deadline);
        const std::vector<std::string> properties{"Listen","Accept","FreeBind","BindIPv6Only","ReusePort","SocketProtocol",
            "BindToDevice","Symlinks","FileDescriptorName","ExecStartPre","ExecStartPost","ExecStopPre","ExecStopPost"};
        readProperties(bus.get(),object,"org.freedesktop.systemd1.Socket",properties,contract,deadline);
    } else {
        auto service = serviceProperties; service.insert(service.end(), commands.begin(), commands.end());
        if(runtime)service.push_back("MainPID");
        if(releaseEpoch)service.insert(service.end(),{"ControlGroup","ExecMainStartTimestampMonotonic","ExecMainExitTimestampMonotonic"});
        if(sssd) {
            const std::vector<std::string> extra{"Type","NotifyAccess","ReadWritePaths","ReadOnlyPaths",
                "InaccessiblePaths","MountFlags","PrivateMounts","PrivateTmp","PrivateDevices","ProtectClock",
                "ProtectKernelTunables","ProtectKernelModules","ProtectKernelLogs","ProtectControlGroups",
                "ProtectHome","ProtectSystem","BindPaths","BindReadOnlyPaths","TemporaryFileSystem","ProtectHostname"};
            service.insert(service.end(),extra.begin(),extra.end());
        }
        readProperties(bus.get(), object, "org.freedesktop.systemd1.Service", service, contract, deadline);
    }
    timeout(bus.get(), deadline);
    sd_bus_message* envRaw = nullptr;
    const int envResult = sd_bus_get_property(bus.get(), "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "Environment", nullptr, &envRaw, "as");
    Message env(envRaw, sd_bus_message_unref);
    if (envResult < 0) requireBus(envResult, "manager Environment");
    unsigned count = 0; auto environment = readValue(env.get(), count);
    std::sort(environment.begin(), environment.end()); contract["launch.ManagerEnvironment"] = environment.dump();
    if(sssd) readProperties(bus.get(),"/org/freedesktop/systemd1","org.freedesktop.systemd1.Manager",{"UnitPath"},contract,deadline);
    const auto fragment = value(contract, "FragmentPath").get<std::string>();
    const auto dropins = value(contract, "DropInPaths");
    if (fragment.empty() || !dropins.is_array() || dropins.size() > 64)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "persistent unit fragment required");
    auto root = openAbsolute("/", O_PATH|O_DIRECTORY);
    std::uint64_t budget = 1024*1024;
    contract["launch.file:" + fragment] = fingerprintUnitSource(root.get(), fragment, budget);
    for (const auto& path : dropins) contract["launch.file:" + path.get<std::string>()] = fingerprintUnitSource(root.get(), path.get<std::string>(), budget);
    if(releaseEpoch) {
        // Endpoints alone do not prove unit topology. Inspect the complete
        // loaded socket set through the SAME verified root-PID1 connection.
        timeout(bus.get(),deadline);sd_bus_message* listedRaw=nullptr;
        const int code=sd_bus_call_method(bus.get(),"org.freedesktop.systemd1","/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager","ListUnits",nullptr,&listedRaw,nullptr);
        Message listed(listedRaw,sd_bus_message_unref);requireBus(code,"offline socket unit enumeration");
        if(!sd_bus_message_has_signature(listed.get(),"a(ssssssouso)"))
            throw Failure(ActivationStatus::UnsupportedConfiguration,"offline unit list schema");
        unsigned count=0;const auto units=readValue(listed.get(),count);Json topology=Json::object();
        if(!units.is_array()||units.size()>1024)throw Failure(ActivationStatus::UnsupportedConfiguration,"offline unit enumeration bound");
        const auto related=[](const std::string& name){return name=="sssd.service"||name=="sssd.socket"||name.rfind("sssd-",0)==0;};
        for(const auto& entry:units) {
            if(!entry.is_array()||entry.size()!=10||!entry[0].is_string()||!entry[6].is_string())
                throw Failure(ActivationStatus::UnsupportedConfiguration,"offline unit identity schema");
            const auto name=entry[0].get<std::string>();
            if(name.size()<7||name.substr(name.size()-7)!=".socket")continue;
            LaunchContract socket;
            readProperties(bus.get(),entry[6].get<std::string>(),"org.freedesktop.systemd1.Unit",
                {"Id","LoadState","ActiveState","SubState","Job","Triggers","Requires","Wants","BindsTo",
                 "ActiveEnterTimestampMonotonic","InactiveEnterTimestampMonotonic"},socket,deadline);
            bool relevant=related(name);
            for(const auto* field:{"Triggers","Requires","Wants","BindsTo"}) {
                const auto refs=Json::parse(socket.at(std::string("launch.")+field));
                if(refs.at("signature")!="as"||!refs.at("value").is_array())
                    throw Failure(ActivationStatus::UnsupportedConfiguration,"offline socket dependency schema");
                for(const auto& ref:refs.at("value")) {
                    if(!ref.is_string())throw Failure(ActivationStatus::UnsupportedConfiguration,"offline socket dependency identity");
                    relevant|=related(ref.get<std::string>());
                }
            }
            if(!relevant)continue;
            const auto prop=[&](const char* key,const char* signature) {
                const auto v=Json::parse(socket.at(std::string("launch.")+key));
                if(v.at("signature")!=signature)throw Failure(ActivationStatus::UnsupportedConfiguration,"offline socket property type");
                return v.at("value");
            };
            const auto job=prop("Job","(uo)");
            if(prop("Id","s")!=name||prop("ActiveState","s")!="inactive"||prop("SubState","s")!="dead"||
               !job.is_array()||job.size()!=2||!job[0].is_number_unsigned()||job[0]!=0)
                throw Failure(ActivationStatus::UnsupportedConfiguration,"SSSD socket unit is active/pending/unknown: "+name+" "+Json(socket).dump());
            const auto load=prop("LoadState","s");
            if(load=="not-found") {
                // GetUnit/Show/old dependency lookups can leave a nonexistent
                // empty unit object. It is not a loaded activation topology.
                // Recognize ONLY a never-active, dependency-free placeholder;
                // do not mistake masked/failed/partially loaded units for it.
                for(const auto* field:{"Triggers","Requires","Wants","BindsTo"})
                    if(!prop(field,"as").empty())throw Failure(ActivationStatus::UnsupportedConfiguration,"nonempty missing SSSD socket topology: "+name);
                for(const auto* field:{"ActiveEnterTimestampMonotonic","InactiveEnterTimestampMonotonic"})
                    if(prop(field,"t")!=0)throw Failure(ActivationStatus::UnsupportedConfiguration,"missing SSSD socket has activation history: "+name);
                continue; // GC of an empty absent object is not a state change.
            }
            if(load!="loaded")throw Failure(ActivationStatus::UnsupportedConfiguration,"SSSD socket load state unproven: "+name);
            if(!topology.emplace(name,socket).second)
                throw Failure(ActivationStatus::UnsupportedConfiguration,"duplicate offline socket unit");
        }
        contract["release.SocketTopology"]=topology.dump();
    }
    return contract;
}
LaunchContract readLaunchContract(const std::string& unit,std::chrono::steady_clock::time_point deadline) {
    return readContract(unit,deadline,false);
}
LaunchContract readSssdLaunchContract(std::chrono::steady_clock::time_point deadline) {
    return readContract("sssd.service",deadline,false,true,true);
}
LaunchContract readSssdReleaseEpoch(std::chrono::steady_clock::time_point deadline) {
    const auto full=readContract("sssd.service",deadline,false,true,true,true);
    LaunchContract epoch{{"release.SocketTopology",full.at("release.SocketTopology")}};
    for(const auto* key:{"ControlGroup","ExecMainStartTimestampMonotonic","ExecMainExitTimestampMonotonic"})
        epoch[std::string("launch.")+key]=full.at(std::string("launch.")+key);
    return epoch;
}
LaunchContract readAltSshRuntime(std::chrono::steady_clock::time_point deadline) {
    return readContract("sshd.service",deadline,false,true);
}
LaunchContract readSshSocketContract(std::chrono::steady_clock::time_point deadline) {
    return readContract("ssh.socket",deadline,true);
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
void validateLaunchContract(const LaunchContract& contract, const std::vector<ControlledPath>* targets, ActivationProfile profile) {
    // First require ALL core properties even when the provided map is malformed.
    for (const auto& key : unitProperties) value(contract, key);
    for (const auto& key : serviceProperties) value(contract, key);
    for (const auto& key : commands) value(contract, key);
    if (!contract.count("launch.ManagerEnvironment"))
        throw Failure(ActivationStatus::UnsupportedConfiguration, "required manager environment missing");
    if (value(contract, "NeedDaemonReload") != false || value(contract, "Transient") != false || value(contract, "SourcePath") != "")
        throw Failure(ActivationStatus::UnsupportedConfiguration, "unit needs reload, is transient, or has external generated source");
    const auto triggers=value(contract,"TriggeredBy");
    const bool validTriggers=profile==ActivationProfile::UbuntuSshSocket ? triggers==Json::array({"ssh.socket"}) : triggers.empty();
    bool pidSupported=value(contract,"PIDFile")=="";
    if(profile==ActivationProfile::SssdNotify){
        const auto platform=fic::platform::makeBuildPlatformProfile().id;
        const bool legacy=platform=="debian-12"||platform=="ubuntu-24.04"||platform=="alt-p11";
        if(!legacy&&platform!="debian-13"&&platform!="ubuntu-26.04")
            throw Failure(ActivationStatus::UnsupportedConfiguration,"unknown SSSD native platform");
        if(value(contract,"Id")!="sssd.service"||value(contract,"Type")!="notify"||value(contract,"NotifyAccess")!="main")
            throw Failure(ActivationStatus::UnsupportedConfiguration,"only closed SSSD notify/main service supported");
        pidSupported=value(contract,"PIDFile")==Json(legacy?"/run/sssd.pid":"");
    }
    if (!validTriggers || value(contract, "FileDescriptorStoreMax") != 0 ||
        value(contract, "NFileDescriptorStore") != 0 || !pidSupported ||
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
