#include "session/LogindSessionContainmentBackend.h"

#include <systemd/sd-bus.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace fic::session {
namespace {
constexpr const char* Service = "org.freedesktop.login1";
constexpr const char* Manager = "org.freedesktop.login1.Manager";
constexpr const char* Session = "org.freedesktop.login1.Session";
constexpr const char* User = "org.freedesktop.login1.User";
constexpr const char* ManagerPath = "/org/freedesktop/login1";
constexpr std::uint64_t CallTimeoutUsec = 500000;
constexpr auto InventoryDeadline = std::chrono::seconds(5);
constexpr std::size_t MaximumObjects = 128;
using Bus = std::unique_ptr<sd_bus, decltype(&sd_bus_unref)>;
using Message = std::unique_ptr<sd_bus_message, decltype(&sd_bus_message_unref)>;

std::string detail(int result, const sd_bus_error& error) {
    if (error.message) return error.message;
    return std::strerror(-result);
}

bool openBus(Bus& bus, std::string& owner, const std::string& expected,
             std::string& diagnostic, const char* serviceName = Service) {
    sd_bus* raw = nullptr;
    int result = sd_bus_open_system(&raw);
    bus.reset(raw);
    if (result < 0) {
        diagnostic = std::string("system bus unavailable: ") + std::strerror(-result);
        return false;
    }
    result = sd_bus_set_method_call_timeout(bus.get(), CallTimeoutUsec);
    if (result < 0) { diagnostic = "bus timeout configuration failed"; return false; }
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message* reply = nullptr;
    result = sd_bus_call_method(bus.get(), "org.freedesktop.DBus",
        "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner",
        &error, &reply, "s", serviceName);
    Message answer(reply, sd_bus_message_unref);
    if (result < 0) {
        diagnostic = "logind owner unavailable: " + detail(result, error);
        sd_bus_error_free(&error);
        return false;
    }
    const char* name = nullptr;
    result = sd_bus_message_read(answer.get(), "s", &name);
    sd_bus_error_free(&error);
    if (result < 0 || !name || name[0] != ':') {
        diagnostic = "logind unique owner is invalid";
        return false;
    }
    owner = name;
    if (!expected.empty() && owner != expected) {
        diagnostic = "logind owner changed";
        return false;
    }
    return true;
}

bool getString(sd_bus* bus, const std::string& owner,
               const std::string& path, const char* interface,
               const char* property, std::string& output,
               std::string& diagnostic) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    char* raw = nullptr;
    const int result = sd_bus_get_property_string(
        bus, owner.c_str(), path.c_str(), interface, property, &error, &raw);
    if (result < 0) diagnostic = std::string(property) + ": " + detail(result, error);
    else output = raw ? raw : "";
    std::free(raw);
    sd_bus_error_free(&error);
    return result >= 0;
}

bool getTrivial(sd_bus* bus, const std::string& owner,
                const std::string& path, const char* interface,
                const char* property, char type, void* output,
                std::string& diagnostic) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    const int result = sd_bus_get_property_trivial(
        bus, owner.c_str(), path.c_str(), interface, property,
        &error, type, output);
    if (result < 0) diagnostic = std::string(property) + ": " + detail(result, error);
    sd_bus_error_free(&error);
    return result >= 0;
}

bool getSessionRecord(sd_bus* bus, const std::string& owner,
                      LogindSessionRecord& record, std::string& diagnostic) {
    if (!getString(bus, owner, record.path, Session, "Id", record.id, diagnostic) ||
        !getString(bus, owner, record.path, Session, "Name", record.name, diagnostic) ||
        !getString(bus, owner, record.path, Session, "Type", record.type, diagnostic) ||
        !getString(bus, owner, record.path, Session, "Class", record.className, diagnostic) ||
        !getString(bus, owner, record.path, Session, "State", record.state, diagnostic) ||
        !getTrivial(bus, owner, record.path, Session, "TimestampMonotonic", 't',
                    &record.timestamp, diagnostic)) return false;
    int remote = 0;
    if (!getTrivial(bus, owner, record.path, Session, "Remote", 'b',
                    &remote, diagnostic)) return false;
    record.remote = remote != 0;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message* raw = nullptr;
    const int result = sd_bus_get_property(bus, owner.c_str(), record.path.c_str(),
        Session, "User", &error, &raw, "(uo)");
    Message value(raw, sd_bus_message_unref);
    if (result < 0) {
        diagnostic = "session User: " + detail(result, error);
        sd_bus_error_free(&error);
        return false;
    }
    std::uint32_t uid = 0;
    const char* userPath = nullptr;
    const int parsed = sd_bus_message_read(value.get(), "(uo)", &uid, &userPath);
    sd_bus_error_free(&error);
    if (parsed < 0 || !userPath) {
        diagnostic = "session User property malformed";
        return false;
    }
    record.uid = uid;
    record.owner = owner;
    return true;
}

bool getUserRecord(sd_bus* bus, const std::string& owner,
                   LogindUserRecord& record, std::string& diagnostic) {
    if (!getString(bus, owner, record.path, User, "Name", record.name, diagnostic) ||
        !getString(bus, owner, record.path, User, "State", record.state, diagnostic))
        return false;
    std::uint32_t uid = 0;
    int linger = 0;
    if (!getTrivial(bus, owner, record.path, User, "UID", 'u', &uid, diagnostic) ||
        !getTrivial(bus, owner, record.path, User, "Linger", 'b', &linger, diagnostic))
        return false;
    record.uid = uid;
    record.linger = linger != 0;
    record.owner = owner;
    return true;
}

bool missingError(const sd_bus_error& error) {
    return error.name && (
        std::strcmp(error.name, "org.freedesktop.login1.NoSuchSession") == 0 ||
        std::strcmp(error.name, "org.freedesktop.login1.NoSuchUser") == 0 ||
        std::strcmp(error.name, "org.freedesktop.DBus.Error.UnknownObject") == 0);
}

class SystemLogindClient final : public LogindClient {
public:
    bool listSessions(std::vector<LogindSessionRecord>& output,
                      std::string& diagnostic) override {
        output.clear();
        Bus bus(nullptr, sd_bus_unref);
        std::string owner;
        if (!openBus(bus, owner, "", diagnostic)) return false;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message* raw = nullptr;
        int result = sd_bus_call_method(bus.get(), owner.c_str(), ManagerPath,
            Manager, "ListSessions", &error, &raw, "");
        Message reply(raw, sd_bus_message_unref);
        if (result < 0) {
            diagnostic = "ListSessions: " + detail(result, error);
            sd_bus_error_free(&error); return false;
        }
        sd_bus_error_free(&error);
        result = sd_bus_message_enter_container(reply.get(), 'a', "(susso)");
        if (result < 0) { diagnostic = "ListSessions malformed array"; return false; }
        const auto deadline = std::chrono::steady_clock::now() + InventoryDeadline;
        for (;;) {
            const char* id = nullptr; const char* name = nullptr;
            const char* seat = nullptr; const char* path = nullptr;
            std::uint32_t uid = 0;
            result = sd_bus_message_read(reply.get(), "(susso)",
                                         &id, &uid, &name, &seat, &path);
            if (result == 0) break;
            if (result < 0 || output.size() >= MaximumObjects ||
                std::chrono::steady_clock::now() >= deadline ||
                !id || !name || !path) {
                diagnostic = "ListSessions malformed, oversized or timed out";
                return false;
            }
            LogindSessionRecord record;
            record.path = path;
            if (!getSessionRecord(bus.get(), owner, record, diagnostic)) return false;
            if (record.id != id || record.uid != uid || record.name != name)
            { diagnostic = "ListSessions identity changed during snapshot"; return false; }
            output.push_back(std::move(record));
        }
        return true;
    }

    bool listUsers(std::vector<LogindUserRecord>& output,
                   std::string& diagnostic) override {
        output.clear();
        Bus bus(nullptr, sd_bus_unref);
        std::string owner;
        if (!openBus(bus, owner, "", diagnostic)) return false;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message* raw = nullptr;
        int result = sd_bus_call_method(bus.get(), owner.c_str(), ManagerPath,
            Manager, "ListUsers", &error, &raw, "");
        Message reply(raw, sd_bus_message_unref);
        if (result < 0) {
            diagnostic = "ListUsers: " + detail(result, error);
            sd_bus_error_free(&error); return false;
        }
        sd_bus_error_free(&error);
        result = sd_bus_message_enter_container(reply.get(), 'a', "(uso)");
        if (result < 0) { diagnostic = "ListUsers malformed array"; return false; }
        const auto deadline = std::chrono::steady_clock::now() + InventoryDeadline;
        for (;;) {
            const char* name = nullptr; const char* path = nullptr;
            std::uint32_t uid = 0;
            result = sd_bus_message_read(reply.get(), "(uso)", &uid, &name, &path);
            if (result == 0) break;
            if (result < 0 || output.size() >= MaximumObjects ||
                std::chrono::steady_clock::now() >= deadline ||
                !name || !path) {
                diagnostic = "ListUsers malformed, oversized or timed out";
                return false;
            }
            LogindUserRecord record;
            record.path = path;
            if (!getUserRecord(bus.get(), owner, record, diagnostic)) return false;
            if (record.uid != uid || record.name != name)
            { diagnostic = "ListUsers identity changed during snapshot"; return false; }
            output.push_back(std::move(record));
        }
        return true;
    }

    LogindLookup getSession(const LogindSessionRecord& expected,
                            LogindSessionRecord& current,
                            std::string& diagnostic) override {
        Bus bus(nullptr, sd_bus_unref); std::string owner;
        if (!openBus(bus, owner, expected.owner, diagnostic)) return LogindLookup::Error;
        sd_bus_error error = SD_BUS_ERROR_NULL; sd_bus_message* raw = nullptr;
        const int result = sd_bus_call_method(bus.get(), owner.c_str(), ManagerPath,
            Manager, "GetSession", &error, &raw, "s", expected.id.c_str());
        Message reply(raw, sd_bus_message_unref);
        if (result < 0) {
            const bool missing = missingError(error);
            diagnostic = "GetSession: " + detail(result, error);
            sd_bus_error_free(&error);
            return missing ? LogindLookup::Missing : LogindLookup::Error;
        }
        sd_bus_error_free(&error);
        const char* path = nullptr;
        if (sd_bus_message_read(reply.get(), "o", &path) < 0 || !path) {
            diagnostic = "GetSession malformed path"; return LogindLookup::Error;
        }
        current.path = path;
        if (!getSessionRecord(bus.get(), owner, current, diagnostic))
            return LogindLookup::Error;
        return LogindLookup::Found;
    }

    LogindLookup getUser(const LogindUserRecord& expected,
                         LogindUserRecord& current,
                         std::string& diagnostic) override {
        Bus bus(nullptr, sd_bus_unref); std::string owner;
        if (!openBus(bus, owner, expected.owner, diagnostic)) return LogindLookup::Error;
        sd_bus_error error = SD_BUS_ERROR_NULL; sd_bus_message* raw = nullptr;
        const std::uint32_t uid = expected.uid;
        const int result = sd_bus_call_method(bus.get(), owner.c_str(), ManagerPath,
            Manager, "GetUser", &error, &raw, "u", uid);
        Message reply(raw, sd_bus_message_unref);
        if (result < 0) {
            const bool missing = missingError(error);
            diagnostic = "GetUser: " + detail(result, error);
            sd_bus_error_free(&error);
            return missing ? LogindLookup::Missing : LogindLookup::Error;
        }
        sd_bus_error_free(&error);
        const char* path = nullptr;
        if (sd_bus_message_read(reply.get(), "o", &path) < 0 || !path) {
            diagnostic = "GetUser malformed path"; return LogindLookup::Error;
        }
        current.path = path;
        if (!getUserRecord(bus.get(), owner, current, diagnostic))
            return LogindLookup::Error;
        return LogindLookup::Found;
    }

    bool lockSession(const LogindSessionRecord& target,
                     std::string& diagnostic) override {
        return act(target.owner, "LockSession", "s", target.id.c_str(), diagnostic);
    }
    bool terminateSession(const LogindSessionRecord& target,
                          std::string& diagnostic) override {
        return act(target.owner, "TerminateSession", "s", target.id.c_str(), diagnostic);
    }
    bool terminateUser(const LogindUserRecord& target,
                       std::string& diagnostic) override {
        return act(target.owner, "TerminateUser", "u", static_cast<std::uint32_t>(target.uid), diagnostic);
    }
    bool userManagerStopped(uid_t uid, bool& stopped,
                            std::string& diagnostic) override {
        stopped = false;
        Bus bus(nullptr, sd_bus_unref); std::string owner;
        constexpr const char* systemd = "org.freedesktop.systemd1";
        constexpr const char* managerPath = "/org/freedesktop/systemd1";
        if (!openBus(bus, owner, "", diagnostic, systemd)) return false;
        const std::string unit = "user@" + std::to_string(uid) + ".service";
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message* raw = nullptr;
        const int result = sd_bus_call_method(bus.get(), owner.c_str(),
            managerPath, "org.freedesktop.systemd1.Manager", "GetUnit",
            &error, &raw, "s", unit.c_str());
        Message reply(raw, sd_bus_message_unref);
        if (result < 0) {
            const bool absent = error.name &&
                std::strcmp(error.name, "org.freedesktop.systemd1.NoSuchUnit") == 0;
            if (!absent) diagnostic = "GetUnit: " + detail(result, error);
            sd_bus_error_free(&error);
            stopped = absent;
            return absent;
        }
        sd_bus_error_free(&error);
        const char* path = nullptr;
        if (sd_bus_message_read(reply.get(), "o", &path) < 0 || !path) {
            diagnostic = "user manager unit path is malformed";
            return false;
        }
        std::string state;
        if (!getString(bus.get(), owner, path, "org.freedesktop.systemd1.Unit",
                       "ActiveState", state, diagnostic)) return false;
        stopped = state == "inactive";
        if (!stopped) diagnostic = "user manager ActiveState=" + state;
        return true;
    }
private:
    template <typename T>
    bool act(const std::string& expectedOwner, const char* method,
             const char* signature, T target, std::string& diagnostic) {
        Bus bus(nullptr, sd_bus_unref); std::string owner;
        if (!openBus(bus, owner, expectedOwner, diagnostic)) return false;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        const int result = sd_bus_call_method(bus.get(), owner.c_str(), ManagerPath,
            Manager, method, &error, nullptr, signature, target);
        if (result < 0) diagnostic = std::string(method) + ": " + detail(result, error);
        sd_bus_error_free(&error);
        return result >= 0;
    }
};
} // namespace

std::shared_ptr<LogindClient> makeSystemLogindClient() {
    return std::make_shared<SystemLogindClient>();
}

} // namespace fic::session
