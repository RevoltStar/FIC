#include "PreLoginSystemdIntegration.h"
#include <systemd/sd-bus.h>
#include <cstdlib>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <memory>
#include <utility>

namespace fic::prelogin {
namespace {
struct Bus {
    sd_bus* value = nullptr;
    int opened = 0, timeout = 0;
    explicit Bus(const PreLoginSystemdIntegration::OpenBus& open = {}) {
        opened = open ? open(&value) : sd_bus_open_system(&value);
        if (opened >= 0) timeout = value ? sd_bus_set_method_call_timeout(value, 250000) : -EBADMSG;
    }
    ~Bus() { sd_bus_unref(value); }
};
struct BusError {
    sd_bus_error value = SD_BUS_ERROR_NULL;
    ~BusError() { sd_bus_error_free(&value); }
};
std::string boundedText(const char* text, std::size_t limit) {
    if (!text) return {};
    auto length = ::strnlen(text, limit);
    // sd-bus strings are UTF-8. Do not split a code point at the byte bound:
    // the diagnostic later travels in the broker's JSON rendering packet.
    if (length == limit)
        while (length && (static_cast<unsigned char>(text[length]) & 0xc0) == 0x80) --length;
    return std::string(text, length);
}
std::string diagnostic(const char* operation, const char* property, int code,
                       const sd_bus_error* error = nullptr) {
    std::string result = std::string("systemd D-Bus operation=") + operation;
    if (property) result += std::string(" property=") + property;
    result += " code=" + std::to_string(code) + ": " +
        (code < 0 ? boundedText(std::strerror(-code), 128) : "invalid reply");
    if (error) {
        if (error->name) result += "; " + boundedText(error->name, 128);
        if (error->message) result += ": " + boundedText(error->message, 512);
    }
    if (result.size() > 1024) result.resize(1024);
    for (char& c : result) if (static_cast<unsigned char>(c) < 32 || c == 127) c = ' ';
    return result;
}
bool text(sd_bus* bus, const char* path, const char* interface, const char* name,
          std::string& output, std::string& error) {
    char* value = nullptr;
    BusError busError;
    const int result = sd_bus_get_property_string(bus, "org.freedesktop.systemd1", path,
        interface, name, &busError.value, &value);
    const bool ok = result >= 0 && value;
    if (ok) output = boundedText(value, 512);
    else error = diagnostic("get_property", name, result < 0 ? result : -EBADMSG, &busError.value);
    std::free(value);
    return ok;
}
}
PreLoginSystemdIntegration::PreLoginSystemdIntegration(OpenBus openBus)
    : openBus_(std::move(openBus)) {}
SystemdStatus PreLoginSystemdIntegration::observe() const {
    SystemdStatus result;
    Bus bus(openBus_);
    if (bus.opened < 0) { result.error = diagnostic("sd_bus_open_system", nullptr, bus.opened); return result; }
    if (bus.timeout < 0) { result.error = diagnostic("set_method_call_timeout", nullptr, bus.timeout); return result; }
    BusError busError;
    sd_bus_message* rawReply = nullptr;
    const int called = sd_bus_call_method(bus.value, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "GetUnit", &busError.value, &rawReply, "s", "fic.service");
    std::unique_ptr<sd_bus_message, decltype(&sd_bus_message_unref)> reply(rawReply, sd_bus_message_unref);
    if (called < 0) { result.error = diagnostic("GetUnit", nullptr, called, &busError.value); return result; }
    const char* path = nullptr;
    const int read = sd_bus_message_read(reply.get(), "o", &path);
    if (read <= 0 || !path) { result.error = diagnostic("GetUnit.read", nullptr, read); return result; }
    // Publish only a complete observation. Partial properties must not become
    // current status when a later call fails; the next poll starts afresh.
    std::string active, sub, statusText;
    if (!text(bus.value, path, "org.freedesktop.systemd1.Unit", "ActiveState", active, result.error) ||
        !text(bus.value, path, "org.freedesktop.systemd1.Unit", "SubState", sub, result.error) ||
        !text(bus.value, path, "org.freedesktop.systemd1.Service", "StatusText", statusText, result.error)) return result;
    unsigned int pid = 0;
    const int pidRead = sd_bus_get_property_trivial(bus.value, "org.freedesktop.systemd1", path,
        "org.freedesktop.systemd1.Service", "MainPID", &busError.value, 'u', &pid);
    if (pidRead < 0) { result.error = diagnostic("get_property", "MainPID", pidRead, &busError.value); return result; }
    result.available = true;
    result.active = std::move(active); result.sub = std::move(sub); result.text = std::move(statusText); result.pid = pid;
    return result;
}
bool PreLoginSystemdIntegration::proveBrokerOnly(std::string& error) {
    Bus bus;
    if (!bus.value) { error = "cannot prove graphics cgroup without systemd"; return false; }
    sd_bus_message* reply = nullptr;
    const int called = sd_bus_call_method(bus.value, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "GetUnitProcesses", nullptr, &reply, "s", "fic-prelogin.service");
    bool onlyBroker = called >= 0 && sd_bus_message_enter_container(reply, 'a', "(sus)") > 0;
    unsigned int count = 0, pid = 0;
    const char *group = nullptr, *command = nullptr;
    if (onlyBroker) {
        int read = 0;
        while ((read = sd_bus_message_read(reply, "(sus)", &group, &pid, &command)) > 0) {
            if (++count > 1 || pid != static_cast<unsigned int>(::getpid())) { onlyBroker = false; break; }
        }
        onlyBroker = onlyBroker && read >= 0 && count == 1;
    }
    sd_bus_message_unref(reply);
    if (!onlyBroker) error = "prelogin cgroup still contains another process or could not be proven";
    return onlyBroker;
}
bool PreLoginPowerController::execute(Action action, std::string& error) {
    const char* method = action == Action::Reboot ? "Reboot" : action == Action::PowerOff ? "PowerOff" : nullptr;
    if (!method) { error = "unsupported local power action"; return false; }
    Bus bus;
    if (!bus.value || sd_bus_call_method(bus.value, "org.freedesktop.login1", "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager", method, nullptr, nullptr, "b", 0) < 0) {
        error = "system logind rejected local power action"; return false;
    }
    return true;
}
}
