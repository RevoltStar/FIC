#include "PreLoginSystemdIntegration.h"
#include <systemd/sd-bus.h>
#include <cstdlib>
#include <algorithm>
#include <unistd.h>

namespace fic::prelogin {
namespace {
struct Bus {
    sd_bus* value = nullptr;
    Bus() { if (sd_bus_open_system(&value) >= 0) sd_bus_set_method_call_timeout(value, 250000); }
    ~Bus() { sd_bus_unref(value); }
};
bool text(sd_bus* bus, const char* path, const char* interface, const char* name, std::string& output) {
    char* value = nullptr;
    const int result = sd_bus_get_property_string(bus, "org.freedesktop.systemd1", path,
        interface, name, nullptr, &value);
    if (result >= 0 && value) output.assign(value, std::min<std::size_t>(std::char_traits<char>::length(value), 512));
    std::free(value); return result >= 0;
}
}
SystemdStatus PreLoginSystemdIntegration::observe() const {
    SystemdStatus result;
    Bus bus;
    if (!bus.value) return result;
    sd_bus_message* reply = nullptr;
    if (sd_bus_call_method(bus.value, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "GetUnit", nullptr, &reply, "s", "fic.service") < 0) return result;
    const char* path = nullptr;
    const int read = sd_bus_message_read(reply, "o", &path);
    if (read > 0) {
        result.available = text(bus.value, path, "org.freedesktop.systemd1.Unit", "ActiveState", result.active) &&
            text(bus.value, path, "org.freedesktop.systemd1.Unit", "SubState", result.sub) &&
            text(bus.value, path, "org.freedesktop.systemd1.Service", "StatusText", result.text) &&
            sd_bus_get_property_trivial(bus.value, "org.freedesktop.systemd1", path,
                "org.freedesktop.systemd1.Service", "MainPID", nullptr, 'u', &result.pid) >= 0;
    }
    sd_bus_message_unref(reply);
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
