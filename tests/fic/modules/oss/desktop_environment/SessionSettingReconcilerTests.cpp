#include "modules/oss/desktop_environment/SessionSettingReconciler.h"
#include "modules/oss/desktop_environment/policies/GnomeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/KdeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/FlyScreenLockTimeoutHandler.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void require(bool value, const std::string& message) {
    require(value, message.c_str());
}

// Fake бэкенд с интерфейсом GnomeBackend: эмулирует gsettings-состояние
// текущей сессии без живой GNOME сессии.
struct FakeGnomeSession {
    mutable std::map<std::string, std::string> values;
    mutable std::vector<std::string> sets;

    bool getSetting(const std::string& schema, const std::string& key,
                    std::string& value, std::string& error) const {
        const auto found = values.find(schema + " " + key);
        if (found == values.end()) {
            error = "no value for " + schema + " " + key;
            return false;
        }
        value = found->second;
        error.clear();
        return true;
    }

    bool getUInt32Setting(const std::string& schema, const std::string& key,
                          std::uint32_t& value, std::string& error) const {
        std::string encoded;
        if (!getSetting(schema, key, encoded, error)) return false;
        if (encoded.rfind("uint32 ", 0) != 0) {
            error = "not uint32: " + encoded;
            return false;
        }
        value = static_cast<std::uint32_t>(std::stoul(encoded.substr(7)));
        error.clear();
        return true;
    }

    bool setSetting(const std::string& schema, const std::string& key,
                    const std::string& value, std::string& error) const {
        sets.push_back(schema + " " + key + " " + value);
        values[schema + " " + key] = value;
        error.clear();
        return true;
    }
};

FakeGnomeSession correctSession() {
    FakeGnomeSession session;
    session.values["org.gnome.desktop.session idle-delay"] = "uint32 300";
    session.values["org.gnome.desktop.screensaver lock-enabled"] = "true";
    session.values["org.gnome.desktop.screensaver lock-delay"] = "uint32 0";
    session.values["org.gnome.desktop.lockdown disable-lock-screen"] = "false";
    return session;
}

void testGnomeSessionConvergence() {
    {
        // disable-lock-screen=true ломает state matching даже при корректных
        // остальных трёх настройках: convergence обязан выполнить set false.
        FakeGnomeSession session = correctSession();
        session.values["org.gnome.desktop.lockdown disable-lock-screen"] =
            "true";
        std::string error;
        require(gnome_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(std::find(session.sets.begin(), session.sets.end(),
                          "org.gnome.desktop.lockdown disable-lock-screen "
                          "false") != session.sets.end(),
                "handler did not write disable-lock-screen=false");
        require(session.values[
                    "org.gnome.desktop.lockdown disable-lock-screen"] ==
                    "false",
                "readback did not observe disable-lock-screen=false");
    }
    {
        // Полностью корректное состояние не требует ненужных записей
        // (read-before-write semantics).
        FakeGnomeSession session = correctSession();
        std::string error;
        require(gnome_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(session.sets.empty(),
                "already-correct session state was rewritten");
    }
    {
        // Неверный timeout тоже ломает matching и конвергируется.
        FakeGnomeSession session = correctSession();
        session.values["org.gnome.desktop.session idle-delay"] = "uint32 1";
        std::string error;
        require(gnome_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(session.values["org.gnome.desktop.session idle-delay"] ==
                    "uint32 300",
                "idle-delay was not converged");
    }
}

struct FakeKdeSession {
    mutable std::map<std::string, std::string> values = {
        {"Autolock", "true"},
        {"Timeout", "5"},
        {"Lock", "false"},
        {"LockGrace", "0"},
        {"RequirePassword", "true"},
    };
    mutable std::vector<std::string> writes;
    mutable std::vector<std::string> events;
    mutable int reloads = 0;
    bool reloadOk = true;

    bool readConfig(const std::string&, const std::string&,
                    const std::string& key, std::string& value,
                    std::string& error) const {
        events.push_back("read:" + key);
        value = values.at(key);
        error.clear();
        return true;
    }
    bool writeConfig(const std::string&, const std::string&,
                     const std::string& key, const std::string& value,
                     std::string& error) const {
        events.push_back("write:" + key);
        writes.push_back(key + "=" + value);
        values[key] = value;
        error.clear();
        return true;
    }
    bool callDbusMethod(const std::string& service, const std::string& path,
                        const std::string& interface,
                        const std::string& method,
                        std::string& error) const {
        require(service == "org.kde.screensaver" && path == "/ScreenSaver" &&
                    interface == "org.kde.screensaver" &&
                    method == "configure",
                "KDE handler used the wrong D-Bus configure call");
        events.push_back("configure");
        ++reloads;
        error = reloadOk ? "" : "D-Bus unavailable";
        return reloadOk;
    }
};

void testKdeLockConvergence() {
    const std::vector<std::string> reads = {
        "read:Autolock", "read:Timeout", "read:Lock",
        "read:LockGrace", "read:RequirePassword"};
    {
        FakeKdeSession session;
        std::string error;
        require(kde_screen_lock_timeout::applyTimeout(session, 5, error), error);
        require(std::find(session.writes.begin(), session.writes.end(),
                          "Lock=true") != session.writes.end(),
                "KDE handler did not repair Lock=false");
        require(session.values["Lock"] == "true",
                "KDE final readback did not observe Lock=true");
        std::vector<std::string> expected = reads;
        expected.insert(expected.end(), {
            "write:Autolock", "write:Timeout", "write:Lock",
            "write:LockGrace", "write:RequirePassword", "configure"});
        expected.insert(expected.end(), reads.begin(), reads.end());
        require(session.events == expected,
                "KDE write/configure/readback ordering is wrong");
    }
    {
        FakeKdeSession session;
        session.values["Lock"] = "true";
        std::string error;
        require(kde_screen_lock_timeout::applyTimeout(session, 5, error), error);
        require(session.writes.empty(),
                "already-correct KDE session state was rewritten");
        std::vector<std::string> expected = reads;
        expected.push_back("configure");
        expected.insert(expected.end(), reads.begin(), reads.end());
        require(session.events == expected && session.reloads == 1,
                "already-correct KDE state skipped configure or final readback");
    }
    {
        FakeKdeSession session;
        session.values["Lock"] = "true";
        session.reloadOk = false;
        std::string error;
        require(!kde_screen_lock_timeout::applyTimeout(session, 5, error),
                "KDE configure failure was ignored");
        std::vector<std::string> expected = reads;
        expected.push_back("configure");
        require(session.events == expected &&
                    error == "failed to reload KDE screen lock settings: "
                             "D-Bus unavailable",
                "KDE configure failure ordering or diagnostic is wrong");
    }
}

struct FakeFlySession {
    mutable std::vector<std::string> calls;
    int failAt = 0;

    bool setValue(const std::string& key, const std::string& value,
                  std::string& error) const {
        calls.push_back(key + "=" + value);
        if (failAt != 0 && static_cast<int>(calls.size()) == failAt) {
            error = "runtime update failed";
            return false;
        }
        error.clear();
        return true;
    }
};

void testFlyRuntimeOnlyConvergence() {
    {
        FakeFlySession session;
        std::string error;
        require(fly_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(session.calls == std::vector<std::string>{
                    "ScreenSaverDelay=300"},
                "FLY runtime calls or minutes-to-seconds conversion are wrong");
    }
    {
        FakeFlySession session;
        session.failAt = 1;
        std::string error;
        require(!fly_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    error == "runtime update failed" &&
                    session.calls == std::vector<std::string>{
                        "ScreenSaverDelay=300"},
                "FLY runtime failure was hidden or execution continued");
    }
}
}

int main() {
    std::string error;
    std::vector<std::string> calls;

    require(desktop_policy::reconcileEffectiveSetting(
                [&](bool& matches, std::string&) {
                    calls.push_back("read"); matches = true; return true;
                },
                [&](std::string&) {
                    calls.push_back("write"); return false;
                }, "mismatch", error),
            "already compliant state failed");
    require(calls == std::vector<std::string>{"read"},
            "already compliant state attempted mutation");

    calls.clear();
    require(!desktop_policy::reconcileEffectiveSetting(
                [&](bool&, std::string& value) {
                    calls.push_back("read"); value = "read failed"; return false;
                },
                [&](std::string&) { calls.push_back("write"); return true; },
                "mismatch", error),
            "unreadable state attempted blind convergence");
    require(calls == std::vector<std::string>{"read"},
            "read failure attempted mutation");

    calls.clear();
    int reads = 0;
    require(desktop_policy::reconcileEffectiveSetting(
                [&](bool& matches, std::string&) {
                    calls.push_back("read"); matches = ++reads == 2; return true;
                },
                [&](std::string&) { calls.push_back("write"); return true; },
                "mismatch", error),
            "wrong state did not converge");
    require(calls == std::vector<std::string>{"read", "write", "read"},
            "write/readback ordering is wrong");

    calls.clear();
    require(!desktop_policy::reconcileEffectiveSetting(
                [&](bool& matches, std::string&) {
                    calls.push_back("read"); matches = false; return true;
                },
                [&](std::string&) { calls.push_back("write"); return true; },
                "readback mismatch", error),
            "readback mismatch succeeded");
    require(error == "readback mismatch", "mismatch diagnostic was lost");

    testGnomeSessionConvergence();
    testKdeLockConvergence();
    testFlyRuntimeOnlyConvergence();
    return 0;
}
