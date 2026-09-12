#include "modules/oss/desktop_environment/SessionSettingReconciler.h"
#include "modules/oss/desktop_environment/policies/GnomeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/KdeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/FlyScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/XfceScreenLockTimeoutHandler.h"

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
    mutable int validations = 0;
    bool reloadOk = true;
    bool validationOk = true;

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
    bool validateRuntimeContext(std::string& error) const {
        ++validations;
        error = validationOk ? "" : "owner changed";
        return validationOk;
    }
};

void testDesktopBackendStrictParsers() {
    using desktop_backend::parseStrictDouble;
    using desktop_backend::parseStrictInteger;

    require(parseStrictInteger("5") == 5, "integer parser rejected 5");
    require(parseStrictInteger(" 5 ") == 5,
            "integer parser did not trim whitespace");
    require(parseStrictInteger("-5") == -5,
            "integer parser lost the sign");
    require(parseStrictInteger("+7") == 7,
            "integer parser rejected an explicit plus sign");
    require(parseStrictInteger("0") == 0, "integer parser rejected 0");
    require(parseStrictInteger("-0") == 0,
            "integer parser did not normalize -0 to 0");
    require(!parseStrictInteger("5foo") &&
                !parseStrictInteger("foo5") &&
                !parseStrictInteger("5.0") &&
                !parseStrictInteger("") &&
                !parseStrictInteger("   ") &&
                !parseStrictInteger("2147483648") &&
                !parseStrictInteger("-2147483649"),
            "integer parser accepted a malformed or overflowing value");

    require(parseStrictDouble("5") == 5.0, "double parser rejected 5");
    require(parseStrictDouble("5.0") == 5.0, "double parser rejected 5.0");
    require(parseStrictDouble("5.00") == 5.0, "double parser rejected 5.00");
    require(parseStrictDouble(" 5.0 ") == 5.0,
            "double parser did not trim whitespace");
    require(parseStrictDouble("-5") == -5.0, "double parser lost the sign");
    require(parseStrictDouble("5.5") == 5.5, "double parser rejected 5.5");
    require(!parseStrictDouble("5foo") &&
                !parseStrictDouble("foo5") &&
                !parseStrictDouble("NaN") &&
                !parseStrictDouble("nan") &&
                !parseStrictDouble("Inf") &&
                !parseStrictDouble("-Inf") &&
                !parseStrictDouble("infinity") &&
                !parseStrictDouble("") &&
                !parseStrictDouble("   "),
            "double parser accepted a malformed or non-finite value");
    require(!parseStrictDouble("1e999") && !parseStrictDouble("-1e999"),
            "double parser accepted an overflowing literal");
}

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
        require(session.events == expected && session.validations == 1,
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
        require(session.events == expected && session.reloads == 1 &&
                    session.validations == 1,
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
        require(session.events == expected && session.validations == 0 &&
                    error == "failed to reload KDE screen lock settings: "
                             "D-Bus unavailable",
                "KDE configure failure ordering or diagnostic is wrong");
    }
    {
        FakeKdeSession session;
        session.values["Lock"] = "true";
        session.validationOk = false;
        std::string error;
        require(!kde_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    session.validations == 1 &&
                    error == "KDE screen locker changed during reconciliation: "
                             "owner changed",
                "KDE final owner change was accepted");
    }

    // Regression: отрицательный Timeout=-5 при policy 5 больше не считается
    // совпадающим состоянием — состояние обязано быть сконвергировано.
    {
        FakeKdeSession session;
        session.values["Timeout"] = "-5";
        session.values["Lock"] = "true";
        std::string error;
        require(kde_screen_lock_timeout::applyTimeout(session, 5, error), error);
        require(std::find(session.writes.begin(), session.writes.end(),
                          "Timeout=5") != session.writes.end(),
                "KDE Timeout=-5 was accepted for policy 5 without repair");
        require(session.values["Timeout"] == "5",
                "KDE Timeout=-5 was not converged to the policy value");
    }

    // Эквивалентные написания Timeout считаются совпадением без записей.
    for (const char* encoded : {"5", "5.0", "5.00", " 5.0 "}) {
        FakeKdeSession session;
        session.values["Timeout"] = encoded;
        session.values["Lock"] = "true";
        std::string error;
        require(kde_screen_lock_timeout::applyTimeout(session, 5, error), error);
        require(session.writes.empty(),
                "KDE equivalent Timeout spelling triggered a rewrite");
    }

    // Malformed / не равные policy значения Timeout дают mismatch и чинятся.
    for (const char* encoded :
         {"-5", "5.5", "5foo", "foo5", "NaN", "Inf", "-Inf", ""}) {
        FakeKdeSession session;
        session.values["Timeout"] = encoded;
        session.values["Lock"] = "true";
        std::string error;
        require(kde_screen_lock_timeout::applyTimeout(session, 5, error), error);
        require(std::find(session.writes.begin(), session.writes.end(),
                          "Timeout=5") != session.writes.end(),
                "KDE malformed Timeout was accepted without repair");
        require(session.values["Timeout"] == "5",
                "KDE malformed Timeout was not converged");
    }

    // LockGrace: "-0" эквивалентен 0, malformed значения чинятся.
    {
        FakeKdeSession session;
        session.values["Lock"] = "true";
        session.values["LockGrace"] = "-0";
        std::string error;
        require(kde_screen_lock_timeout::applyTimeout(session, 5, error), error);
        require(session.writes.empty(),
                "KDE LockGrace=-0 was not accepted as 0");
    }
    for (const char* encoded : {"0foo", "foo0", "0.0"}) {
        FakeKdeSession session;
        session.values["LockGrace"] = encoded;
        std::string error;
        require(kde_screen_lock_timeout::applyTimeout(session, 5, error), error);
        require(std::find(session.writes.begin(), session.writes.end(),
                          "LockGrace=0") != session.writes.end(),
                "KDE malformed LockGrace was accepted without repair");
        require(session.values["LockGrace"] == "0",
                "KDE malformed LockGrace was not converged");
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

// Fake бэкенд с интерфейсом XfceBackend: эмулирует три состояния каждого
// Xfconf property — Present(type,value), Absent и ReadError — без живой
// XFCE сессии.
struct FakeXfceSession {
    // The fake models explicit presence + storage type + value: absence and
    // read failures are distinct states, type identity is part of compliance.
    mutable std::map<std::string, XfcePropertyState> values;
    mutable std::vector<std::string> events;
    mutable std::size_t liveChecks = 0;
    std::vector<bool> live = {true, true};
    std::string failRead;
    bool failEveryRead = false; // simulates daemon/session bus unavailable
    std::string failWrite;
    bool ignoreWrites = false;
    // Simulates a race: the typed write reports success, but the final
    // readback sees a wrong storage type instead of the requested one.
    bool raceWrongTypeAfterWrite = false;

    FakeXfceSession() {
        for (const auto& property :
             xfce_screen_lock_timeout::requiredProperties(5))
            values[property.path] =
                present(xfcePropertyTypeFromToken(property.type),
                        property.value);
    }

    static XfcePropertyState present(XfcePropertyType type,
                                     std::string value) {
        return {XfcePropertyStateKind::Present, type, std::move(value)};
    }
    static XfcePropertyState absent() {
        return {XfcePropertyStateKind::Absent, XfcePropertyType::Other, ""};
    }
    // Fresh XFCE profile: none of the managed properties is materialized.
    void makeAllAbsent() {
        for (auto& entry : values) entry.second = absent();
    }

    bool screenSaverAvailable(std::string& error) const {
        events.push_back("live");
        const bool available = liveChecks < live.size() && live[liveChecks++];
        error = available ? "" : "xfce4-screensaver is not running";
        return available;
    }
    bool getPropertyState(const std::string& channel,
                          const std::string& property,
                          XfcePropertyState& state, std::string& error) const {
        require(channel == "xfce4-screensaver", "wrong XFCE channel");
        events.push_back("read:" + property);
        const auto found = values.find(property);
        if (failEveryRead || property == failRead || found == values.end()) {
            error = "read failed";
            return false;
        }
        state = found->second;
        error.clear();
        return true;
    }
    bool setProperty(const std::string& channel, const std::string& property,
                     const std::string& type, const std::string& value,
                     std::string& error) const {
        require(channel == "xfce4-screensaver", "wrong XFCE channel");
        events.push_back("write:" + property + ":" + type + "=" + value);
        if (property == failWrite) {
            error = "write failed";
            return false;
        }
        if (!ignoreWrites) {
            // The production writer is a typed mutation (`--create --type`):
            // the stored type always converges to the requested type.
            values[property] =
                raceWrongTypeAfterWrite
                    ? present(XfcePropertyType::String, value)
                    : present(xfcePropertyTypeFromToken(type), value);
        }
        error.clear();
        return true;
    }

    static XfcePropertyType xfcePropertyTypeFromToken(const std::string& type) {
        if (type == "bool") return XfcePropertyType::Bool;
        if (type == "int") return XfcePropertyType::Int;
        if (type == "uint") return XfcePropertyType::UInt;
        if (type == "double") return XfcePropertyType::Double;
        if (type == "string") return XfcePropertyType::String;
        return XfcePropertyType::Other;
    }
};

XfcePropertyState presentState(XfcePropertyType type, std::string value) {
    return FakeXfceSession::present(type, std::move(value));
}

std::vector<std::string> xfceReads() {
    std::vector<std::string> result;
    for (const auto& property :
         xfce_screen_lock_timeout::requiredProperties(5))
        result.push_back("read:" + std::string(property.path));
    return result;
}

void testXfceScreenLockConvergence() {
    require(desktop_backend::parseStrictInteger(" -5 ") == -5,
            "XFCE integer parser lost the sign or rejected whitespace");
    require(desktop_backend::parseStrictInteger("5") == 5,
            "XFCE integer parser rejected a valid value");
    require(!desktop_backend::parseStrictInteger("5foo") &&
                !desktop_backend::parseStrictInteger("foo5") &&
                !desktop_backend::parseStrictInteger(""),
            "XFCE integer parser accepted a malformed value");

    {
        FakeXfceSession session;
        session.live = {false};
        std::string error;
        require(!xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    session.events == std::vector<std::string>{"live"},
                "missing XFCE locker allowed state access or success");
    }
    {
        FakeXfceSession session;
        session.live = {true, false};
        session.values["/saver/fullscreen-inhibit"] =
            presentState(XfcePropertyType::Bool, "true");
        std::string error;
        require(!xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    session.events.back() == "live" &&
                    session.liveChecks == 2 &&
                    std::find(session.events.begin(), session.events.end(),
                        "write:/saver/fullscreen-inhibit:bool=false") !=
                        session.events.end(),
                "disappeared XFCE locker was not detected");
    }
    {
        FakeXfceSession session;
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        auto expected = std::vector<std::string>{"live"};
        const auto reads = xfceReads();
        expected.insert(expected.end(), reads.begin(), reads.end());
        expected.push_back("live");
        require(session.events == expected,
                "correct XFCE state did not use live/read/live flow");
    }
    {
        FakeXfceSession session;
        session.values["/saver/fullscreen-inhibit"] =
            presentState(XfcePropertyType::Bool, "true");
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(session.values["/saver/fullscreen-inhibit"].value == "false" &&
                    session.values["/saver/fullscreen-inhibit"].type ==
                        XfcePropertyType::Bool &&
                    std::find(session.events.begin(), session.events.end(),
                        "write:/saver/fullscreen-inhibit:bool=false") !=
                        session.events.end(),
                "XFCE fullscreen inhibit was not disabled");
    }
    {
        FakeXfceSession session;
        session.values["/saver/idle-activation/delay"] =
            presentState(XfcePropertyType::Int, "1");
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    session.values["/saver/idle-activation/delay"].value ==
                        "5",
                "XFCE timeout did not converge");
    }
    {
        FakeXfceSession session;
        session.values["/saver/idle-activation/delay"] =
            presentState(XfcePropertyType::Int, "-5");
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    session.values["/saver/idle-activation/delay"].value ==
                        "5" &&
                    std::find(session.events.begin(), session.events.end(),
                        "write:/saver/idle-activation/delay:int=5") !=
                        session.events.end(),
                "negative XFCE idle delay was accepted as matching");
    }
    for (const std::string malformed : {"5foo", "foo5"}) {
        FakeXfceSession session;
        session.values["/saver/idle-activation/delay"] =
            presentState(XfcePropertyType::Int, malformed);
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    session.values["/saver/idle-activation/delay"].value ==
                        "5",
                "malformed XFCE idle delay was accepted as matching");
    }
    for (const std::string malformed : {"0foo", "foo0"}) {
        FakeXfceSession session;
        session.values["/lock/saver-activation/delay"] =
            presentState(XfcePropertyType::Int, malformed);
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    session.values["/lock/saver-activation/delay"].value ==
                        "0",
                "malformed XFCE lock delay was accepted as matching");
    }
    // Главный regression подтверждённого bug: textually equal, но wrong
    // storage type (string "5" vs int 5) обязан вызвать typed repair.
    {
        FakeXfceSession session;
        session.values["/saver/idle-activation/delay"] =
            presentState(XfcePropertyType::String, "5");
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(std::find(session.events.begin(), session.events.end(),
                          "write:/saver/idle-activation/delay:int=5") !=
                    session.events.end(),
                "wrong-type XFCE delay was not repaired with a typed write");
        require(session.values["/saver/idle-activation/delay"].type ==
                        XfcePropertyType::Int &&
                    session.values["/saver/idle-activation/delay"].value ==
                        "5",
                "wrong-type XFCE delay did not converge to int 5");
    }
    {
        FakeXfceSession session;
        session.values["/saver/enabled"] = presentState(XfcePropertyType::String, "true");
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(std::find(session.events.begin(), session.events.end(),
                          "write:/saver/enabled:bool=true") !=
                    session.events.end(),
                "wrong-type XFCE boolean was not repaired with a typed write");
        require(session.values["/saver/enabled"].type ==
                    XfcePropertyType::Bool,
                "wrong-type XFCE boolean did not converge to bool");
    }
    {
        // fullscreen-inhibit: string("false") vs bool false. Особенно важен
        // из-за default drift в XFCE 4.20 (default=true при required=false).
        FakeXfceSession session;
        session.values["/saver/fullscreen-inhibit"] =
            presentState(XfcePropertyType::String, "false");
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(std::find(session.events.begin(), session.events.end(),
                          "write:/saver/fullscreen-inhibit:bool=false") !=
                    session.events.end(),
                "wrong-type XFCE fullscreen inhibit was not repaired");
        require(session.values["/saver/fullscreen-inhibit"].type ==
                    XfcePropertyType::Bool,
                "wrong-type XFCE fullscreen inhibit did not converge");
    }
    {
        FakeXfceSession session;
        session.values["/saver/idle-activation/delay"] =
            presentState(XfcePropertyType::UInt, "5");
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(session.values["/saver/idle-activation/delay"].type ==
                    XfcePropertyType::Int,
                "uint XFCE delay was accepted as int 5");
    }
    {
        FakeXfceSession session;
        session.values["/saver/idle-activation/delay"] =
            presentState(XfcePropertyType::Double, "5.000000");
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(session.values["/saver/idle-activation/delay"].type ==
                    XfcePropertyType::Int,
                "double XFCE delay was accepted as int 5");
    }
    {
        // Typed write заявляет успех, но final typed readback всё ещё видит
        // wrong type: reconciliation обязана fail closed.
        FakeXfceSession session;
        session.values["/saver/idle-activation/delay"] =
            presentState(XfcePropertyType::String, "5");
        session.ignoreWrites = true;
        std::string error;
        require(!xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    error == "XFCE screen lock settings did not reach the "
                             "requested state",
                "wrong-type XFCE delay was accepted after failed repair");
    }
    {
        FakeXfceSession session;
        session.failRead = "/saver/fullscreen-inhibit";
        std::string error;
        require(!xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    std::none_of(session.events.begin(), session.events.end(),
                        [](const std::string& event) {
                            return event.rfind("write:", 0) == 0;
                        }),
                "XFCE read failure attempted a blind write");
    }
    {
        FakeXfceSession session;
        session.values["/saver/fullscreen-inhibit"] =
            presentState(XfcePropertyType::Bool, "true");
        session.failWrite = "/saver/fullscreen-inhibit";
        std::string error;
        require(!xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    error == "write failed",
                "XFCE property write failure was hidden");
    }
    {
        FakeXfceSession session;
        session.values["/saver/fullscreen-inhibit"] =
            presentState(XfcePropertyType::Bool, "true");
        session.ignoreWrites = true;
        std::string error;
        require(!xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    error == "XFCE screen lock settings did not reach the requested state",
                "XFCE final readback mismatch was accepted");
    }

    // Regression A: fresh profile, absent idle delay. Absence — штатное
    // состояние Xfconf, а не read failure: она обязана стать mismatch и
    // materialизоваться typed writer'ом, а не провалить reconciliation.
    {
        FakeXfceSession session;
        session.values["/saver/idle-activation/delay"] =
            FakeXfceSession::absent();
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 1, error),
                error);
        require(std::find(session.events.begin(), session.events.end(),
                          "write:/saver/idle-activation/delay:int=1") !=
                    session.events.end(),
                "absent XFCE idle delay was not materialized with a typed "
                "create");
        require(session.values["/saver/idle-activation/delay"].kind ==
                        XfcePropertyStateKind::Present &&
                    session.values["/saver/idle-activation/delay"].type ==
                        XfcePropertyType::Int &&
                    session.values["/saver/idle-activation/delay"].value ==
                        "1",
                "absent XFCE idle delay did not converge to explicit int 1");
    }
    // Regression B: absent fullscreen-inhibit обязан быть создан как
    // bool false (explicit-state model, без опоры на upstream defaults).
    {
        FakeXfceSession session;
        session.values["/saver/fullscreen-inhibit"] =
            FakeXfceSession::absent();
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        require(std::find(session.events.begin(), session.events.end(),
                          "write:/saver/fullscreen-inhibit:bool=false") !=
                    session.events.end(),
                "absent XFCE fullscreen inhibit was not materialized");
        require(session.values["/saver/fullscreen-inhibit"].kind ==
                        XfcePropertyStateKind::Present &&
                    session.values["/saver/fullscreen-inhibit"].type ==
                        XfcePropertyType::Bool &&
                    session.values["/saver/fullscreen-inhibit"].value ==
                        "false",
                "absent XFCE fullscreen inhibit did not converge to bool "
                "false");
    }
    // Regression C: fresh profile со всеми семью отсутствующими свойствами.
    // Typed writer обязан materialизовать все семь, final readback — exact.
    {
        FakeXfceSession session;
        session.makeAllAbsent();
        std::string error;
        require(xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                error);
        for (const auto& property :
             xfce_screen_lock_timeout::requiredProperties(5)) {
            const std::string writeEvent = std::string("write:") +
                property.path + ":" + property.type + "=" + property.value;
            require(std::find(session.events.begin(), session.events.end(),
                              writeEvent) != session.events.end(),
                    "fresh XFCE profile: " + writeEvent + " was not written");
            const XfcePropertyState& finalState =
                session.values[property.path];
            require(finalState.kind == XfcePropertyStateKind::Present &&
                        xfcePropertyTypeName(finalState.type) ==
                            std::string(property.type) &&
                        finalState.value == property.value,
                    "fresh XFCE profile did not materialize " +
                        std::string(property.path));
        }
    }
    // Regression D (present exact → zero writes) уже покрыт выше: события
    // ровно live + 7 reads + live без единого write.
    // Regression F/G: real read failure / недоступный daemon — policy failure
    // и zero writes. Никакой read error не превращается в Absent и не пишет.
    {
        FakeXfceSession session;
        session.failEveryRead = true; // daemon/session bus unavailable
        std::string error;
        require(!xfce_screen_lock_timeout::applyTimeout(session, 5, error),
                "unavailable XFCE session bus was accepted as success");
        require(std::none_of(session.events.begin(), session.events.end(),
                             [](const std::string& event) {
                                 return event.rfind("write:", 0) == 0;
                             }),
                "unavailable XFCE session bus attempted a blind write");
    }
    // Regression H: initial Absent, writer отчитался успехом, но final
    // readback всё ещё видит Absent — fail closed.
    {
        FakeXfceSession session;
        session.makeAllAbsent();
        session.ignoreWrites = true;
        std::string error;
        require(!xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    error == "XFCE screen lock settings did not reach the "
                             "requested state",
                "absent XFCE state was accepted without materialization");
    }
    // Regression H2: initial Absent, writer успех, но final readback видит
    // wrong storage type — race closure обязана провалить операцию.
    {
        FakeXfceSession session;
        session.makeAllAbsent();
        session.raceWrongTypeAfterWrite = true;
        std::string error;
        require(!xfce_screen_lock_timeout::applyTimeout(session, 5, error) &&
                    error == "XFCE screen lock settings did not reach the "
                             "requested state",
                "XFCE state race after absent was accepted as success");
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

    testDesktopBackendStrictParsers();
    testGnomeSessionConvergence();
    testKdeLockConvergence();
    testFlyRuntimeOnlyConvergence();
    testXfceScreenLockConvergence();
    return 0;
}
