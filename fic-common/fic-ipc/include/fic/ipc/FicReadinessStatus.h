#pragma once
#include <fic/ipc/FicIpcClient.h>
#include <string>

namespace fic::ipc {
// Read-only wire contract shared by the daemon producers and strict clients.
// Tokens deliberately do not depend on executable-private incident headers.
struct AccessGateStatus {
    std::string state = "INITIALIZING", mode = "ACTIVE", severity = "ISOLATE";
    bool modeProven = false, stateProven = false;
    std::string provenance = "BROKEN";
    bool loginAllowed = false;
};
struct PreLoginStatus {
    AccessGateStatus access;
    bool started = false, completed = false, applyOk = false, lifecycleCompleted = false;
    std::string diagnostic, bootId;
    int daemonPid = 0;
};
bool computedLoginAllowed(const AccessGateStatus& status);
json serializeAccessGateStatus(const AccessGateStatus& status);
json serializePreLoginStatus(const PreLoginStatus& status);
bool parseAccessGateStatus(const json& value, AccessGateStatus& status, std::string& error);
bool parsePreLoginStatus(const json& value, PreLoginStatus& status, std::string& error);
bool validBootId(const std::string& value);
bool mayAutoHandoff(const PreLoginStatus& status, const std::string& currentBootId);
}
