// Model A (session-derived containment targets) regression suite.
//
// Covers the required incident lifecycle with the PRODUCTION controller, the
// PRODUCTION durable target store and the PRODUCTION logind backend over a
// fake logind transport:
//   R1  — a failed TerminateUser followed by reconcile keeps the pending
//         target and DEGRADES (never a false ACTIVE);
//   R2  — a HARD->ISOLATE escalation uses the durably saved target even
//         after its login session is gone;
//   R3  — a daemon restart (a NEW controller + NEW backend over the same
//         store) recovers pending obligations;
//   R4  — an unprovable store degrades instead of empty-success;
//   R5  — root/recovery identities are never selected;
//   R6  — a lingering-only runtime without a qualifying login session is
//         never a target;
//   R7  — a service identity WITH a genuine login session is a target;
//   R8  — UID reuse (same UID, different account) is refused and DEGRADES.
#include "incident/IncidentController.h"
#include "incident/IncidentSessionTargetStore.h"
#include "session/LogindSessionContainmentBackend.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

#include <sys/stat.h>
#include <unistd.h>

using fic::incident::IncidentController;
using fic::incident::IncidentResult;
using fic::incident::IncidentSessionTarget;
using fic::incident::IncidentSessionTargetStore;
using fic::incident::IncidentStateStore;
using fic::incident::IncidentResponseMode;
using fic::incident::NullIncidentNetworkBackend;
using fic::session::LogindClient;
using fic::session::LogindSessionContainmentBackend;
using fic::session::LogindSessionRecord;
using fic::session::LogindUserRecord;
using Severity = fic::core::IncidentSeverity;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

namespace {

class FakeLogind final : public LogindClient {
public:
    std::vector<LogindSessionRecord> sessions;
    std::vector<LogindUserRecord> users;
    bool listOk = true;
    bool keepSession = false;
    bool keepUser = false;
    bool acceptTermination = true;
    bool managerStopped = true;
    int terminatedSessions = 0;
    int terminatedUsers = 0;

    bool listSessions(std::vector<LogindSessionRecord>& out,
                      std::string& error) override {
        if (!listOk) { error = "logind unavailable"; return false; }
        out = sessions;
        return true;
    }
    bool listUsers(std::vector<LogindUserRecord>& out,
                   std::string& error) override {
        if (!listOk) { error = "logind unavailable"; return false; }
        out = users;
        return true;
    }
    LogindLookup getSession(const LogindSessionRecord& expected,
                            LogindSessionRecord& out, std::string& error) override {
        if (!listOk) { error = "logind unavailable"; return LogindLookup::Error; }
        const auto it = std::find_if(sessions.begin(), sessions.end(),
            [&](const auto& s) { return s.id == expected.id; });
        if (it == sessions.end()) return LogindLookup::Missing;
        out = *it;
        return LogindLookup::Found;
    }
    LogindLookup getUser(const LogindUserRecord& expected,
                         LogindUserRecord& out, std::string& error) override {
        if (!listOk) { error = "logind unavailable"; return LogindLookup::Error; }
        const auto it = std::find_if(users.begin(), users.end(),
            [&](const auto& u) { return u.uid == expected.uid; });
        if (it == users.end()) return LogindLookup::Missing;
        // A Model A target lookup probes by UID with no pinned owner: the
        // owner recorded at selection time is dead after a logind restart.
        // The empty owner means "fresh lookup"; the CURRENT owner is returned
        // and later verified before any action.
        if (!expected.owner.empty() && it->owner != expected.owner) {
            error = "owner changed";
            return LogindLookup::Error;
        }
        out = *it;
        return LogindLookup::Found;
    }
    bool lockSession(const LogindSessionRecord&, std::string&) override {
        return true;
    }
    bool terminateSession(const LogindSessionRecord& s, std::string&) override {
        ++terminatedSessions;
        if (!acceptTermination) return false;
        if (!keepSession) {
            sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                [&](const auto& c) { return c.id == s.id; }), sessions.end());
        }
        return true;
    }
    bool terminateUser(const LogindUserRecord& u, std::string& error) override {
        ++terminatedUsers;
        if (!acceptTermination) { error = "terminate rejected"; return false; }
        if (!keepUser) {
            users.erase(std::remove_if(users.begin(), users.end(),
                [&](const auto& c) { return c.uid == u.uid; }), users.end());
        }
        return true;
    }
    bool userManagerStopped(uid_t, bool& stopped, std::string&) override {
        stopped = managerStopped;
        return true;
    }
};