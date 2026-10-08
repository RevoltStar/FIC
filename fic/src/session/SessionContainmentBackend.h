#ifndef FIC_SESSION_SESSION_CONTAINMENT_BACKEND_H
#define FIC_SESSION_SESSION_CONTAINMENT_BACKEND_H

#include <fic/core/incident/IncidentSeverity.h>

#include "session/UserSession.h"

#include <memory>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace fic::session {

// How a login session presents itself to the containment decision.
enum class SessionKind {
    // A graphical session whose lock state can be queried.
    Graphical,
    // ssh / tty / console: there is nothing to lock, only to terminate.
    Terminal,
    // Anything FIC cannot classify confidently. Treated as Terminal by the
    // containment flow (the stronger action), never ignored.
    Unknown
};

// A session as reported by the AUTHORITATIVE source (systemd-logind).
struct LoginSession {
    std::string id;
    uid_t uid = 0;
    std::string user;
    std::string type;
    SessionKind kind = SessionKind::Unknown;
    // True when the session belongs to a recovery identity and must never be
    // terminated by containment.
    bool recovery = false;
    std::string className;
    std::string state;
    bool remote = false;
    // Backend-derived NSS + logind decision; never populated from IPC input.
    bool ordinary = false;
    bool serviceAccount = false;
    std::string objectPath;
    std::string logindOwner;
    std::uint64_t startTimestamp = 0;
};

// A user identity as reported by the AUTHORITATIVE source (systemd-logind).
struct LoginUser {
    uid_t uid = 0;
    std::string name;
    // True for a service account or system identity FIC must not terminate.
    bool serviceAccount = false;
    // True when this identity is configured as a recovery identity.
    bool recovery = false;
    // True when a user manager is running (including lingering state).
    bool userManagerRunning = false;
    // Backend-derived identity decision, not a claim from ListUsers alone.
    bool ordinary = false;
    std::string objectPath;
    std::string logindOwner;
};

struct SessionInventoryResult {
    bool proven = false;
    std::vector<LoginSession> sessions;
    std::string diagnostic;
};

struct UserInventoryResult {
    bool proven = false;
    std::vector<LoginUser> users;
    std::string diagnostic;
};

// Result of a containment action on one object.
struct ContainmentOutcome {
    bool performed = false;
    std::string diagnostic;
};

// Outcome of a whole containment round.
struct ContainmentReport {
    // True when every requested action was proven, not merely invoked.
    bool proven = false;
    std::vector<std::string> failedActions;
    std::string diagnostic;

    // A report is "degraded" when some actions could not be proven. The
    // runtime state then becomes DEGRADED rather than ACTIVE.
    bool degraded() const { return !failedActions.empty(); }
};

// Interface to the containment mechanisms. The production implementation is
// logind-backed (see LogindSessionContainmentBackend); tests substitute a
// fake so the decision logic can be exercised without touching the host.
//
// Invariants every implementation must honour:
//   * logind is the authoritative source of sessions and users;
//   * a successful action call is NOT a proof - containment is only proven by
//     the dedicated verification step;
//   * recovery identities are never terminated;
//   * a graphical lock must be VERIFIED, and an unverifiable lock escalates to
//     session termination;
//   * /etc/passwd and UID ranges are never used to pick termination targets.
class SessionContainmentBackend {
public:
    virtual ~SessionContainmentBackend() = default;

    virtual SessionInventoryResult listSessions() = 0;
    virtual UserInventoryResult listUsers() = 0;

    virtual SessionKind classifySession(const LoginSession& session) = 0;

    // Locks a graphical session. The return value says only that the request
    // was accepted; callers MUST then verify with verifySessionLocked().
    virtual ContainmentOutcome lockSession(const LoginSession& session) = 0;
    virtual bool verifySessionLocked(const LoginSession& session,
                                    std::string& diagnostic) = 0;

    virtual ContainmentOutcome terminateSession(const LoginSession& session) = 0;
    virtual ContainmentOutcome terminateUser(const LoginUser& user) = 0;

    virtual bool verifySessionsGone(const std::vector<LoginSession>& sessions,
                                   std::string& diagnostic) = 0;
    virtual bool verifyUserRuntimeGone(const LoginUser& user,
                                       std::string& diagnostic) = 0;

    // Model A support: look up ONE logind user by UID and prove its identity
    // against the canonical name recorded when the user was durably selected.
    // This lets the controller operate on an ALREADY-SELECTED target whose
    // login session is gone, without ever treating ListUsers as a source of
    // new targets.
    //
    //   Found    — logind returned this UID, the reply is proven, NSS confirms
    //              uid<->name consistency and the recorded canonical name, and
    //              the identity is not a protected recovery identity;
    //   Absent   — logind positively proves no such user object (its runtime
    //              may still need manager verification);
    //   Unproven — logind failed, the UID maps to a different identity (UID
    //              reuse), or any proof failed. NEVER a permission to act.
    struct RegisteredUserLookup {
        enum class Status { Found, Absent, Unproven };
        Status status = Status::Unproven;
        LoginUser user;
        std::string diagnostic;
    };
    virtual RegisteredUserLookup lookupProvenUser(
        uid_t uid, const std::string& expectedCanonicalName) = 0;
};

} // namespace fic::session

#endif // FIC_SESSION_SESSION_CONTAINMENT_BACKEND_H
