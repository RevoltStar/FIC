// Production-to-production ACK contract test: the responses the MAIN DAEMON
// actually builds (fic::daemon::make_device_incident_ack_response, driven by
// the real IncidentController in every response mode) must be accepted by the
// PRODUCTION device-daemon parser
// (fic::device_control::parse_device_incident_acknowledgement) with the
// authoritative matrix:
//
//   NONE/DISABLE/OFF      -> valid, acknowledged=true, persistence=false,
//                            ignored=true, no detector retry
//   PASSIVE durable       -> valid, acknowledged=persistence=true, ignored=false
//   ACTIVE durable + DEGRADED -> valid, acknowledged=persistence=true,
//                            incident_ok=false, runtime=degraded, no retry
//   persistence failure   -> valid, acknowledged=persistence=false, retry kept
//
// Inconsistent replies must be rejected: the parser never repairs them.
#include "daemon/DeviceIncidentEvent.h"
#include "daemon/PermanentDeviceIncident.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

#include <fic/core/incident/IncidentSeverity.h>
#include <sys/stat.h>

#include <nlohmann/json.hpp>

#include "incident/IncidentController.h"
#include "incident/IncidentStateStore.h"
#include "session/SessionContainmentBackend.h"

using fic::daemon::DeviceMissingReaction;
using fic::daemon::DeviceMissingReactionKind;
using fic::daemon::make_device_incident_ack_response;
using fic::device_control::DeviceIncidentAcknowledgement;
using fic::device_control::parse_device_incident_acknowledgement;
using fic::incident::IncidentController;
using fic::incident::IncidentResult;
using fic::incident::IncidentSource;
using fic::incident::IncidentStateStore;
using fic::incident::IncidentResponseMode;
using fic::incident::RuntimeState;
using Severity = fic::core::IncidentSeverity;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

namespace {

class TempTree {
public:
    TempTree() {
        char pattern[] = "/tmp/fic-ack-contract-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root_ = created;
        statePath_ = root_ / "lockstatus";
        std::ofstream output(statePath_);
        output << "UNLOCKED\n";
        output.close();
        // The store validates the exact production mode.
        ::chmod(statePath_.c_str(), 0640);
    }
    ~TempTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }
    const std::filesystem::path& statePath() const { return statePath_; }

private:
    std::filesystem::path root_;
    std::filesystem::path statePath_;
};
// A session containment backend whose actions are never proven: it drives the
// ACTIVE + durable-severity + DEGRADED-containment outcome without touching
// the host.
class NeverProvenSessions final
    : public fic::session::SessionContainmentBackend {
public:
    std::vector<fic::session::LoginSession> listSessions() override {
        fic::session::LoginSession session;
        session.id = "c1";
        session.uid = 12345;
        session.user = "target";
        session.type = "wayland";
        session.kind = fic::session::SessionKind::Graphical;
        return {session};
    }
    std::vector<fic::session::LoginUser> listUsers() override { return {}; }
    fic::session::SessionKind classifySession(
        const fic::session::LoginSession&) override {
        return fic::session::SessionKind::Graphical;
    }
    fic::session::ContainmentOutcome lockSession(
        const fic::session::LoginSession&) override {
        return {false, "test backend never locks"};
    }
    bool verifySessionLocked(const fic::session::LoginSession&,
                             std::string& diagnostic) override {
        diagnostic = "test backend never locks";
        return false;
    }
    fic::session::ContainmentOutcome terminateSession(
        const fic::session::LoginSession&) override {
        return {false, "test backend never terminates"};
    }
    fic::session::ContainmentOutcome terminateUser(
        const fic::session::LoginUser&) override {
        return {false, "test backend never terminates"};
    }
    bool verifySessionsGone(const std::vector<fic::session::LoginSession>&,
                            std::string& diagnostic) override {
        diagnostic = "test backend never proves termination";
        return false;
    }
    bool verifyUserRuntimeGone(const fic::session::LoginUser&,
                               std::string& diagnostic) override {
        diagnostic = "test backend never proves termination";
        return false;
    }
};

DeviceMissingReaction reactionOf(DeviceMissingReactionKind kind) {
    DeviceMissingReaction reaction;
    reaction.kind = kind;
    if (kind == DeviceMissingReactionKind::None ||
        kind == DeviceMissingReactionKind::Disabled) {
        reaction.severity = Severity::Unlocked;
        reaction.diagnostic = kind == DeviceMissingReactionKind::None
            ? "permanent_device_missing_severity is NONE"
            : "permanent_device_missing_severity is DISABLE";
    } else {
        reaction.severity = Severity::Standard;
        reaction.diagnostic = "configured STANDARD";
    }
    return reaction;
}

} // namespace

int main() {
    // The state store proves root ownership in production; the test runs as
    // the invoking user.
    IncidentStateStore::setOwnershipExpectationForTests(
        ::geteuid(), ::geteuid());

    TempTree tree;
    IncidentController controller(
        IncidentStateStore(tree.statePath()), nullptr, nullptr);

    IncidentSource deviceSource;
    deviceSource.name = "device";
    const std::string reason = "PERMANENT_DEVICE_MISSING: device_id=123";

    // ---- NONE: intentional ignore, no incident write ----------------------
    {
        const nlohmann::json response = make_device_incident_ack_response(
            reactionOf(DeviceMissingReactionKind::None),
            /*ignoredByMode=*/true, /*persistenceConfirmed=*/false,
            /*incidentOk=*/true, "NONE", "UNLOCKED", "ACTIVE", "inactive",
            false, false, "");
        const auto ack = parse_device_incident_acknowledgement(response);
        require(ack.valid, "NONE must be accepted: " + ack.error);
        require(ack.acknowledged, "NONE must close the delivery obligation");
        require(!ack.persistenceConfirmed,
                "NONE must not claim a persistence that was not required");
        require(ack.ignored, "NONE must be an intentional ignore");
        require(response.value("message", "") ==
                    "device incident intentionally ignored",
                "NONE must not be diagnosed as a recording failure");
    }

    // ---- DISABLE: intentional ignore, no incident write -------------------
    {
        const nlohmann::json response = make_device_incident_ack_response(
            reactionOf(DeviceMissingReactionKind::Disabled),
            /*ignoredByMode=*/true, /*persistenceConfirmed=*/false,
            /*incidentOk=*/true, "NONE", "UNLOCKED", "ACTIVE", "inactive",
            false, false, "");
        const auto ack = parse_device_incident_acknowledgement(response);
        require(ack.valid && ack.acknowledged && !ack.persistenceConfirmed &&
                    ack.ignored,
                "DISABLE must be accepted as an intentional ignore: " +
                    ack.error);
    }

    // ---- OFF with a PROVEN lockstatus (real controller raise) -------------
    {
        controller.setModeResolver([] {
            return fic::incident::IncidentResponseModeResult{
                IncidentResponseMode::Off, true, "test OFF"};
        });
        const IncidentResult raised =
            controller.raise(Severity::Standard, deviceSource, reason);
        require(raised.ignoredByMode,
                "OFF must ignore the raise without incident mutation");
        const nlohmann::json response = make_device_incident_ack_response(
            reactionOf(DeviceMissingReactionKind::Severity),
            /*ignoredByMode=*/raised.ignoredByMode,
            /*persistenceConfirmed=*/raised.persistenceConfirmed,
            /*incidentOk=*/raised.ok, "STANDARD",
            fic::core::incidentSeverityToken(raised.effectiveSeverity), "OFF",
            fic::incident::runtimeStateToString(raised.runtime),
            raised.escalated, raised.persistentStateBroken, raised.detail);
        const auto ack = parse_device_incident_acknowledgement(response);
        require(ack.valid,
                "OFF with a proven lockstatus must be accepted: " + ack.error);
        require(ack.acknowledged && !ack.persistenceConfirmed && ack.ignored,
                "OFF must acknowledge the event without a persistence claim");
    }

    // ---- PASSIVE, durable severity (real controller raise) ----------------
    {
        controller.setModeResolver([] {
            return fic::incident::IncidentResponseModeResult{
                IncidentResponseMode::Passive, true, "test PASSIVE"};
        });
        const IncidentResult raised =
            controller.raise(Severity::Standard, deviceSource, reason);
        require(raised.persistenceConfirmed && raised.ok,
                "PASSIVE must durably record the severity: " + raised.detail);
        const nlohmann::json response = make_device_incident_ack_response(
            reactionOf(DeviceMissingReactionKind::Severity),
            raised.ignoredByMode, raised.persistenceConfirmed, raised.ok,
            "STANDARD",
            fic::core::incidentSeverityToken(raised.effectiveSeverity),
            "PASSIVE", fic::incident::runtimeStateToString(raised.runtime),
            raised.escalated, raised.persistentStateBroken, raised.detail);
        const auto ack = parse_device_incident_acknowledgement(response);
        require(ack.valid && ack.acknowledged && ack.persistenceConfirmed &&
                    !ack.ignored,
                "PASSIVE durable must be a full acknowledgement: " + ack.error);
    }

    // ---- ACTIVE, durable severity + DEGRADED containment ------------------
    {
        // A real session backend that never proves its actions drives the
        // controller to the DEGRADED outcome without touching the host.
        IncidentController degrading(
            IncidentStateStore(tree.statePath()),
            std::make_shared<NeverProvenSessions>(), nullptr);
        degrading.setModeResolver([] {
            return fic::incident::IncidentResponseModeResult{
                IncidentResponseMode::Active, true, "test ACTIVE"};
        });
        const IncidentResult raised =
            degrading.raise(Severity::Standard, deviceSource, reason);
        require(raised.persistenceConfirmed,
                "the severity must be durably recorded even when containment "
                "degrades");
        require(!raised.ok && raised.runtime == RuntimeState::Degraded,
                "a failed containment must be DEGRADED, not proven");
        const nlohmann::json response = make_device_incident_ack_response(
            reactionOf(DeviceMissingReactionKind::Severity),
            raised.ignoredByMode, raised.persistenceConfirmed, raised.ok,
            "STANDARD",
            fic::core::incidentSeverityToken(raised.effectiveSeverity),
            "ACTIVE", fic::incident::runtimeStateToString(raised.runtime),
            raised.escalated, raised.persistentStateBroken, raised.detail);
        const auto ack = parse_device_incident_acknowledgement(response);
        require(ack.valid && ack.acknowledged && ack.persistenceConfirmed,
                "ACTIVE durable + DEGRADED is still a full acknowledgement: " +
                    ack.error);
        require(!response.value("incident_ok", true),
                "incident_ok must stay false for a degraded containment");
        require(response.value("message", "") ==
                    "device incident recorded; containment degraded",
                "the DEGRADED diagnostic must describe the recorded incident, "
                "not a recording failure");
        require(!response.value("ok", true),
                "ok must reflect the combined containment outcome");
    }

    // ---- Persistence failure ----------------------------------------------
    {
        const nlohmann::json response = make_device_incident_ack_response(
            reactionOf(DeviceMissingReactionKind::Severity),
            /*ignoredByMode=*/false, /*persistenceConfirmed=*/false,
            /*incidentOk=*/false, "STANDARD", "ISOLATE", "ACTIVE", "degraded",
            false, true, "incident state could not be persisted");
        const auto ack = parse_device_incident_acknowledgement(response);
        require(ack.valid && !ack.acknowledged && !ack.persistenceConfirmed &&
                    !ack.ignored,
                "a persistence failure must be a non-acknowledgement: " +
                    ack.error);
        require(response.value("message", "") ==
                    "device incident could not be recorded",
                "a failed persistence must be diagnosed as a recording failure");
    }

    // ---- Inconsistent replies must be rejected ----------------------------
    {
        // acknowledged=false that the daemon never sent must NOT be repaired.
        const auto ack = parse_device_incident_acknowledgement(nlohmann::json{
            {"ok", true},
            {"message", "device incident intentionally ignored"},
            {"command", "incident_device_missing"},
            {"acknowledged", false},
            {"persistence_confirmed", false},
            {"incident_ok", true},
            {"escalated", false},
            {"response_mode", "ACTIVE"},
            {"requested_severity", "NONE"},
            {"effective_severity", "UNLOCKED"},
            {"ignored", true},
            {"runtime", "inactive"},
            {"api_version", 1}});
        require(!ack.valid,
                "an unacknowledged ignore must be rejected, never repaired");
    }
    {
        // The OLD (base-commit) NONE/DISABLE/OFF reply claimed persistence.
        const auto ack = parse_device_incident_acknowledgement(nlohmann::json{
            {"ok", true},
            {"message", "device incident processed"},
            {"command", "incident_device_missing"},
            {"acknowledged", true},
            {"persistence_confirmed", true},
            {"escalated", false},
            {"response_mode", "OFF"},
            {"requested_severity", "NONE"},
            {"effective_severity", "UNLOCKED"},
            {"ignored", true},
            {"runtime", "inactive"},
            {"api_version", 1}});
        require(!ack.valid,
                "an ignored event claiming persistence must be rejected");
    }
    {
        // A wrong-type field must be rejected without throwing.
        const auto ack = parse_device_incident_acknowledgement(nlohmann::json{
            {"ok", true},
            {"command", "incident_device_missing"},
            {"acknowledged", "yes"},
            {"persistence_confirmed", false},
            {"ignored", true},
            {"response_mode", "ACTIVE"},
            {"api_version", 1}});
        require(!ack.valid,
                "a wrongly typed acknowledged field must be rejected");
    }

    std::cout << "Device incident ACK production contract proven\n";
    return 0;
}
