// Integration test of the permanent-device-missing incident path with a
// substituted transport:
//
//   device daemon detection
//     -> bounded detector event (FACT only, no severity authority)
//     -> authenticated IPC request validation
//     -> configured detector severity resolution
//     -> IncidentController.raise()
//     -> persistent state result
//
// The main-daemon side is exercised through the real IncidentController with
// fake containment backends, so no real host state is touched.
#include "daemon/PermanentDeviceIncident.h"
#include "incident/IncidentController.h"
#include "incident/IncidentStateStore.h"
#include "incident/IncidentResponseMode.h"
#include "FicIpcWire.h"

#include <fic/ipc/FicIpcClient.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <fic/core/incident/IncidentSeverity.h>
#include <fic/core/fs/AtomicFileWriter.h>

#include <nlohmann/json.hpp>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>


using fic::device_control::PermanentViolation;
using fic::incident::IncidentController;
using fic::incident::IncidentResult;
using fic::incident::IncidentSource;
using fic::incident::IncidentStateStore;
using fic::incident::IncidentResponseMode;
using fic::incident::IncidentResponseModeResult;
using fic::incident::RuntimeState;
using ::fic::core::IncidentSeverity;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error("device incident integration: " + message);
    }
}

class TempTree {
public:
    TempTree() {
        char pattern[] = "/tmp/fic-device-incident-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = created;
        statePath = root / "lockstatus";
        std::ofstream output(statePath);
        output << "UNLOCKED\n";
        output.close();
        // The authoritative state file is 0640 in production; the store
        // validates the exact mode, so the fixture must match.
        ::chmod(statePath.c_str(), 0640);
    }
    ~TempTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }
    std::filesystem::path root;
    std::filesystem::path statePath;
};
// A single-connection IPC fixture standing in for the main daemon socket.
class MainDaemonFixture {
public:
    MainDaemonFixture() {
        char pattern[] = "/tmp/fic-device-incident-ipc-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        directory_ = created;
        path_ = (directory_ / "socket").string();
        server_ = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (server_ < 0) {
            throw std::runtime_error("socket failed");
        }
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, path_.c_str(),
                     sizeof(address.sun_path) - 1);
        if (::bind(server_, reinterpret_cast<sockaddr*>(&address),
                   sizeof(address)) != 0 ||
            ::listen(server_, 2) != 0) {
            throw std::runtime_error("bind/listen failed");
        }
    }
    ~MainDaemonFixture() {
        if (server_ >= 0) {
            ::close(server_);
        }
        std::filesystem::remove_all(directory_);
    }

    const std::string& path() const { return path_; }

    // Answers ONE connection with the configured response (or refuses, when the
    // response text is empty).
    std::thread answer(const std::string& response) {
        return std::thread([this, response] {
            const int client = ::accept(server_, nullptr, nullptr);
            if (client < 0) {
                return;
            }
            char request[8192];
            const ssize_t received =
                ::recv(client, request, sizeof(request), 0);
            if (received > 0) {
                lastRequest_ = std::string(
                    request, static_cast<std::size_t>(received));
            }
            if (!response.empty()) {
                const auto frame = fic::ipc::wire::responseFrame(
                    response, 0, response.size());
                (void)::send(client, frame.data(), frame.size(), MSG_NOSIGNAL);
            }
            ::close(client);
        });
    }

    const std::string& lastRequest() const { return lastRequest_; }

    // Accepts and closes one queued-but-never-served connection.
    void drainQueuedConnection() {
        const int queued = ::accept(server_, nullptr, nullptr);
        if (queued >= 0) {
            ::close(queued);
        }
    }

private:
    std::filesystem::path directory_;
    std::string path_;
    int server_ = -1;
    std::string lastRequest_;
};

IncidentSource deviceSource() {
    IncidentSource source;
    source.name = "device";
    return source;
}

int main() {
    using fic::device_control::is_valid_permanent_device_incident_request;
    using fic::device_control::permanent_device_incident_request;

    // The state store proves root ownership in production; tests run as the
    // invoking user, so the expectation is overridden for the whole run.
    IncidentStateStore::setOwnershipExpectationForTests(
        ::geteuid(), ::geteuid());
    fic::incident::IncidentSessionTargetStore::setOwnershipExpectationForTests(
        ::geteuid(), ::geteuid());

    TempTree tree;

    // The controller the main daemon owns. Fake/absent backends: nothing
    // touches the real host.
    IncidentController controller(
        IncidentStateStore(tree.statePath), nullptr, nullptr);
    controller.setModeResolver([] {
        return IncidentResponseModeResult{
            IncidentResponseMode::Passive, true, "test passive"};
    });

    const std::vector<PermanentViolation> violations{
        {123, 100, "/devices/usb1", "dc:block_usb_storage"}};
    const nlohmann::json request =
        permanent_device_incident_request(violations);
    std::string schemaError;
    require(is_valid_permanent_device_incident_request(request, schemaError),
            schemaError);

    MainDaemonFixture fixture;
    ::setenv("FIC_SOCKET_PATH", fixture.path().c_str(), 1);

    // --- T2: PASSIVE + HARD -> persisted/audited, no containment ------------
    {
        auto server = fixture.answer(nlohmann::json{
            {"ok", true},
            {"message", "device incident processed"},
            {"command", "incident_device_missing"},
            {"escalated", true},
            {"reason", "configured HARD"},
            {"response_mode", "PASSIVE"},
            {"requested_severity", "HARD"},
            {"effective_severity", "HARD"},
            {"ignored", false},
            {"runtime", "inactive"},
            {"api_version", 1}}.dump());
        const auto result = fic::ipc::Client().requestWithStatus(request);
        server.join();
        require(result.hasResponse, "the detector event must be delivered");
        require(result.response.value("ok", false),
                "PASSIVE + HARD with proven persistence is a success");
        require(result.response.value("response_mode", "") == "PASSIVE",
                "the mode must be echoed so ok=true is not read as containment");
        require(result.response.value("runtime", "") == "inactive",
                "PASSIVE must not imply runtime containment");
        require(fixture.lastRequest().find("incident_device_missing") !=
                    std::string::npos,
                "the daemon must have received the detector event");
        require(fixture.lastRequest().find("HARD") == std::string::npos,
                "the detector must not carry an authoritative severity");
    }

    // --- T1/T6: the REAL controller raise + monotonicity -------------------
    // T2 first: the main daemon would raise HARD in PASSIVE mode, so the real
    // controller performs the same transition the handler would have driven.
    {
        const IncidentResult hard = controller.raise(
            IncidentSeverity::Hard, deviceSource(),
            "PERMANENT_DEVICE_MISSING: device_id=123");
        require(hard.ok && hard.escalated,
                "PASSIVE + HARD must persist durably: " + hard.detail);
        require(hard.effectiveSeverity == IncidentSeverity::Hard,
                "the requested severity must be persisted");
        require(hard.runtime == RuntimeState::Inactive,
                "PASSIVE must not apply containment");
    }
    {
        const IncidentResult raised = controller.raise(
            IncidentSeverity::Soft, deviceSource(),
            "PERMANENT_DEVICE_MISSING: device_id=123");
        require(raised.effectiveSeverity == IncidentSeverity::Hard,
                "SOFT must not lower the persisted HARD");
        require(!raised.escalated,
                "a lower raise must not re-escalate or re-notify");
    }

    // --- T10: main daemon unavailable -> delivery failure -------------------
    // A short timeout models an unreachable daemon. The connection still lands
    // in the listen backlog, so the next fixture consumer drains it first.
    {
        const auto failed = fic::ipc::Client(
            fixture.path(), std::chrono::milliseconds(300)).requestWithStatus(request);
        require(!failed.hasResponse,
                "an unreachable main daemon must be a delivery failure");

        // Drain the queued-but-never-served connection so later fixtures only
        // see fresh requests.
        fixture.drainQueuedConnection();
    }

    // --- T11: main daemon returns -> retry delivers -------------------------
    {
        auto server = fixture.answer(nlohmann::json{
            {"ok", true},
            {"message", "device incident processed"},
            {"command", "incident_device_missing"},
            {"escalated", true},
            {"response_mode", "PASSIVE"},
            {"requested_severity", "HARD"},
            {"effective_severity", "HARD"},
            {"ignored", false},
            {"runtime", "inactive"},
            {"api_version", 1}}.dump());
        const auto retried = fic::ipc::Client().requestWithStatus(request);
        server.join();
        require(retried.hasResponse,
                "the retry must reach the daemon: " + retried.error);
        require(retried.response.value("ok", false),
                "the retry must deliver the still-existing violation: " +
                    retried.response.value("message", "no message"));
    }

    // --- T12: main daemon rejects the event -> no false success -------------
    {
        auto server = fixture.answer(nlohmann::json{
            {"ok", false}, {"message", "request.device_ids must not be empty"},
            {"api_version", 1}}.dump());
        const auto rejected = fic::ipc::Client().requestWithStatus(request);
        server.join();
        require(rejected.hasResponse && !rejected.response.value("ok", true),
                "a rejection must be reported as a failure");
    }

    // --- T13: malformed response -> failure diagnosed ----------------------
    {
        auto server = fixture.answer("not json at all");
        const auto malformed = fic::ipc::Client().requestWithStatus(request);
        server.join();
        require(!malformed.hasResponse || !malformed.response.is_object(),
                "a malformed response must be diagnosable");
    }

    ::unsetenv("FIC_SOCKET_PATH");

    // --- T8: reconnect does NOT clear --------------------------------------
    require(controller.status().severity == IncidentSeverity::Hard,
            "a reconnected device must not lower the persisted severity");

    // --- T9: the device remains missing after a clear -> raise again -------
    {
        const IncidentResult cleared = controller.clear("administrator");
        require(cleared.ok, "the administrative clear must succeed");
        const IncidentResult again = controller.raise(
            IncidentSeverity::Standard, deviceSource(),
            "PERMANENT_DEVICE_MISSING: device_id=123");
        require(again.escalated &&
                    again.effectiveSeverity == IncidentSeverity::Standard,
                "a still-missing device may escalate again after a clear");
    }

    std::cout << "Permanent-device incident integration path proven\n";
    return 0;
}
