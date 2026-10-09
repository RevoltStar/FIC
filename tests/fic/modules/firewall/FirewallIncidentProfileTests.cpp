#include "modules/firewall/FirewallCoordinator.h"
#include "modules/firewall/FirewallPolicies.h"
#include "incident/FirewallIncidentNetworkAdapter.h"
#include "rollback/DaemonMutationJournal.h"
#include <fic/core/process/ProcessExecutor.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <sys/stat.h>
#include <unistd.h>

using namespace fic::firewall;
using Json = nlohmann::json;
using Severity = fic::core::IncidentSeverity;
void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

struct FakeNft {
    Json objects = Json::array();
    int writes = 0, checks = 0, reads = 0;
    bool unavailable = false, malformed = false, failCheck = false, failApply = false;
    bool lie = false, extraAllow = false, wrongHook = false;
    bool realKernel = false;
    unsigned int handle = 100;
    std::vector<Json> batches;
    ProcessResult run(const std::vector<std::string>& args, const ProcessOptions& options) {
        if (realKernel) {
            auto result = ProcessExecutor::execute("/usr/sbin/nft", args, options);
            if (args == std::vector<std::string>{"-j", "list", "ruleset"} && result.success())
                objects = Json::parse(result.standardOutput).at("nftables");
            return result;
        }
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        if (unavailable) { result.exitCode = 1; result.error = "unavailable"; return result; }
        if (args == std::vector<std::string>{"-j", "list", "ruleset"}) {
            ++reads;
            auto output = objects;
            output.insert(output.begin(), Json{{"metainfo", {{"json_schema_version", 1}}}});
            result.standardOutput = malformed ? "{" : Json{{"nftables", output}}.dump();
            return result;
        }
        const auto commands = Json::parse(*options.standardInput).at("nftables");
        if (std::find(args.begin(), args.end(), "-c") != args.end()) {
            ++checks;
            if (failCheck) { result.exitCode = 1; result.error = "check failed"; }
            return result;
        }
        ++writes; batches.push_back(commands);
        if (failApply) { result.exitCode = 1; result.error = "apply failed"; return result; }
        if (lie) return result;
        Json next = objects;
        for (const auto& command : commands) {
            const auto op = command.begin().key();
            const auto item = command.begin().value();
            const auto kind = item.begin().key();
            auto object = item.begin().value();
            if (op == "delete" && kind == "table") {
                std::string table;
                for (const auto& current : next)
                    if (current.contains("table") &&
                        (object.contains("handle") ? current.at("table").at("handle") == object.at("handle")
                         : current.at("table").at("name") == object.at("name")))
                        table = current.at("table").at("name").get<std::string>();
                require(!table.empty(), "fake: table deletion must target an existing table");
                Json retained = Json::array();
                for (const auto& current : next) {
                    const auto& value = current.begin().value();
                    if (value.value(current.contains("table") ? "name" : "table", "") != table)
                        retained.push_back(current);
                }
                next = retained;
            } else if ((op == "flush" || op == "delete") && kind == "chain") {
                Json retained = Json::array();
                for (const auto& current : next) {
                    const auto& value = current.begin().value();
                    const bool inChain = value.value("family", "") == object.at("family") &&
                        value.value("table", "") == object.at("table") &&
                        ((current.contains("rule") && value.at("chain") == object.at("name")) ||
                         (op == "delete" && current.contains("chain") && value.at("name") == object.at("name")));
                    if (!inChain) retained.push_back(current);
                }
                next = std::move(retained);
            } else if (op == "create" || op == "add") {
                if (kind == "table") {
                    for (const auto& current : next)
                        require(!current.contains("table") || current.at("table").at("name") != object.at("name"),
                                "fake: create collision");
                }
                object["handle"] = ++handle;
                next.push_back({{kind, object}});
            } else {
                throw std::runtime_error("fake: unexpected command " + command.dump());
            }
        }
        if (extraAllow) {
            next.push_back({{"rule", {{"family", "inet"}, {"table", "fic_incident_quarantine"},
                {"chain", "input"}, {"expr", Json::array({{{"accept", nullptr}}})},
                {"comment", "fic:quarantine:0"}}}});
        }
        if (wrongHook)
            for (auto& item : next)
                if (item.contains("chain") && item.at("chain").at("table") == "fic_incident_quarantine" &&
                    item.at("chain").at("name") == "input") item.at("chain")["hook"] = "output";
        objects = std::move(next);
        return result;
    }
};
struct EmptySessions : fic::session::SessionContainmentBackend {
    fic::session::SessionInventoryResult listSessions() override { return {true, {}, ""}; }
    fic::session::UserInventoryResult listUsers() override { return {true, {}, ""}; }
    fic::session::SessionKind classifySession(const fic::session::LoginSession&) override {
        throw std::runtime_error("no session actions expected");
    }
    fic::session::ContainmentOutcome lockSession(const fic::session::LoginSession&) override { return {}; }
    bool verifySessionLocked(const fic::session::LoginSession&, std::string&) override { return false; }
    fic::session::ContainmentOutcome terminateSession(const fic::session::LoginSession&) override { return {}; }
    fic::session::ContainmentOutcome terminateUser(const fic::session::LoginUser&) override { return {}; }
    bool verifySessionsGone(const std::vector<fic::session::LoginSession>&, std::string&) override { return true; }
    bool verifyUserRuntimeGone(const fic::session::LoginUser&, std::string&) override { return true; }
    RegisteredUserLookup lookupProvenUser(uid_t, const std::string&) override { return {}; }
};

struct Fixture {
    std::filesystem::path root;
    FakeNft nft;
    fic::platform::PlatformExecutableResolver resolver{{}};
    FirewallDesiredState config;
    bool quarantine = false, configValid = true;
    FirewallOwnershipOptions ownership;
    std::unique_ptr<FirewallBackend> backend;
    std::unique_ptr<FirewallCoordinator> coordinator;
    Fixture() {
        std::string pattern = "/tmp/fic-firewall-profile-XXXXXX";
        root = ::mkdtemp(pattern.data());
        ownership.path = root / "firewall_ownership";
        auto& expected = ownership.expectation;
        expected.owner = ::geteuid(); expected.group = ::getegid();
        expected.parentOwner = ::geteuid(); expected.parentGroup = ::getegid();
        expected.exactMode = 0640; expected.exactParentMode = 0700;
        expected.requireSingleLink = true;
        resetBackend();
    }
    ~Fixture() { std::filesystem::remove_all(root); }
    void resetBackend() {
        backend = std::make_unique<FirewallBackend>(resolver,
            [&](const auto& args, const auto& options) { return nft.run(args, options); }, ownership,
            [&] { return quarantine; }, [&](auto& desired, auto& error) {
                desired = config; error = configValid ? "" : "invalid exception JSON"; return configValid;
            });
        coordinator = std::make_unique<FirewallCoordinator>(*backend);
    }
    bool reconcile(std::string& error) {
        bool changed;
        std::vector<ForeignBaseChain> neutralized;
        return coordinator->reconcile(nullptr, changed, neutralized, error);
    }
    std::map<std::string, Json> tables() {
        std::map<std::string, Json> result; std::string error;
        require(observeManagedObjects({{"nftables", nft.objects}}, result, error), error);
        return result;
    }
    void normal() {
        std::string error;
        require(buildFirewallDesiredState({{"block_rdp", true}, {"block_ftp", true}}, "[]", config, error), error);
        require(reconcile(error), error);
    }
};
void parserTests() {
    FirewallActualState actual; std::string error;
    require(!parseNftActualState({{"nftables", Json::array({17})}}, actual, error), "C13 unsupported nft entry");
    std::map<std::string, Json> observed;
    require(!observeManagedObjects({{"nftables", Json::array({{{"unknown", Json::object()}}})}}, observed, error),
            "C13 unsupported nft object");
    std::vector<FirewallRule> rules; std::string normalized;
    require(parseQuarantineRules("[]", rules, normalized, error), error);
    require(!parseQuarantineRules("{}", rules, normalized, error), "Q10 invalid JSON");
    Json duplicate;
    require(!parseFirewallJson("{\"nftables\":[],\"nftables\":[]}", duplicate, error),
            "C13 duplicate JSON keys must not be last-wins proof");
    const Json rule = {{"direction", "outgoing"}, {"protocol", "tcp"}, {"source", "any"},
        {"destination", "192.0.2.10"}, {"source_port", "any"}, {"destination_port", "443-445"}, {"action", "allow"}};
    require(parseQuarantineRules(Json::array({rule}).dump(), rules, normalized, error), error);
    auto blocked = rule; blocked["action"] = "block";
    require(!parseQuarantineRules(Json::array({blocked}).dump(), rules, normalized, error), "Q11 block must be rejected");
    auto ipv6 = rule; ipv6["destination"] = "2001:db8::10/128"; ipv6["protocol"] = "udp";
    require(parseQuarantineRules(Json::array({ipv6}).dump(), rules, normalized, error), error);
    FirewallDesiredState desired; desired.quarantine = true; desired.exceptions = rules;
    const auto objects = compileFirewallObjects(desired).dump();
    require(objects.find("reply") != std::string::npos && objects.find("established") != std::string::npos,
            "Q8 replies must require conntrack reply");
    require(objects.find("related") == std::string::npos, "Q9 no broad related accept");
    require(objects.find("ip6") != std::string::npos, "Q6 IPv6 matching");
    std::cout << "C13 Q5 Q6 Q7 Q8 Q9 Q10 Q11 PASS\n";
}
void profilesAndDirectPaths() {
    Fixture f; f.normal(); std::string error;
    require(f.tables().size() == 2, "P1 normal policies");
    const int beforeDormant = f.nft.writes;
    bool dormantChanged = true;
    require(f.backend->applyPolicy("incident_quarantine", {}, dormantChanged, error) &&
            !dormantChanged && f.nft.writes == beforeDormant, "Q13 dormant quarantine apply must not mutate nft");
    f.quarantine = true;
    require(f.reconcile(error), error);
    require(f.tables().size() == 1 && f.tables().count("fic_incident_quarantine"), "P6 quarantine only");
    const auto& batch = f.nft.batches.back();
    int deletes = 0, creates = 0;
    for (const auto& command : batch) { deletes += command.contains("delete"); creates += command.contains("create"); }
    require(deletes == 2 && creates == 1, "F10 atomic switch must include old removals and new creation");
    for (const std::string policy : {"block_rdp", "block_ftp", "custom_rules", "future_policy"}) {
        bool changed = true;
        require(f.backend->applyPolicy(policy, {}, changed, error), error);
        require(!changed && f.tables().size() == 1, "F1 F2 F3 F14 deferred ordinary apply");
    }
    std::vector<ForeignBaseChain> neutralized;
    require(f.backend->applyExclusive(neutralized, error), error);
    FirewallDesiredState normalIntent;
    require(f.backend->reconcile(normalIntent, neutralized, error), error);
    require(f.tables().count("fic_incident_quarantine"), "F4 F5 F8 normal reconcile/rollback cannot remove quarantine");
    const int writes = f.nft.writes;
    f.resetBackend();
    require(f.reconcile(error), error);
    require(f.nft.writes == writes, "C5 C17 restart/unchanged reconcile writes nothing");
    f.nft.objects = Json::array();
    require(f.reconcile(error), error);
    require(f.tables().count("fic_incident_quarantine"), "C6 drift restore");
    // Current configuration, including modifications while isolated, is authority.
    require(buildFirewallDesiredState({{"block_ftp", true}}, "[]", f.config, error), error);
    f.quarantine = false;
    require(f.coordinator->requestProfile(false, error), error);
    require(f.tables().size() == 1 && f.tables().count("fic_block_ftp"), "F9 current normal config");
    std::cout << "P1 P6 F1 F2 F3 F4 F5 F8 F9 F10 F11 F14 C5 C6 C17 PASS\n";
}
void configurationTests() {
    Fixture f;
    const auto directory = f.root / "config";
    std::filesystem::create_directory(directory); ::chmod(directory.c_str(), 0700);
    const auto path = directory / "FIREWALL.conf";
    const auto write = [&](const std::string& status, const std::string& value) {
        std::ofstream config(path);
        config << "_schema_version=1\nblock_rdp.status=ENABLE\nblock_ftp.status=DISABLE\n"
                  "custom_rules.status=DISABLE\ncustom_rules.value=[]\nexclusive_firewall_control.status=DISABLE\n"
               << "incident_quarantine.status=" << status << "\nincident_quarantine.value=" << value << '\n';
        config.close(); ::chmod(path.c_str(), 0640);
    };
    FirewallDesiredState desired; std::string error;
    auto read = [&](FirewallEffectiveProfile profile) {
        return FirewallCoordinator::readConfiguration(path, f.ownership.expectation, profile, desired, error);
    };
    const Json exception = {{"direction", "outgoing"}, {"protocol", "tcp"}, {"source", "any"},
        {"destination", "192.0.2.10"}, {"source_port", "any"}, {"destination_port", 443}, {"action", "allow"}};
    write("ENABLE", Json::array({exception}).dump());
    require(read(FirewallEffectiveProfile::IncidentQuarantine) && desired.exceptions.size() == 1, "Q3 ENABLE exceptions");
    write("DISABLE", "malformed but disabled");
    require(read(FirewallEffectiveProfile::IncidentQuarantine) && desired.exceptions.empty(), "Q2 DISABLE suppresses exceptions only");
    write("ENABLE", "malformed");
    require(read(FirewallEffectiveProfile::Normal) && desired.policyRules.count("block_rdp") && desired.exceptions.empty(),
            "Q13 invalid dormant exceptions cannot activate or disturb NORMAL");
    require(!read(FirewallEffectiveProfile::IncidentQuarantine), "Q10 malformed active exceptions");
    write("ENABLE", "[]");
    { std::ofstream append(path, std::ios::app); append << "incident_quarantine.status=DISABLE\n"; }
    require(!read(FirewallEffectiveProfile::IncidentQuarantine), "Q10 duplicate authority key");
    std::cout << "Q2 Q3 Q10 Q13 production configuration PASS\n";
}
void failureTests() {
    std::string error;
    { Fixture f; f.quarantine = true; f.nft.lie = true;
      require(!f.reconcile(error), "C3 command success is not proof");
      f.nft.lie = false; f.resetBackend(); require(f.reconcile(error), error); }
    { Fixture f; f.normal(); const auto old = f.nft.objects;
      f.quarantine = true; f.nft.failApply = true;
      require(!f.reconcile(error) && f.nft.objects == old, "C1 F10 failed transaction retains before state");
      f.nft.failApply = false; f.resetBackend(); require(f.reconcile(error), error); }
    { Fixture f; f.quarantine = true; f.nft.extraAllow = true;
      require(!f.reconcile(error), "C15 extra permissive rule must fail postcondition");
      const int writes = f.nft.writes; f.nft.extraAllow = false;
      require(!f.reconcile(error) && f.nft.writes == writes, "F13 unowned drift cannot be deleted"); }
    { Fixture f; f.quarantine = true; f.nft.wrongHook = true;
      require(!f.reconcile(error), "C14 wrong quarantine hook cannot pass postcondition"); }
    { Fixture f; f.quarantine = true; f.nft.malformed = true;
      require(!f.reconcile(error) && f.nft.writes == 0, "C13 malformed observation"); }
    { Fixture f; f.quarantine = true; f.nft.unavailable = true;
      require(!f.reconcile(error), "C12 unavailable"); }
    { Fixture f; f.quarantine = true; f.configValid = false;
      require(!f.reconcile(error) && f.tables().count("fic_incident_quarantine"), "Q10 strict fallback remains degraded"); }
    { Fixture f; f.quarantine = true;
      f.nft.objects = Json::array({{{"table", {{"family", "inet"}, {"name", "fic_block_rdp"}}}}});
      require(!f.reconcile(error) && f.nft.writes == 0, "F13 old name-only ownership refused"); }
    { Fixture f; f.normal(); f.quarantine = true;
      AtomicFileWriter::setDirectoryFsyncHookForTests([](const auto&) { return false; });
      const int writes = f.nft.writes;
      require(!f.reconcile(error) && f.nft.writes == writes, "C1 durable manifest required before mutation");
      AtomicFileWriter::setDirectoryFsyncHookForTests({}); }
    { Fixture f; f.quarantine = true; require(f.reconcile(error), error);
      f.config.policyRules.clear(); f.quarantine = false; f.nft.failApply = true;
      require(!f.coordinator->requestProfile(false, error), "C11 failed NORMAL restoration");
      f.nft.failApply = false; require(f.coordinator->requestProfile(false, error), error); }
    { Fixture f; f.normal(); f.quarantine = true; require(f.reconcile(error), error);
      f.nft.objects = Json::array(); f.quarantine = false;
      bool changed = false;
      require(f.backend->applyPolicy("block_rdp", f.config.policyRules.at("block_rdp"), changed, error), error);
      require(f.tables().size() == 2 && f.tables().count("fic_block_ftp"),
              "F9 missing quarantine must still restore full current NORMAL config on direct apply"); }
    std::cout << "C1 C2 C3 C4 C11 C12 C13 C15 F13 Q10 PASS\n";
}
void foreignAndExceptionTests() {
    Fixture f; std::string error;
    f.nft.objects = Json::array({
        {{"table", {{"family", "inet"}, {"name", "foreign"}, {"handle", 20}}}},
        {{"chain", {{"family", "inet"}, {"table", "foreign"}, {"name", "input"},
          {"type", "filter"}, {"hook", "input"}, {"prio", 0}, {"policy", "drop"}, {"handle", 21}}}}
    });
    const auto foreign = f.nft.objects;
    f.normal(); f.quarantine = true;
    require(f.reconcile(error), error);
    for (const auto& item : foreign)
        require(std::find(f.nft.objects.begin(), f.nft.objects.end(), item) != f.nft.objects.end(), "F12 foreign objects preserved");
    std::vector<ForeignBaseChain> neutralized;
    require(f.backend->applyExclusive(neutralized, error) && neutralized.empty(), "F4 no exclusive actions in quarantine");
    const auto first = f.tables().at("fic_incident_quarantine");
    const Json rule = {{"direction", "incoming"}, {"protocol", "udp"}, {"source", "192.0.2.20/24"},
        {"destination", "any"}, {"source_port", "any"}, {"destination_port", 53}, {"action", "allow"}};
    std::string normalized;
    require(parseQuarantineRules(Json::array({rule}).dump(), f.config.exceptions, normalized, error), error);
    require(f.config.exceptions.front().source.value == "192.0.2.0/24", "CIDR host bits must be canonical");
    const int writes = f.nft.writes;
    require(f.reconcile(error) && f.nft.writes == writes + 1, "Q12 exception update uses one transaction");
    require(f.tables().at("fic_incident_quarantine") != first, "Q12 new exception is verified");
    f.quarantine = false; f.config.exclusive = true;
    require(f.reconcile(error), error);
    require(!f.tables().count("fic_incident_quarantine"), "exclusive normal restoration removes only owned quarantine");
    bool foreignAccept = false;
    for (const auto& item : f.nft.objects)
        if (item.contains("chain") && item.at("chain").at("table") == "foreign")
            foreignAccept = item.at("chain").at("policy") == "accept";
    require(foreignAccept, "NORMAL retains exclusive semantics");
    std::cout << "F4 F12 F15 Q4 Q12 NORMAL exclusive PASS\n";
}
void pendingJournalSurvivesProfiles() {
    using namespace fic::rollback;
    Fixture f; std::string error;
    auto& facade = DaemonMutationJournal::instance();
    facade.setOverridePath(f.root / "journal.json");
    const PolicyRef policy{"FIREWALL", "HostFiltering", "block_rdp"};
    MutationId id = 0;
    require(recordPreparedMutation(policy, "block_rdp",
        {MutationBackend::Firewall, UndoRemoveFirewallPolicy{"block_rdp"}}, id, error), error);
    const auto snapshot = [](const std::filesystem::path& path) {
        std::ifstream stream(path); return std::string((std::istreambuf_iterator<char>(stream)), {});
    };
    const auto before = snapshot(f.root / "journal.json");
    f.normal(); f.quarantine = true; require(f.reconcile(error), error);
    bool changed;
    require(f.backend->applyPolicy("block_rdp", {}, changed, error) && !changed, error);
    require(f.coordinator->applyJournaledPolicy(policy, {}, error), error);
    f.quarantine = false; require(f.reconcile(error), error);
    require(f.coordinator->applyJournaledPolicy(policy, f.config.policyRules.at("block_rdp"), error), error);
    require(before == snapshot(f.root / "journal.json"), "F16 profile transitions must not rewrite ordinary journal");
    auto* journal = facade.tryGet(error);
    require(journal && journal->activeRecords(policy).size() == 1 &&
            journal->activeRecords(policy).front().status == MutationStatus::Prepared,
            "F16 pending ordinary obligation remains pending");
    facade.resetOverride();
    std::cout << "F16 pending ordinary journal survives profiles PASS\n";
}
void controllerTests() {
    using namespace fic::incident;
    Fixture f; std::string error;
    IncidentStateStore::setOwnershipExpectationForTests(::geteuid(), ::geteuid());
    IncidentSessionTargetStore::setOwnershipExpectationForTests(::geteuid(), ::geteuid());
    const auto statePath = f.root / "lockstatus";
    { std::ofstream stream(statePath); stream << "UNLOCKED\n"; }
    ::chmod(statePath.c_str(), 0640);
    IncidentResponseMode mode = IncidentResponseMode::Active;
    auto network = std::make_shared<FirewallIncidentNetworkAdapter>(*f.coordinator);
    auto makeController = [&] {
        auto controller = std::make_unique<IncidentController>(IncidentStateStore(statePath),
            std::make_shared<EmptySessions>(), network);
        controller->setModeResolver([&] { return IncidentResponseModeResult{mode, true, "test"}; });
        controller->setAccessGateVerifier([](auto&) { return true; });
        controller->setBootIdProviderForTests([] { return "11111111-1111-4111-8111-111111111111"; });
        return controller;
    };
    // Production backend entry points use a selector grounded in the controller's
    // persistent state, including its fail-closed provenance rule.
    auto decide = [&] {
        const auto state = IncidentStateStore(statePath).read();
        return IncidentController::networkQuarantineRequired({mode, true, "test"}, state);
    };
    f.backend = std::make_unique<FirewallBackend>(f.resolver,
        [&](const auto& args, const auto& options) { return f.nft.run(args, options); }, f.ownership,
        decide, [&](auto& desired, auto& diagnostic) { desired = f.config; diagnostic.clear(); return true; });
    f.coordinator = std::make_unique<FirewallCoordinator>(*f.backend);
    network = std::make_shared<FirewallIncidentNetworkAdapter>(*f.coordinator);
    auto controller = makeController();
    for (const auto severity : {Severity::Soft, Severity::Standard, Severity::Hard}) {
        require(controller->raise(severity, {"test"}, "profile").ok, "P3 P4 P5 controller normal");
        require(!f.tables().count("fic_incident_quarantine"), "non-ISOLATE must not quarantine");
    }
    const auto isolate = controller->raise(Severity::Isolate, {"test"}, "profile");
    require(isolate.ok && controller->status().containment.networkQuarantined, "P6 controller fresh network proof");
    mode = IncidentResponseMode::Passive;
    controller = makeController(); require(controller->reconcile().ok, "C8 restart PASSIVE");
    require(!f.tables().count("fic_incident_quarantine"), "P7 PASSIVE restores normal");
    mode = IncidentResponseMode::Active; require(controller->reconcile().ok, "reenter isolate");
    mode = IncidentResponseMode::Off; controller = makeController();
    require(controller->reconcile().ok && !f.tables().count("fic_incident_quarantine"), "P8 C9 OFF after restart");
    mode = IncidentResponseMode::Active; require(controller->reconcile().ok, "reenter isolate");
    f.nft.failApply = true;
    const auto cleared = controller->clear("test");
    require(!cleared.ok && cleared.runtime == RuntimeState::Degraded &&
        IncidentStateStore(statePath).read().severity == Severity::Unlocked, "P9 C11 clear must keep durable UNLOCKED");
    f.nft.failApply = false; controller = makeController();
    require(controller->reconcile().ok && !f.tables().count("fic_incident_quarantine"), "C10 clear restart retry");
    auto broken = IncidentStateStore(statePath).read();
    broken.provenance = IncidentStateStore::Provenance::Broken;
    require(IncidentController::networkQuarantineRequired({IncidentResponseMode::Active, true, "test"}, broken),
            "P10 unproven state must select quarantine");
    broken.provenance = IncidentStateStore::Provenance::Proven; broken.severity = Severity::Isolate;
    require(IncidentController::networkQuarantineRequired({IncidentResponseMode::Off, false, "unproven"}, broken),
            "P11 unproven mode must have ACTIVE semantics");
    broken.severity = Severity::Hard;
    require(IncidentController::networkQuarantineRequired({IncidentResponseMode::Active, true, "test"}, broken, true),
            "failed persistence with older valid HARD token must retain effective ISOLATE quarantine");
    require(!IncidentController::networkQuarantineRequired({IncidentResponseMode::Off, true, "test"}, broken, true),
            "proven OFF overrides transient stricter ACTIVE requirement");
    std::cout << "P3 P4 P5 P6 P7 P8 P9 C8 C9 C10 C11 controller PASS\n";
}
int main(int argc, char** argv) {
    try {
        Fixture runtime;
        auto paths = fic::core::FicProductPaths::production();
        paths.logDir = runtime.root / "log";
        paths.notifyDir = runtime.root / "notify";
        paths.configDir = runtime.root / "config";
        std::filesystem::create_directory(paths.logDir);
        std::filesystem::create_directory(paths.notifyDir);
        std::filesystem::create_directory(paths.configDir);
        { std::ofstream audit(paths.configDir / "AUDIT.conf"); audit << "log_level.status=ENABLE\nlog_level.value=ERROR\n"; }
        std::string pathError;
        require(fic::core::FicRuntimePaths::initialize(paths, pathError), pathError);
        if (argc == 2 && std::string(argv[1]) == "--kernel-server") {
            require(std::filesystem::exists("/run/.containerenv"), "kernel server requires disposable Podman namespace");
            Fixture f; f.nft.realKernel = true;
            std::string line;
            while (std::getline(std::cin, line)) {
                try {
                    const auto request = Json::parse(line);
                    f.quarantine = request.at("quarantine").get<bool>();
                    f.config = {};
                    std::string error, normalized;
                    require(parseQuarantineRules(request.value("exceptions", Json::array()).dump(),
                                                  f.config.exceptions, normalized, error), error);
                    const bool ok = f.reconcile(error);
                    std::cout << Json{{"ok", ok}, {"error", error}}.dump() << std::endl;
                } catch (const std::exception& error) {
                    std::cout << Json{{"ok", false}, {"error", error.what()}}.dump() << std::endl;
                }
            }
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--kernel-tests") {
            require(std::filesystem::exists("/run/.containerenv"), "kernel tests require disposable Podman namespace");
            Fixture f; f.nft.realKernel = true; std::string error;
            f.normal(); f.quarantine = true;
            require(f.reconcile(error), error);
            const Json rule = {{"direction", "outgoing"}, {"protocol", "tcp"}, {"source", "any"},
                {"destination", "2001:db8::10/128"}, {"source_port", "any"}, {"destination_port", "443-445"}, {"action", "allow"}};
            std::string normalized;
            require(parseQuarantineRules(Json::array({rule}).dump(), f.config.exceptions, normalized, error), error);
            if (!f.reconcile(error)) { std::cerr << f.nft.objects.dump(2) << '\n'; throw std::runtime_error(error); }
            f.quarantine = false; require(f.reconcile(error), error);
            std::cout << "real nft NORMAL/quarantine/IPv6 exceptions/NORMAL postcondition PASS\n"; return 0;
        }
        if (argc >= 2 && std::string(argv[1]) == "--emit-quarantine") {
            FirewallDesiredState desired; desired.quarantine = true;
            if (argc == 3) {
                std::ifstream input(argv[2]);
                const std::string value((std::istreambuf_iterator<char>(input)), {});
                std::string normalized, error;
                require(parseQuarantineRules(value, desired.exceptions, normalized, error), error);
            }
            Json commands = Json::array();
            for (const auto& object : compileFirewallObjects(desired)) commands.push_back({{"add", object}});
            std::cout << Json{{"nftables", commands}}.dump() << '\n'; return 0;
        }
        parserTests(); configurationTests(); profilesAndDirectPaths(); failureTests(); foreignAndExceptionTests(); pendingJournalSurvivesProfiles(); controllerTests();
        return 0;
    } catch (const std::exception& error) {
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
