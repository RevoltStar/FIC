#include "FirewallTestFixture.h"
#include "rollback/RollbackExecutor.h"

namespace {
using namespace firewall_test;
using namespace fic::rollback;
PolicyRef ref(const std::string& policy) { return {"FIREWALL", "HostFiltering", policy}; }
MutationJournal& journal() {
    std::string error;
    auto* value = DaemonMutationJournal::instance().tryGet(error);
    require(value != nullptr, "journal: " + error);
    return *value;
}
std::vector<MutationRecord> records(const std::string& policy) {
    return journal().activeRecords(ref(policy));
}
void desired(Fixture& f, const std::vector<std::string>& policies) {
    std::map<std::string, bool> enabled;
    for (const auto& p : policies) enabled[p] = true;
    const Json custom = Json::array({{{"direction", "outgoing"}, {"protocol", "udp"},
        {"source", "any"}, {"destination", "192.0.2.10"}, {"source_port", "any"},
        {"destination_port", 53}, {"action", "allow"}}});
    std::string error;
    require(buildFirewallDesiredState(enabled, custom.dump(), f.config, error), error);
}
void restart(Fixture& f) {
    DaemonMutationJournal::instance().setOverridePath(f.root / "journal.json");
    f.resetBackend();
}
void prepared(const std::string& p) {
    std::string error; MutationId id;
    require(recordPreparedMutation(ref(p), p,
        {MutationBackend::Firewall, UndoRemoveFirewallPolicy{p}}, id, error), error);
}
bool release(Fixture& f, const std::string& policy, std::string& error) {
#ifdef FIC_FIREWALL_PROVENANCE_BASE_REPLAY
    // Keep R1-R12 executable against the original f910e50 public API.
    bool changed;
    return f.backend->applyPolicy(policy, {}, changed, error);
#else
    return f.backend->removePolicy(policy, error);
#endif
}
void disable(Fixture& f, const std::string& p) {
    RollbackExecutorDeps deps;
    deps.undoFirewallPolicy = [&](const auto& name, auto& error) {
        return release(f, name, error);
    };
    const auto before = f.tables();
    const auto result = rollbackPolicyBeforeDisable(ref(p), p, deps);
    require(result.rollbackCompleted(), "production disable refused: " + result.message);
    f.config.policyRules.erase(p); // production configuration flips only after rollback
    const auto after = f.tables();
    require(!after.count(managedTableName(p)), "disable left policy table");
    for (const auto& [table, objects] : before)
        if (table != managedTableName(p))
            require(after.count(table) && after.at(table) == objects, "disable changed another table");
}
void enableInQuarantine(Fixture& f, const std::vector<std::string>& policies) {
    std::string error;
    f.quarantine = true; require(f.reconcile(error), error);
    desired(f, policies);
    for (const auto& p : policies) {
        require(f.coordinator->applyJournaledPolicy(ref(p), f.config.policyRules.at(p), error), error);
        require(records(p).empty(), "deferred apply created false obligation");
    }
    require(f.tables().size() == 1 && f.tables().count("fic_incident_quarantine"), "deferred ordinary mutation");
}
void run(int scenario) {
    Fixture f; std::string error;
    (void)journal();
    if (scenario <= 4) {
        std::vector<std::string> policies = scenario == 4
            ? managedFirewallPolicies() : std::vector<std::string>{scenario == 1 ? "block_rdp" : scenario == 2 ? "block_ftp" : "custom_rules"};
        enableInQuarantine(f, policies);
        if (scenario == 4) f.nft.beforeWrite = [&] {
            for (const auto& p : policies) {
                MutationJournal disk(f.root / "journal.json");
                require(disk.initializeOrLoad(error), error);
                auto active = disk.activeRecords(ref(p));
                require(active.size() == 1 && active.front().status == MutationStatus::Prepared,
                        "all preparations must be durable before atomic batch");
            }
        };
        f.quarantine = false; const int writes = f.nft.writes;
        require(f.coordinator->requestProfile(false, error), error);
        require(f.nft.writes == writes + 1, "restoration must use one batch");
        f.nft.beforeWrite = {};
        for (const auto& p : policies) disable(f, p);
        require(f.tables().empty(), "restoration/disable left tables");
    } else if (scenario == 5) {
        desired(f, {"block_rdp"});
        std::vector<ForeignBaseChain> neutralized;
        require(f.backend->reconcile(f.config, neutralized, error), error);
        disable(f, "block_rdp");
    } else if (scenario == 6 || scenario == 9) {
        desired(f, scenario == 6 ? std::vector<std::string>{"block_rdp"} : managedFirewallPolicies());
        AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path) {
            if (path != (f.root / "journal.json").string()) return true;
            std::ifstream file(path); Json disk; file >> disk;
            return disk.at("records").size() < (scenario == 6 ? 1U : 2U);
        });
        const bool ok = f.reconcile(error);
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(!ok && f.nft.writes == 0 && f.tables().empty(), "preparation failure allowed unjournaled batch");
        restart(f); require(f.reconcile(error), error);
        for (const auto& p : managedFirewallPolicies())
            if (f.config.policyRules.count(p)) require(records(p).size() == 1, "retry duplicated obligation");
    } else if (scenario == 7 || scenario == 8) {
        desired(f, {"block_rdp"});
        f.nft.beforeWrite = scenario == 7 ? std::function<void()>([] { throw std::runtime_error("crash before nft"); }) : std::function<void()>{};
        f.nft.afterWrite = scenario == 8 ? std::function<void()>([] { throw std::runtime_error("crash after nft"); }) : std::function<void()>{};
        require(!f.reconcile(error), "injected crash must fail");
        require(records("block_rdp").size() == 1 && records("block_rdp").front().status == MutationStatus::Prepared,
                "crash lost Prepared authority");
        const auto id = records("block_rdp").front().id;
        f.nft.beforeWrite = {}; f.nft.afterWrite = {};
        restart(f); const int writes = f.nft.writes;
        require(f.reconcile(error), error);
        auto active = records("block_rdp");
        require(active.size() == 1 && active.front().id == id && active.front().status == MutationStatus::Applied,
                "restart did not resolve same Prepared");
        require(f.nft.writes == writes + (scenario == 7 ? 1 : 0), "restart unnecessarily recreated proven table");
        disable(f, "block_rdp");
    } else if (scenario == 10) {
        desired(f, {"block_rdp"}); bool changed;
        require(f.backend->applyPolicy("block_rdp", f.config.policyRules.at("block_rdp"), changed, error), error);
        auto before = records("block_rdp");
        require(before.size() == 1 && before.front().status == MutationStatus::Applied, "direct apply lacks durable Applied");
        const int writes = f.nft.writes;
        require(f.reconcile(error), error); restart(f); require(f.reconcile(error), error);
        require(f.nft.writes == writes && records("block_rdp").front().id == before.front().id, "no-op changed Applied authority");
        f.nft.objects = Json::array(); restart(f); require(f.reconcile(error), error);
        require(records("block_rdp").size() == 1 && records("block_rdp").front().id == before.front().id, "reboot duplicated authority");
    } else if (scenario == 11) {
        desired(f, {"block_rdp"}); prepared("block_rdp"); require(f.reconcile(error), error);
        f.quarantine = true; require(f.reconcile(error), error);
        disable(f, "block_rdp");
        require(f.tables().size() == 1 && f.tables().count("fic_incident_quarantine"), "rollback weakened quarantine");
        f.quarantine = false; require(f.reconcile(error), error);
        require(f.tables().empty(), "disabled policy recreated after quarantine");
    } else if (scenario == 12) {
        desired(f, {"block_rdp"});
        f.nft.objects = compileFirewallObjects(f.config); // foreign/name-only candidate
        require(!f.reconcile(error) && f.nft.writes == 0 && records("block_rdp").empty(), "foreign object adopted");
        f.nft.objects = Json::array(); prepared("block_rdp"); require(f.reconcile(error), error);
        // Manifest is valid, but deliberately remove policy provenance.
        const auto id = records("block_rdp").front().id;
        require(journal().discard(id, error), error);
        const int writes = f.nft.writes;
        require(!f.reconcile(error) && f.nft.writes == writes && records("block_rdp").empty(), "manifest retroactively adopted rollback authority");
    } else if (scenario == 13) {
        desired(f, managedFirewallPolicies());
        f.nft.afterWrite = [&] {
            AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path) {
                if (path != (f.root / "journal.json").string()) return true;
                std::ifstream file(path); Json disk; file >> disk;
                int applied = 0;
                for (const auto& record : disk.at("records"))
                    applied += record.at("status") == "applied";
                return applied < 2;
            });
        };
        require(!f.reconcile(error) && f.tables().size() == 3, "partial commit must report failure after successful batch");
        AtomicFileWriter::setDirectoryFsyncHookForTests({}); f.nft.afterWrite = {};
        restart(f); const int writes = f.nft.writes;
        int pending = 0;
        for (const auto& p : managedFirewallPolicies()) {
            const auto active = records(p);
            require(active.size() == 1, "partial commit lost obligation");
            pending += active.front().status == MutationStatus::Prepared;
        }
        require(pending == 1, "partial commit must retain remaining Prepared");
        require(f.reconcile(error) && f.nft.writes == writes, "partial commit retry rewrote kernel");
        for (const auto& p : managedFirewallPolicies()) disable(f, p);
    } else if (scenario == 14) {
        desired(f, {"block_rdp"});
        f.nft.failCheck = true;
        require(!f.reconcile(error) && f.nft.writes == 0, "failed check mutated kernel");
        auto active = records("block_rdp");
        require(active.size() == 1 && active.front().status == MutationStatus::Prepared, "failed check lost Prepared");
        const auto id = active.front().id;
        f.nft.failCheck = false; f.nft.failApply = true;
        require(!f.reconcile(error) && f.tables().empty(), "failed batch mutated kernel");
        require(records("block_rdp").front().status == MutationStatus::Prepared, "failed batch created false Applied");
        f.nft.failApply = false; f.nft.lie = true;
        require(!f.reconcile(error), "unproven batch was accepted");
        require(records("block_rdp").front().status == MutationStatus::Prepared, "unproven batch committed Applied");
        f.nft.lie = false; restart(f); require(f.reconcile(error), error);
        require(records("block_rdp").size() == 1 && records("block_rdp").front().id == id, "failed batch retry duplicated id");
    } else if (scenario == 15) {
        desired(f, {"block_rdp"}); require(f.reconcile(error), error);
        f.quarantine = true; require(f.reconcile(error), error);
        std::filesystem::remove(f.root / "journal.json"); // persistent initialization witness remains
        const auto protectedState = f.tables(); const int writes = f.nft.writes;
        bool changed; std::vector<ForeignBaseChain> neutralized;
        require(f.coordinator->applyJournaledPolicy(ref("block_rdp"), f.config.policyRules.at("block_rdp"), error), error);
        require(f.backend->applyPolicy("block_rdp", {}, changed, error), error);
        require(f.backend->applyExclusive(neutralized, error), error);
        require(f.reconcile(error) && f.nft.writes == writes && f.tables() == protectedState, "journal error weakened quarantine");
        f.quarantine = false;
        require(!f.reconcile(error) && f.tables() == protectedState, "lost journal allowed NORMAL creation");
        f.config = {}; require(f.reconcile(error), error);
        require(f.tables().empty(), "journal unrelated to empty NORMAL cleanup blocked quarantine removal");
    } else if (scenario == 16) {
        desired(f, {"block_rdp"}); prepared("block_rdp");
        f.nft.afterWrite = [&] { f.nft.malformed = true; };
        require(!f.reconcile(error), "unproven postcondition reported success");
        const auto id = records("block_rdp").front().id;
        require(records("block_rdp").front().status == MutationStatus::Prepared, "postcondition failure promoted Applied");
        f.nft.afterWrite = {}; f.nft.malformed = false; restart(f);
        const int writes = f.nft.writes;
        require(f.reconcile(error) && f.nft.writes == writes, "postcondition recovery recreated table");
        require(journal().setStatusWithMessage(id, MutationStatus::RollbackFailed, "earlier rollback failed", error), error);
        require(f.reconcile(error), error);
        require(records("block_rdp").front().status == MutationStatus::RollbackFailed &&
                records("block_rdp").front().error == "earlier rollback failed", "no-op erased RollbackFailed diagnostic");
        disable(f, "block_rdp");
    } else if (scenario == 17) {
        desired(f, {"block_rdp", "block_ftp"}); require(f.reconcile(error), error);
        const auto ftp = f.tables().at("fic_block_ftp");
        Json retained = Json::array();
        for (const auto& item : f.nft.objects) {
            const auto& value = item.begin().value();
            if (value.value(item.contains("table") ? "name" : "table", "") != "fic_block_ftp") retained.push_back(item);
        }
        f.nft.objects = retained;
        f.nft.failApply = true;
        RollbackExecutorDeps deps;
        deps.undoFirewallPolicy = [&](const auto& p, auto& e) { return release(f, p, e); };
        require(!rollbackPolicyBeforeDisable(ref("block_rdp"), "block_rdp", deps).rollbackCompleted(), "failed removal reported success");
        require(!f.tables().count("fic_block_ftp"), "failed rollback recreated other policy");
        f.nft.failApply = false; disable(f, "block_rdp");
        require(f.tables().empty() && records("block_ftp").size() == 1, "rollback affected missing other policy obligation");
        require(!ftp.empty(), "fixture requires other policy");
    } else if (scenario == 18) {
        enableInQuarantine(f, {"block_rdp", "block_ftp"});
        f.quarantine = false; bool changed;
        require(f.backend->applyPolicy("custom_rules", {}, changed, error), error);
        require(!f.tables().count("fic_incident_quarantine") && f.tables().size() == 2,
                "empty custom_rules APPLY must still restore whole NORMAL profile");
        require(records("custom_rules").empty(), "empty custom_rules created false obligation");
        for (const auto& p : {"block_rdp", "block_ftp"}) {
            require(records(p).size() == 1 && records(p).front().status == MutationStatus::Applied,
                    "empty-rule direct profile restoration lost ordinary provenance");
            disable(f, p);
        }
    } else if (scenario == 19) {
        desired(f, {"block_rdp"});
        require(f.coordinator->applyJournaledPolicy(ref("block_rdp"), f.config.policyRules.at("block_rdp"), error), error);
        require(records("block_rdp").size() == 1 && records("block_rdp").front().status == MutationStatus::Applied,
                "journaled direct apply lacks provenance");
        desired(f, {"block_rdp", "block_ftp"});
        std::vector<ForeignBaseChain> neutralized;
        require(f.backend->applyExclusive(neutralized, error), error);
        require(records("block_ftp").size() == 1 && f.tables().size() == 2,
                "exclusive full reconciliation created unjournaled resource");
        require(f.coordinator->applyJournaledPolicy(ref("custom_rules"), {}, error), error);
        require(records("custom_rules").empty(), "empty journaled apply created false record");
    } else if (scenario == 20) {
        desired(f, managedFirewallPolicies());
        AtomicFileWriter::setPreInstallHookForTests([&](const std::string& path) {
            if (path == f.ownership.path.string()) throw std::runtime_error("crash before ownership intent");
        });
        require(!f.reconcile(error) && f.nft.writes == 0 && !std::filesystem::exists(f.ownership.path),
                "crash before ownership intent performed kernel mutation");
        AtomicFileWriter::setPreInstallHookForTests({});
        std::map<std::string, MutationId> ids;
        for (const auto& p : managedFirewallPolicies()) {
            require(records(p).size() == 1 && records(p).front().status == MutationStatus::Prepared,
                    "journal preparations must precede ownership intent");
            ids[p] = records(p).front().id;
        }
        restart(f); require(f.reconcile(error), error);
        for (const auto& p : managedFirewallPolicies())
            require(records(p).size() == 1 && records(p).front().id == ids.at(p), "ownership crash retry duplicated id");
    }
}
}
int runFirewallProvenanceTests(const std::string& scenario) {
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
        std::string error;
        require(fic::core::FicRuntimePaths::initialize(paths, error), error);
        require(scenario.size() >= 2 && scenario.front() == 'R', "unknown scenario");
        run(std::stoi(scenario.substr(1)));
        std::cout << scenario << " FIREWALL provenance PASS\n";
        return 0;
    } catch (const std::exception& ex) {
        AtomicFileWriter::setPreInstallHookForTests({});
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        std::cerr << scenario << " FAIL: " << ex.what() << '\n'; return 1;
    }
}
