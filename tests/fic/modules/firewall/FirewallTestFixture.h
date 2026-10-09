#pragma once
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

namespace firewall_test {
using namespace fic::firewall;
using Json = nlohmann::json;
using Severity = fic::core::IncidentSeverity;
inline void require(bool condition, const std::string& message) {
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
    std::function<void()> beforeWrite, afterWrite;
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
        if (beforeWrite) beforeWrite();
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
        if (afterWrite) afterWrite();
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
        fic::rollback::DaemonMutationJournal::instance().setOverridePath(root / "journal.json");
        resetBackend();
    }
    ~Fixture() { fic::rollback::DaemonMutationJournal::instance().resetOverride(); std::filesystem::remove_all(root); }
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
}
