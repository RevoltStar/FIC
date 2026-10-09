#include "modules/firewall/FirewallBackend.h"
#include "modules/firewall/FirewallCoordinator.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include "incident/IncidentStateStore.h"
#include "rollback/DaemonMutationJournal.h"

#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fic/core/logging/Logger.h>

#include <filesystem>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <array>
#include <sys/random.h>

namespace fic::firewall {
namespace {

std::string processFailure(const std::string& operation,
                           const ProcessResult& result) {
    std::string detail = result.error;
    if (detail.empty()) {
        detail = result.standardError;
    }
    if (detail.empty()) {
        detail = "exit code " + std::to_string(result.exitCode);
    }
    return operation + " failed: " + detail;
}

nlohmann::json logicalObjects(nlohmann::json objects) {
    for (auto& item : objects) {
        if (!item.contains("rule")) continue;
        auto& rule = item.at("rule");
        const auto comment = rule.at("comment").get<std::string>();
        const auto marker = comment.rfind(":owner:");
        if (marker != std::string::npos) rule["comment"] = comment.substr(0, marker);
    }
    return objects;
}
bool stampOwnership(nlohmann::json& objects, std::string& error) {
    std::array<unsigned char, 16> bytes{};
    if (::getrandom(bytes.data(), bytes.size(), 0) != static_cast<ssize_t>(bytes.size())) {
        error = "could not obtain firewall ownership nonce"; return false;
    }
    const char hex[] = "0123456789abcdef";
    std::string nonce;
    for (const auto byte : bytes) { nonce += hex[byte >> 4]; nonce += hex[byte & 15]; }
    for (auto& item : objects)
        if (item.contains("rule"))
            item.at("rule")["comment"] = item.at("rule").at("comment").get<std::string>() + ":owner:" + nonce;
    return true;
}

// Backend ownership authorizes nft object replacement, not Policy rollback.
// Prepare at the shared physical execution boundary, after ownership proof,
// so direct apply, startup and every profile restoration use the same protocol.
bool prepareOrdinaryMutations(const std::map<std::string, nlohmann::json>& observed,
    const std::map<std::string, nlohmann::json>& wanted,
    std::vector<fic::rollback::MutationId>& pending, std::string& error) {
    using namespace fic::rollback;
    if (wanted.empty()) return true;
    auto* journal = DaemonMutationJournal::instance().tryGet(error);
    if (!journal) {
        if (error.empty()) error = "ordinary FIREWALL mutation journal is unavailable";
        return false;
    }
    // A cached Healthy object does not prove that its persistent file still
    // exists. Re-prove the witness-aware journal before authorizing a batch.
    if (!journal->initializeOrLoad(error)) return false;
    std::map<std::string, MutationRecord> existing;
    for (const auto& [table, objects] : wanted) {
        const auto& policies = managedFirewallPolicies();
        const auto found = std::find_if(policies.begin(), policies.end(),
            [&](const auto& policy) { return managedTableName(policy) == table; });
        if (found == policies.end()) {
            error = "unsupported ordinary FIREWALL resource: " + table; return false;
        }
        const PolicyRef policy{"FIREWALL", "HostFiltering", *found};
        const auto records = journal->activeRecords(policy);
        if (records.size() > 1) {
            error = "ambiguous ordinary FIREWALL rollback provenance: " + *found; return false;
        }
        if (!records.empty()) {
            const auto& record = records.front();
            const auto* undo = std::get_if<UndoRemoveFirewallPolicy>(&record.undo.payload);
            if (record.resource != *found || record.undo.backend != MutationBackend::Firewall ||
                !undo || undo->policyName != *found) {
                error = "ordinary FIREWALL rollback provenance conflicts: " + *found; return false;
            }
            existing.emplace(*found, record);
        } else if (observed.count(table)) {
            // Even an exact durable backend manifest cannot retroactively
            // provide missing Policy provenance for an already present table.
            error = "ordinary FIREWALL rollback provenance unavailable: " + *found; return false;
        }
    }
    // Validate the whole plan before any preparation; prepare ALL missing
    // obligations durably before the ONE multi-policy nft transaction.
    for (const auto& policy : managedFirewallPolicies()) {
        if (!wanted.count(managedTableName(policy))) continue;
        const auto found = existing.find(policy);
        if (found != existing.end()) {
            if (found->second.status == MutationStatus::Prepared)
                pending.push_back(found->second.id);
            // Applied and RollbackFailed remain active, without being reset
            // to Prepared or losing an earlier failed rollback diagnostic.
            continue;
        }
        MutationId id = 0;
        if (!recordPreparedMutation({"FIREWALL", "HostFiltering", policy}, policy,
                {MutationBackend::Firewall, UndoRemoveFirewallPolicy{policy}}, id, error)) return false;
        pending.push_back(id);
    }
    return true;
}

} // namespace

FirewallBackend::FirewallBackend(
    const fic::platform::PlatformExecutableResolver& executables)
    : executables_(executables) {
    ownership_.path = fic::core::FicRuntimePaths::get().lockStatusFile.parent_path() / "firewall_ownership";
    ownership_.expectation = fic::incident::IncidentStateStore::lockedStateExpectation();
    ownership_.expectation.maxSize = 4 * 1024 * 1024;
}

bool FirewallBackend::resolveNft(std::string& executable,
                                 std::string& error) const {
    if (runner_) { executable = "injected-nft"; return true; }
    std::filesystem::path path;
    if (!executables_.resolve(
            fic::platform::ExecutableId::Nft, path, error)) {
        return false;
    }
    executable = path.string();
    return true;
}

bool FirewallBackend::readActual(const std::string& executable,
                                 FirewallActualState& state,
                                 std::string& error) const {
    ProcessOptions options;
    options.timeout = std::chrono::seconds(10);
    // Full host ruleset includes foreign rules and potentially large sets.
    options.maxOutputBytes = 32 * 1024 * 1024;
    const ProcessResult result = run(
        executable, {"-j", "list", "ruleset"}, options);
    if (!result.success()) {
        error = processFailure("nft ruleset inspection", result);
        return false;
    }
    try {
        nlohmann::json ruleset;
        if (!parseFirewallJson(result.standardOutput, ruleset, error)) return false;
        std::size_t metadataCount = 0;
        if (ruleset.is_object() && ruleset.contains("nftables") && ruleset.at("nftables").is_array()) {
            for (const auto& item : ruleset.at("nftables")) {
                if (!item.is_object() || !item.contains("metainfo")) continue;
                ++metadataCount;
                if (!item.at("metainfo").is_object() ||
                    item.at("metainfo").at("json_schema_version") != 1) {
                    error = "unsupported nft JSON metadata"; return false;
                }
            }
        }
        if (metadataCount != 1) { error = "incomplete/ambiguous nft JSON metadata"; return false; }
        return parseNftActualState(ruleset, state, error);
    } catch (const nlohmann::json::exception& exception) {
        error = std::string("could not parse nft ruleset JSON: ") + exception.what();
        return false;
    }
}

bool FirewallBackend::executeScript(const std::string& executable,
                                    const std::string& script,
                                    std::string& error) const {
    if (script.empty()) {
        error.clear();
        return true;
    }
    ProcessOptions options;
    options.timeout = std::chrono::seconds(10);
    options.standardInput = script;
    const ProcessResult check = run(
        executable, {"-j", "-c", "-f", "-"}, options);
    if (!check.success()) {
        error = processFailure("nft script validation", check);
        return false;
    }
    const ProcessResult apply = run(
        executable, {"-j", "-f", "-"}, options);
    if (!apply.success()) {
        error = processFailure("nft script application", apply);
        return false;
    }
    error.clear();
    return true;
}


bool FirewallBackend::applyPolicy(const std::string& policy,
    const std::vector<FirewallRule>& rules, bool& changed, std::string& error) const {
    return FirewallCoordinator(*this).applyPolicy(policy, rules, changed, error);
}
bool FirewallBackend::removePolicy(const std::string& policy, std::string& error) const {
    return FirewallCoordinator(*this).removePolicy(policy, error);
}
bool FirewallBackend::applyExclusive(std::vector<ForeignBaseChain>& neutralized,
                                    std::string& error) const {
    bool changed = false;
    return FirewallCoordinator(*this).reconcile(nullptr, changed, neutralized, error, true);
}
bool FirewallBackend::reconcile(const FirewallDesiredState& desired,
    std::vector<ForeignBaseChain>& neutralized, std::string& error) const {
    bool changed = false;
    return FirewallCoordinator(*this).reconcile(&desired, changed, neutralized, error);
}

ProcessResult FirewallBackend::run(const std::string& executable,
    const std::vector<std::string>& args, const ProcessOptions& options) const {
    return runner_ ? runner_(args, options)
                   : VerifiedProcessExecutor::execute(executable, args, options);
}

FirewallBackend::FirewallBackend(
    const fic::platform::PlatformExecutableResolver& executables,
    NftRunner runner, FirewallOwnershipOptions ownership,
    std::function<bool()> quarantineDecision,
    std::function<bool(FirewallDesiredState&, std::string&)> configuration)
    : executables_(executables), runner_(std::move(runner)), ownership_(std::move(ownership)),
      quarantineDecision_(std::move(quarantineDecision)), configuration_(std::move(configuration)) {}

bool FirewallBackend::applyEffective(const FirewallDesiredState& desired,
    bool& changed, std::vector<ForeignBaseChain>& neutralized, std::string& error,
    const std::string& onlyPolicy, bool removalOnly) const {
    using Json = nlohmann::json;
    using namespace fic::core;
    changed = false;
    neutralized.clear();
    try {
    std::string executable;
    if (!resolveNft(executable, error)) return false;
    FirewallActualState actual;
    if (!readActual(executable, actual, error)) return false;
    std::map<std::string, Json> observed, wanted;
    if (!observeManagedObjects({{"nftables", actual.objects}}, observed, error) ||
        !observeManagedObjects({{"nftables", compileFirewallObjects(desired)}}, wanted, error)) return false;
    bool onlySelectedPolicy = !desired.quarantine && !onlyPolicy.empty() &&
        (removalOnly || !observed.count("fic_incident_quarantine"));
    if (onlySelectedPolicy) {
        // A normal direct policy apply owns only that policy's mutation.
        // A profile restoration still compiles the complete current config.
        const auto table = managedTableName(onlyPolicy);
        auto selected = wanted.find(table);
        nlohmann::json replacement = selected == wanted.end() ? nlohmann::json::array() : selected->second;
        wanted = observed;
        wanted.erase(table);
        if (!replacement.empty()) wanted[table] = std::move(replacement);
    }

    if (!proveSafeParentDirectory(ownership_.path.parent_path(), ownership_.expectation, error)) return false;
    const auto witness = readSecureFileBounded(ownership_.path, ownership_.expectation, 4 * 1024 * 1024);
    Json document = {{"schema_version", 1}, {"before", Json::object()}, {"after", Json::object()}};
    if (witness.status == SecureStateReadStatus::Unprovable) {
        error = "firewall ownership is unproven: " + witness.detail; return false;
    }
    if (witness.status == SecureStateReadStatus::Proven) {
        try {
            if (!parseFirewallJson(witness.content, document, error)) return false;
            if (document.size() != 3 || document.at("schema_version") != 1 ||
                !document.at("before").is_object() || !document.at("after").is_object()) {
                error = "invalid firewall ownership document"; return false;
            }
            if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                    ownership_.path.string(), witness.targetState, &error)) return false;
        } catch (const Json::exception& ex) { error = ex.what(); return false; }
    }
    if (onlySelectedPolicy && !removalOnly && document.at("after").contains("fic_incident_quarantine")) {
        // Drift may have removed quarantine before a profile restoration.
        // Its durable intent still distinguishes this from a normal single
        // policy apply: restore ALL current normal settings atomically.
        onlySelectedPolicy = false;
        if (!observeManagedObjects({{"nftables", compileFirewallObjects(desired)}}, wanted, error)) return false;
    }
    for (const auto& [table, objects] : observed) {
        bool owned = false;
        for (const char* phase : {"before", "after"})
            if (document.at(phase).contains(table) && document.at(phase).at(table) == objects)
                owned = true;
        if (!owned) {
            error = "reserved table ownership/structure unproven: " + table;
            return false;
        }
    }
    // A durable intent plus exact structure alone could adopt a competing
    // deterministic lookalike after a failed create. Bind every intended table
    // to an unpredictable nonce, durable BEFORE its creation. Comments are
    // checked only together with the full root-owned manifest and structure.
    for (auto& [table, objects] : wanted) {
        const auto logical = logicalObjects(objects);
        if (observed.count(table) && logicalObjects(observed.at(table)) == logical) {
            objects = observed.at(table);
        } else if (document.at("after").contains(table) &&
                   logicalObjects(document.at("after").at(table)) == logical) {
            objects = document.at("after").at(table);
        } else if (!stampOwnership(objects, error)) return false;
    }
    Json commands = Json::array();
    // All removals and additions, including NORMAL/quarantine switch, share
    // ONE kernel batch. Delete uses observed handles, refusing replaced tables.
    for (const auto& [table, objects] : observed) {
        if (wanted.count(table) && wanted.at(table) == objects) continue;
        if (wanted.count(table)) {
            Logger::log("Refreshing managed firewall table: " + table, logLevel::DEBUG, "daemon");
            Logger::log("Refreshing managed firewall rule set: " + table, logLevel::DEBUG, "daemon");
        } else {
            Logger::log("Removing stale managed firewall table: " + table, logLevel::INFO, "daemon");
        }
        Json deletion = {{"family", "inet"}, {"name", table}};
        for (const auto& item : actual.objects)
            if (item.contains("table") && item.at("table").at("family") == "inet" &&
                item.at("table").at("name") == table && item.at("table").contains("handle")) {
                deletion.erase("name"); deletion["handle"] = item.at("table").at("handle");
            }
        commands.push_back({{"delete", {{"table", deletion}}}});
    }
    for (const auto& [table, objects] : wanted) {
        if (observed.count(table) && observed.at(table) == objects) continue;
        if (!observed.count(table)) {
            Logger::log("Managed firewall table is missing: " + table, logLevel::DEBUG, "daemon");
            Logger::log("Managed firewall rule set is missing: " + table, logLevel::DEBUG, "daemon");
        }
        for (const auto& item : objects)
            commands.push_back({{item.contains("table") ? "create" : "add", item}});
    }
    if (desired.exclusive && !desired.quarantine && !onlySelectedPolicy) {
        for (const auto& chain : actual.foreignHostFilterChains) {
            Json id = {{"family", chain.family}, {"table", chain.table}, {"name", chain.chain}};
            commands.push_back({{"flush", {{"chain", id}}}});
            commands.push_back({{"delete", {{"chain", id}}}});
            id["type"] = chain.type; id["hook"] = chain.hook;
            id["prio"] = chain.priority; id["policy"] = "accept";
            commands.push_back({{"add", {{"chain", id}}}});
            neutralized.push_back(chain);
        }
    }
    std::vector<fic::rollback::MutationId> pending;
    // Removal-only rollback preserves all other objects and never creates
    // ordinary resources from configuration. Quarantine requires no ordinary
    // journal and cannot be weakened by an ordinary journal failure.
    if (!desired.quarantine && !removalOnly &&
        !prepareOrdinaryMutations(observed, wanted, pending, error)) return false;
    if (!commands.empty()) {
        Json next = {{"schema_version", 1}, {"before", observed}, {"after", wanted}};
        const auto serialized = next.dump();
        if (serialized.size() > 4 * 1024 * 1024) {
            error = "firewall ownership document exceeds bound"; return false;
        }
        AtomicWriteOptions options;
        options.createIfMissing = witness.status == SecureStateReadStatus::Missing;
        options.exclusiveCreate = options.createIfMissing;
        options.rejectSymlink = true;
        options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
        options.fileOwner = ownership_.expectation.owner;
        options.fileGroup = ownership_.expectation.group;
        options.fileMode = 0640;
        if (!options.createIfMissing) options.expectedTargetState = witness.targetState;
        AtomicWriteResult written;
        if (!AtomicFileWriter::writeWithResult(ownership_.path.string(), serialized, options,
                &error, &written) || !written.durabilityConfirmed) return false;
        changed = true;
        if (!executeScript(executable, Json{{"nftables", commands}}.dump(), error)) return false;
    }
    FirewallActualState verified;
    std::map<std::string, Json> verifiedObjects;
    if (!readActual(executable, verified, error) ||
        !observeManagedObjects({{"nftables", verified.objects}}, verifiedObjects, error)) return false;
    if (verifiedObjects != wanted) {
        error = "effective firewall postcondition is unproven"; return false;
    }
    if (desired.exclusive && !desired.quarantine && !onlySelectedPolicy && !verified.foreignHostFilterChains.empty()) {
        error = "exclusive firewall postcondition failed"; return false;
    }
    // Also resolves a crash-after-nft Prepared on a proven kernel no-op.
    // Partial completion is recoverable: remaining Prepared records stay
    // active, and a failure here must never be reported as successful apply.
    for (const auto id : pending)
        if (!fic::rollback::commitMutation(id, error)) return false;
    error.clear(); return true;
    } catch (const std::exception& exception) {
        error = std::string("firewall state is unproven: ") + exception.what();
        return false;
    }
}

} // namespace fic::firewall
