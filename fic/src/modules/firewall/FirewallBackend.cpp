#include "modules/firewall/FirewallBackend.h"

#include <fic/core/VerifiedProcessExecutor.h>
#include <fic/core/Logger.h>

#include <filesystem>
#include <nlohmann/json.hpp>

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

std::set<std::string> expectedComments(const std::string& policyName,
                                       std::size_t ruleCount) {
    std::set<std::string> comments;
    for (std::size_t index = 0; index < ruleCount; ++index) {
        comments.insert("fic:" + policyName + ":" + std::to_string(index));
    }
    return comments;
}

} // namespace

FirewallBackend::FirewallBackend(
    const fic::platform::PlatformExecutableResolver& executables)
    : executables_(executables) {
}

bool FirewallBackend::resolveNft(std::string& executable,
                                 std::string& error) const {
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
    const ProcessResult result = VerifiedProcessExecutor::execute(
        executable, {"-j", "list", "ruleset"}, options);
    if (!result.success()) {
        error = processFailure("nft ruleset inspection", result);
        return false;
    }
    try {
        const nlohmann::json ruleset = nlohmann::json::parse(result.standardOutput);
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
    const ProcessResult check = VerifiedProcessExecutor::execute(
        executable, {"-c", "-f", "-"}, options);
    if (!check.success()) {
        error = processFailure("nft script validation", check);
        return false;
    }
    const ProcessResult apply = VerifiedProcessExecutor::execute(
        executable, {"-f", "-"}, options);
    if (!apply.success()) {
        error = processFailure("nft script application", apply);
        return false;
    }
    error.clear();
    return true;
}

bool FirewallBackend::applyPolicy(const std::string& policyName,
                                  const std::vector<FirewallRule>& rules,
                                  std::string& error) const {
    std::string executable;
    if (!resolveNft(executable, error)) {
        return false;
    }
    FirewallActualState actual;
    if (!readActual(executable, actual, error)) {
        return false;
    }
    const std::string table = managedTableName(policyName);
    if (actual.managedInetTables.count(table) == 0 && !rules.empty()) {
        Logger::log("Managed firewall rule set is missing: " + policyName,
                    logLevel::WARN, "daemon");
    } else if (actual.managedInetTables.count(table) != 0) {
        Logger::log("Refreshing managed firewall rule set: " + policyName,
                    logLevel::WARN, "daemon");
    }
    if (!executeScript(
            executable, buildPolicyScript(policyName, rules, actual), error)) {
        return false;
    }
    FirewallActualState verified;
    if (!readActual(executable, verified, error)) {
        return false;
    }
    const bool shouldExist = !rules.empty();
    const bool exists = verified.managedInetTables.count(
        managedTableName(policyName)) != 0;
    if (exists != shouldExist) {
        error = "nft postcondition failed for " + policyName;
        return false;
    }
    if (shouldExist && verified.managedRuleComments[managedTableName(policyName)] !=
            expectedComments(policyName, rules.size())) {
        error = "managed nft rule postcondition failed for " + policyName;
        return false;
    }
    Logger::log(
        shouldExist ? "Managed firewall rule set created: " + policyName
                    : "Managed firewall rule set removed: " + policyName,
        logLevel::INFO, "daemon");
    return true;
}

bool FirewallBackend::applyExclusive(
    std::vector<ForeignBaseChain>& neutralized,
    std::string& error) const {
    FirewallDesiredState desired;
    desired.exclusive = true;
    std::string executable;
    if (!resolveNft(executable, error)) {
        return false;
    }
    FirewallActualState actual;
    if (!readActual(executable, actual, error)) {
        return false;
    }
    actual.managedInetTables.clear();
    const std::string script = buildReconciliationScript(
        desired, actual, neutralized);
    if (!executeScript(executable, script, error)) {
        return false;
    }
    FirewallActualState verified;
    if (!readActual(executable, verified, error)) {
        return false;
    }
    if (!verified.foreignHostFilterChains.empty()) {
        error = "foreign host filtering chains remain after exclusive apply";
        return false;
    }
    return true;
}

bool FirewallBackend::reconcile(const FirewallDesiredState& desired,
                                std::vector<ForeignBaseChain>& neutralized,
                                std::string& error) const {
    std::string executable;
    if (!resolveNft(executable, error)) {
        return false;
    }
    FirewallActualState actual;
    if (!readActual(executable, actual, error)) {
        return false;
    }
    for (const std::string& table : actual.managedInetTables) {
        bool remainsDesired = false;
        for (const auto& [policy, rules] : desired.policyRules) {
            if (!rules.empty() && managedTableName(policy) == table) {
                remainsDesired = true;
                break;
            }
        }
        Logger::log(
            remainsDesired
                ? "Refreshing managed firewall table: " + table
                : "Removing stale managed firewall table: " + table,
            logLevel::WARN, "daemon");
    }
    for (const auto& [policy, rules] : desired.policyRules) {
        const std::string table = managedTableName(policy);
        if (!rules.empty() && actual.managedInetTables.count(table) == 0) {
            Logger::log("Managed firewall table is missing: " + table,
                        logLevel::WARN, "daemon");
        }
    }
    if (!executeScript(
        executable,
        buildReconciliationScript(desired, actual, neutralized),
        error)) {
        return false;
    }
    FirewallActualState verified;
    if (!readActual(executable, verified, error)) {
        return false;
    }
    std::set<std::string> expectedTables;
    for (const auto& [policy, rules] : desired.policyRules) {
        if (!rules.empty()) {
            expectedTables.insert(managedTableName(policy));
        }
    }
    if (verified.managedInetTables != expectedTables) {
        error = "managed nft table postcondition failed after reconciliation";
        return false;
    }
    for (const auto& [policy, rules] : desired.policyRules) {
        if (!rules.empty() &&
            verified.managedRuleComments[managedTableName(policy)] !=
                expectedComments(policy, rules.size())) {
            error = "managed nft rule postcondition failed after reconciliation: " +
                policy;
            return false;
        }
    }
    if (desired.exclusive && !verified.foreignHostFilterChains.empty()) {
        error = "foreign host filtering chains remain after reconciliation";
        return false;
    }
    return true;
}

} // namespace fic::firewall
