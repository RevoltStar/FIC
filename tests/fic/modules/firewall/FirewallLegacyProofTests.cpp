// Executable RED replay on the requested base. Uses only the pre-existing
// backend API, replacing execution at its trusted transport boundary.
#include "modules/firewall/FirewallBackend.h"
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <unistd.h>

using Json = nlohmann::json;
namespace {
Json observation;
int writes = 0;
}
ProcessResult VerifiedProcessExecutor::execute(const std::string&,
    const std::vector<std::string>& args, const ProcessOptions&) {
    ProcessResult result; result.started = true; result.exitCode = 0;
    if (args == std::vector<std::string>{"-j", "list", "ruleset"})
        result.standardOutput = observation.dump();
    else if (std::find(args.begin(), args.end(), "-c") == args.end()) ++writes;
    return result;
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string scenario = argv[1];
    std::string pattern = "/tmp/fic-firewall-legacy-proof-XXXXXX";
    const std::filesystem::path root = ::mkdtemp(pattern.data());
    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config"; paths.logDir = root / "log";
    paths.notifyDir = root / "notify"; paths.lockStatusFile = root / "lockstatus";
    std::filesystem::create_directory(paths.configDir);
    std::filesystem::create_directory(paths.logDir);
    { std::ofstream audit(paths.configDir / "AUDIT.conf"); audit << "log_level.status=ENABLE\nlog_level.value=ERROR\n"; }
    std::string error;
    if (!fic::core::FicRuntimePaths::initialize(paths, error)) return 2;
    observation = {{"nftables", Json::array({
        {{"metainfo", {{"json_schema_version", 1}}}},
        {{"table", {{"family", "inet"}, {"name", "fic_block_rdp"}}}},
        {{"chain", {{"family", "inet"}, {"table", "fic_block_rdp"}, {"name", "input"},
          {"type", "filter"}, {"hook", scenario == "C14" ? "output" : "input"}, {"prio", 0}, {"policy", "accept"}}}},
        {{"rule", {{"family", "inet"}, {"table", "fic_block_rdp"}, {"chain", "input"},
          {"comment", "fic:block_rdp:0"}, {"expr", scenario == "C14"
            ? Json::array({{{"match", {{"op", "=="}, {"left", {{"payload", {{"protocol", "tcp"}, {"field", "dport"}}}}}, {"right", 3389}}}}, {{"drop", nullptr}}})
            : Json::array({{{"accept", nullptr}}})}}}}
    })}};
    fic::platform::PlatformExecutables executables;
    executables.entries.push_back({fic::platform::ExecutableId::Nft, {"/bin/true"}});
    fic::platform::PlatformExecutableResolver resolver(executables, {false});
    fic::firewall::FirewallBackend backend(resolver);
    bool changed = false;
    fic::firewall::FirewallRule rule;
    rule.protocol = fic::firewall::Protocol::Tcp;
    rule.action = fic::firewall::Action::Block;
    rule.destinationPort = {false, 3389, 3389};
    const bool ok = backend.applyPolicy("block_rdp", scenario == "F13"
        ? std::vector<fic::firewall::FirewallRule>{} : std::vector<fic::firewall::FirewallRule>{rule}, changed, error);
    std::filesystem::remove_all(root);
    const bool passed = scenario == "F13" ? !ok && writes == 0 : !ok;
    if (!passed) {
        std::cerr << scenario << " RED: " << (scenario == "F13"
            ? "name-only foreign collision was destructively mutated"
            : "wrong nft structure passed comment-only postcondition") << '\n';
        return 1;
    }
    std::cout << scenario << " GREEN\n";
    return 0;
}
