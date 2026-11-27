#include <algorithm>
#include "modules/oss/display_manager/DisplayManagerInventory.h"
#include <chrono>
#include <iostream>
#include <nlohmann/json.hpp>
#include <unistd.h>

int main(int argc, char** argv) {
    const bool includeMissing = argc == 2 && std::string(argv[1]) == "--include-missing";
    if (::geteuid() != 0 || !std::filesystem::exists("/.dockerenv")) return 77;
    using fic::platform::ExecutableId;
    using Clock = std::chrono::steady_clock;
    nlohmann::json metrics = {{"systemctl_calls",0},{"show_calls",0},
        {"show_seconds",0.0},{"max_show_seconds",0.0},{"max_show_bytes",0},
        {"requested_names",nlohmann::json::array()}};
    std::string lastShow;
    fic::platform::DisplayManagerPlatformConfig config;
    SystemDisplayManagerInventory inventory([&](ExecutableId id, const std::vector<std::string>& args) {
        ProcessOptions options; options.clearEnvironment=true;
        options.environment={{"LC_ALL","C"},{"PATH","/usr/sbin:/usr/bin:/sbin:/bin"}};
        const auto begin=Clock::now();
        auto result=ProcessExecutor::execute(
            id==ExecutableId::Systemctl ? "/usr/bin/systemctl" : "/usr/bin/loginctl",args,options);
        const auto elapsed=std::chrono::duration<double>(Clock::now()-begin).count();
        // Model a unit disappearing between enumeration and show, while the
        // property query and not-found reply still come from real systemd.
        if(includeMissing && id==ExecutableId::Systemctl && args.front()=="--root=/")
            result.standardOutput += "fic-dm-nonexistent.service disabled\n";
        if(id==ExecutableId::Systemctl) {
            metrics["systemctl_calls"]=metrics["systemctl_calls"].get<int>()+1;
            if(args.front()=="show") {
                lastShow = result.standardOutput;
                metrics["show_calls"]=metrics["show_calls"].get<int>()+1;
                metrics["show_seconds"]=metrics["show_seconds"].get<double>()+elapsed;
                metrics["max_show_seconds"]=std::max(metrics["max_show_seconds"].get<double>(),elapsed);
                metrics["max_show_bytes"]=std::max(metrics["max_show_bytes"].get<std::size_t>(),
                    result.standardOutput.size()+result.standardError.size());
                for(std::size_t i=1;i+2<args.size();++i) metrics["requested_names"].push_back(args[i]);
            }
        }
        return result;
    },config);
    DisplayManagerSnapshot snapshot;std::string error;
    const auto begin=Clock::now();
    const bool ok=inventory.inspect(snapshot,error,DisplayManagerInventoryMode::SelectedAndRunning);
    metrics["inventory_seconds"]=std::chrono::duration<double>(Clock::now()-begin).count();
    metrics["ok"]=ok;metrics["error"]=error;
    if(!ok) metrics["last_show_output"]=lastShow;
    nlohmann::json states=nlohmann::json::object();
    for(const auto& [dm,state]:snapshot.managers)
        states[dm]={{"installed",state.installed},{"selected",state.selected},
            {"running",state.running},{"configurationSupported",state.configurationSupported}};
    metrics["snapshot"]={{"complete",snapshot.complete},{"managers",states},
        {"unknownSelectedOrRunning",snapshot.unknownSelectedOrRunning}};
    std::cout<<metrics.dump(2)<<'\n';
    return ok?0:1;
}
